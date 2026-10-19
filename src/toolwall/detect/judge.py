"""Judge-model wrapper.

The judge is the third detector layer. It is invoked only on residual text
that the pattern + unicode + markdown detectors did not already adjudicate.

v0.3 ships ``bryteai/toolwall-judge-v0.3``, a windowed DeBERTa-v3-base
classifier (pinned revision below): the tool output is cut into overlapping
512-token windows and the score is the highest window score. See
``training/MODEL_CARD_v0_3.md``. ``TOOLWALL_JUDGE=v0.3-xsmall`` picks the
smaller, faster variant; ``TOOLWALL_JUDGE=v0.2`` the previous judge. The
superseded v0.1 LoRA adapter (Qwen2.5-7B) loads only when
``TOOLWALL_JUDGE_LOCAL_PATH`` points at it.

The wrapper is lazy: importing ``toolwall.detect`` does NOT import torch /
transformers. The model is materialised only when :func:`score` is called
and ``transformers`` is on the path. If the dependency is missing, the judge
returns ``None`` and emits one warning, so deploys without GPU still
pass through with only the regex / unicode / markdown layers active.

This is deliberate: the threat model flags the judge as an extra layer,
not a load-bearing one. Pattern + unicode alone bring ASR well below the
baseline; the judge closes the long tail.

Loading order
-------------
1.  If ``TOOLWALL_JUDGE_LOCAL_PATH`` is set, load the model from that
    directory (this is the path the trainer writes to).
2.  If ``TOOLWALL_JUDGE`` names a published judge (``v0.3``, ``v0.3-xsmall``,
    ``v0.2``), load ``models/judge-<name>`` from a repo checkout when present,
    otherwise its pinned Hugging Face revision.
3.  Otherwise a local ``models/judge-v0.3``, then ``models/judge-v0.2``, then
    the pinned Hugging Face revision of ``bryteai/toolwall-judge-v0.3``.
"""

from __future__ import annotations

import logging
import os
from pathlib import Path
from typing import Any

from ._types import Detection

_LOG = logging.getLogger("toolwall.detect.judge")

# Base model. Bump in lockstep with the adapter when the base changes.
JUDGE_BASE_MODEL = "Qwen/Qwen2.5-7B-Instruct"

# HF id used IF/WHEN the adapter is published. The local path takes
# precedence; see ``_resolve_adapter_source`` below.
JUDGE_HF_ID = "bryteai/toolwall-judge-v0.1"
JUDGE_HF_REVISION = "main"  # replaced with a sha pin at publish time

# Default local adapter path that the trainer writes to.
_REPO_ROOT = Path(__file__).resolve().parents[3]
JUDGE_LOCAL_PATH_DEFAULT = _REPO_ROOT / "models" / "judge-v0.1"
# v0.2: a plain (non-LoRA) DeBERTa-v3 sequence classifier with a calibrated threshold
# stored next to the weights in ``toolwall_judge.json``. Preferred when present.
JUDGE_V02_LOCAL_PATH_DEFAULT = _REPO_ROOT / "models" / "judge-v0.2"
JUDGE_V02_HF_ID = "bryteai/toolwall-judge-v0.2"
# Pinned Hugging Face commit; weights sha256 34dc0cc929250b61ee2bc24f901ba31da87c38f923f7623bfe31924a796768fe
JUDGE_V02_HF_REVISION = "4427056d8d5b1636a82f3cf4fad940923eb05b29"
# v0.3: task-aware, windowed DeBERTa-v3 classifier. ``toolwall_judge.json`` carries ``max_len`` and
# ``stride``; the tool output is cut into overlapping token windows and the score is the maximum window score,
# so benign text around an attack cannot dilute it. See training/modal_train_judge_v0_3.py.
JUDGE_V03_LOCAL_PATH_DEFAULT = _REPO_ROOT / "models" / "judge-v0.3"
JUDGE_V03_HF_ID = "bryteai/toolwall-judge-v0.3"
# Pinned Hugging Face commit; weights sha256 b4df0319…7d72 (full hash in training/MODEL_CARD_v0_3.md)
JUDGE_V03_HF_REVISION = "9423f03cb20536a777ed0ecc46af483e48938b15"
JUDGE_V03_XSMALL_HF_ID = "bryteai/toolwall-judge-v0.3-xsmall"
# Pinned Hugging Face commit; weights sha256 aa1705ca…b138
JUDGE_V03_XSMALL_HF_REVISION = "7fd8aee6b9014cd054a4937c5cee057baad1da1e"
# Names accepted by TOOLWALL_JUDGE.
PUBLISHED_JUDGES = {"v0.3": JUDGE_V03_HF_ID, "v0.3-xsmall": JUDGE_V03_XSMALL_HF_ID, "v0.2": JUDGE_V02_HF_ID}
# The v0.3 judge was trained with short user requests as the task (median 12 tokens, none written as a role
# prompt). With role-style system prompts as the task it flagged almost every benign document (LongPIBench).
_TASK_WARN_TOKENS = 32
_task_warned = False
_kind: str | None = None         # "lora" (v0.1), "seqcls" (v0.2) or "windowed" (v0.3)
_threshold: float = 0.5
_win: dict[str, Any] = {}

_MAX_INPUT_CHARS = 4_000
# Windowed judge: texts longer than this are scored on their first and last halves of this size.
_MAX_WINDOWED_CHARS = int(os.environ.get("TOOLWALL_JUDGE_MAX_CHARS", "200000"))

_pipeline: Any | None = None
_load_attempted = False
_source_used: str | None = None


def _resolve_adapter_source() -> tuple[str, str] | None:
    """Return ``(kind, location)`` for the adapter, or ``None`` if absent.

    ``kind`` is ``"local"`` or ``"hf"``. ``location`` is a filesystem
    path or HF id. Order: ``TOOLWALL_JUDGE_LOCAL_PATH``; then the judge named by
    ``TOOLWALL_JUDGE`` (local ``models/judge-<name>`` or its HF id); then a local
    ``models/judge-v0.3``, a local ``models/judge-v0.2``, and finally the pinned
    Hugging Face revision of ``bryteai/toolwall-judge-v0.3``.
    """
    env_path = os.environ.get("TOOLWALL_JUDGE_LOCAL_PATH")
    if env_path:
        p = Path(env_path).expanduser().resolve()
        if (p / "adapter_config.json").exists() or (p / "config.json").exists():
            return ("local", str(p))
        _LOG.warning(
            "TOOLWALL_JUDGE_LOCAL_PATH=%s but adapter_config.json not found there; ignoring",
            p,
        )
    choice = os.environ.get("TOOLWALL_JUDGE", "").strip()
    if choice:
        if choice in PUBLISHED_JUDGES:
            local = _REPO_ROOT / "models" / f"judge-{choice}"
            if (local / "config.json").exists():
                return ("local", str(local))
            return ("hf", PUBLISHED_JUDGES[choice])
        _LOG.warning("TOOLWALL_JUDGE=%s is not one of %s; using the default judge", choice, sorted(PUBLISHED_JUDGES))
    for default in (JUDGE_V03_LOCAL_PATH_DEFAULT, JUDGE_V02_LOCAL_PATH_DEFAULT):
        if (default / "config.json").exists():
            return ("local", str(default))
    # The superseded v0.1 LoRA judge (models/judge-v0.1) is used only when
    # TOOLWALL_JUDGE_LOCAL_PATH points at it; it is never picked by default.
    return ("hf", JUDGE_V03_HF_ID)


def _try_load() -> Any | None:
    """Load the judge once. Returns None if dependencies are missing."""
    global _pipeline, _load_attempted, _source_used
    if _load_attempted:
        return _pipeline
    _load_attempted = True

    if os.environ.get("TOOLWALL_DISABLE_JUDGE") == "1":
        _LOG.info("TOOLWALL_DISABLE_JUDGE=1; judge skipped")
        return None

    try:
        import torch  # type: ignore[import-not-found,unused-ignore]
        from transformers import (  # type: ignore[import-not-found,unused-ignore]
            AutoModelForSequenceClassification,
            AutoTokenizer,
            pipeline,
        )
    except Exception:
        _LOG.warning(
            "transformers/peft/torch not installed; "
            "toolwall.detect.judge inactive. "
            "`pip install \"toolwall-guard[judge]\"` to enable."
        )
        return None

    source = _resolve_adapter_source()
    if source is None:
        return None
    kind, location = source
    _source_used = f"{kind}:{location}"
    global _kind, _threshold
    windowed_revisions = {JUDGE_V03_HF_ID: JUDGE_V03_HF_REVISION, JUDGE_V03_XSMALL_HF_ID: JUDGE_V03_XSMALL_HF_REVISION}
    if kind == "hf" and location in windowed_revisions:
        try:  # the windowed judge reads toolwall_judge.json next to the weights, so fetch the pinned snapshot
            from huggingface_hub import (
                snapshot_download,  # type: ignore[import-not-found,unused-ignore]
            )
            location = snapshot_download(location, revision=windowed_revisions[location])
            kind = "local"
        except Exception as exc:
            _LOG.warning("judge download failed (%s); continuing without judge", exc)
            return None
    is_lora = kind == "local" and (Path(location) / "adapter_config.json").exists()
    if not is_lora:
        try:
            import json as _json
            cfg_path = Path(location) / "toolwall_judge.json" if kind == "local" else None
            meta = _json.loads(cfg_path.read_text()) if cfg_path is not None and cfg_path.exists() else {}
            if "stride" in meta:
                tok = AutoTokenizer.from_pretrained(location)
                tok.model_max_length = 10**9  # we window ourselves; silence the length warning
                model = AutoModelForSequenceClassification.from_pretrained(location).eval()
                device = "cuda" if torch.cuda.is_available() else "cpu"
                _win.update(tok=tok, model=model.to(device), device=device, torch=torch, max_len=int(meta["max_len"]),
                            stride=int(meta["stride"]), task_max=int(meta.get("task_max_tokens", 64)),
                            version=str(meta.get("version", "0.3")))
                _threshold = float(meta["threshold"])
                _kind = "windowed"
                _pipeline = model
                return _pipeline
            if meta:
                _threshold = float(meta["threshold"])
            elif kind == "hf":
                from huggingface_hub import (
                    hf_hub_download,  # type: ignore[import-not-found,unused-ignore]
                )
                _threshold = float(_json.loads(Path(hf_hub_download(location, "toolwall_judge.json", revision=JUDGE_V02_HF_REVISION)).read_text())["threshold"])
            _pipeline = pipeline(
                "text-classification", model=location, tokenizer=location, top_k=None,
                revision=JUDGE_V02_HF_REVISION if kind == "hf" else None,
                truncation=True, max_length=512, device=0 if torch.cuda.is_available() else -1,
            )
            _kind = "seqcls"
        except Exception as exc:
            _LOG.warning("judge load failed (%s); continuing without judge", exc)
            _pipeline = None
        return _pipeline
    _kind = "lora"
    try:
        # only the v0.1 LoRA judge needs peft
        from peft import PeftModel  # type: ignore[import-not-found,unused-ignore]
    except Exception:
        _LOG.warning("peft not installed; the v0.1 LoRA judge needs `pip install peft`")
        _pipeline = None
        return None

    try:
        tokenizer = AutoTokenizer.from_pretrained(location if kind == "local" else JUDGE_HF_ID)
        base = AutoModelForSequenceClassification.from_pretrained(
            JUDGE_BASE_MODEL,
            num_labels=3,
            torch_dtype=torch.float16 if torch.cuda.is_available() else torch.float32,
        )
        if tokenizer.pad_token_id is None:
            tokenizer.pad_token = tokenizer.eos_token
        base.config.pad_token_id = tokenizer.pad_token_id
        merged = PeftModel.from_pretrained(base, location)
        _pipeline = pipeline(
            "text-classification",
            model=merged,
            tokenizer=tokenizer,
            top_k=1,
            truncation=True,
            max_length=512,
            device=0 if torch.cuda.is_available() else -1,
        )
    except Exception as exc:
        _LOG.warning("judge load failed (%s); continuing without judge", exc)
        _pipeline = None
    return _pipeline


def _windows(task: str, text: str) -> list[tuple[list[int], tuple[int, int]]]:
    """Token windows exactly as in training: ``[CLS] task [SEP] piece [SEP]`` (or ``[CLS] piece [SEP]``)."""
    tok, max_len, stride = _win["tok"], _win["max_len"], _win["stride"]
    task_ids = tok(task, add_special_tokens=False)["input_ids"][: _win["task_max"]] if task else []
    enc = tok(text, add_special_tokens=False, return_offsets_mapping=True)
    ids, offs = enc["input_ids"], enc["offset_mapping"]
    room = max_len - len(task_ids) - (4 if task_ids else 2)
    step = max(1, min(stride, room))
    cls, sep = tok.cls_token_id, tok.sep_token_id
    out, start = [], 0
    while True:
        end = min(len(ids), start + room)
        piece = ids[start:end]
        model_in = [cls, *task_ids, sep, *piece, sep] if task_ids else [cls, *piece, sep]
        chars = (offs[start][0], offs[end - 1][1]) if piece else (0, 0)
        out.append((model_in, chars))
        if end >= len(ids):
            break
        start += step
    return out


def _score_windowed(text: str, task: str) -> tuple[float, tuple[int, int], int]:
    torch, model, tok = _win["torch"], _win["model"], _win["tok"]
    segments = [(0, text)]
    if len(text) > _MAX_WINDOWED_CHARS:
        half = _MAX_WINDOWED_CHARS // 2
        segments = [(0, text[:half]), (len(text) - half, text[-half:])]
    best, best_span, n = 0.0, (0, 0), 0
    for base, seg in segments:
        ws = _windows(task, seg)
        n += len(ws)
        for i in range(0, len(ws), 16):
            batch = ws[i:i + 16]
            m = max(len(x) for x, _ in batch)
            ids = torch.full((len(batch), m), tok.pad_token_id)
            att = torch.zeros((len(batch), m), dtype=torch.long)
            for j, (x, _) in enumerate(batch):
                ids[j, :len(x)] = torch.tensor(x)
                att[j, :len(x)] = 1
            with torch.no_grad():
                logits = model(input_ids=ids.to(_win["device"]), attention_mask=att.to(_win["device"])).logits
            p = torch.softmax(logits.float(), -1)[:, 1].tolist()
            for pj, (_, chars) in zip(p, batch, strict=True):
                if pj > best:
                    best, best_span = pj, (base + chars[0], base + chars[1])
    return best, best_span, n


def score(text: str, task: str = "") -> Detection | None:
    """Return a :class:`Detection` with score in ``[0,1]`` or ``None``.

    ``task`` is the user's request, when the caller knows it (a short sentence such as "Summarize my last
    email"), never the agent's system prompt. The v0.3 judge was trained with and without it; older judges
    ignore it. On the v0.3 final tests the task did not improve detection, and with LongPIBench's role-style
    system prompts as the task the judge flagged almost every benign document, so the default is no task.

    ``None`` means the judge could not opine (model not present, input
    empty, etc.) --- callers treat this as "no signal" and rely on the
    other detector layers.
    """
    if not text:
        return None
    pipeline = _try_load()
    if pipeline is None:
        return None

    if _kind == "windowed":
        global _task_warned
        if task and not _task_warned and (task.lstrip().lower().startswith("you are")
                                          or len(_win["tok"](task, add_special_tokens=False)["input_ids"]) > _TASK_WARN_TOKENS):
            _task_warned = True
            _LOG.warning("judge task looks like a system prompt; the v0.3 judge was trained with short user requests "
                         "and flags most benign text when given a system prompt. Pass the user's request or no task.")
        try:
            p_attack, span, n_windows = _score_windowed(text, task or "")
        except Exception as exc:
            _LOG.warning("judge inference failed: %s", exc)
            return None
        if p_attack < _threshold:
            return None
        mapped = 0.6 + 0.4 * (p_attack - _threshold) / max(1e-9, 1.0 - _threshold)
        return Detection(kind="judge-attack", span=span, score=min(1.0, mapped),
                         evidence={"p_attack": round(p_attack, 4), "threshold": _threshold, "windows": n_windows,
                                   "task_given": bool(task), "source": _source_used or "unknown"})

    snippet = text[:_MAX_INPUT_CHARS]
    if _kind == "seqcls":
        try:
            scores = pipeline(snippet)
            if scores and isinstance(scores[0], list):
                scores = scores[0]
            p_attack = next((float(r["score"]) for r in scores
                             if str(r["label"]).lower() in ("attack", "label_1", "injection")), 0.0)
        except Exception as exc:
            _LOG.warning("judge inference failed: %s", exc)
            return None
        if p_attack < _threshold:
            return None
        # Map [threshold, 1] onto [0.6, 1] so a judge hit crosses the default block threshold.
        mapped = 0.6 + 0.4 * (p_attack - _threshold) / max(1e-9, 1.0 - _threshold)
        return Detection(kind="judge-attack", span=(0, len(text)), score=min(1.0, mapped),
                         evidence={"p_attack": round(p_attack, 4), "threshold": _threshold,
                                   "source": _source_used or "unknown"})
    try:
        result = pipeline(snippet)[0]
        if isinstance(result, list):
            result = result[0]
        label = str(result.get("label", "")).lower()
        prob = float(result.get("score", 0.0))
    except Exception as exc:
        _LOG.warning("judge inference failed: %s", exc)
        return None

    evidence = {
        "label": label,
        "base_model": JUDGE_BASE_MODEL,
        "source": _source_used or "unknown",
    }
    if label.startswith("attack") or label == "label_2":
        return Detection(
            kind="judge-attack",
            span=(0, len(text)),
            score=prob,
            evidence=evidence,
        )
    if label.startswith("suspicious") or label == "label_1":
        return Detection(
            kind="judge-suspicious",
            span=(0, len(text)),
            score=min(prob, 0.55),
            evidence=evidence,
        )
    return None


__all__ = [
    "JUDGE_BASE_MODEL",
    "JUDGE_HF_ID",
    "JUDGE_HF_REVISION",
    "JUDGE_LOCAL_PATH_DEFAULT",
    "JUDGE_V03_HF_ID",
    "JUDGE_V03_HF_REVISION",
    "JUDGE_V03_XSMALL_HF_ID",
    "PUBLISHED_JUDGES",
    "score",
]
