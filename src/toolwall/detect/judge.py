"""Judge-model wrapper.

The judge is the third detector layer. It is invoked only on residual text
that the pattern + unicode + markdown detectors did not already adjudicate.

v0.2 ships ``bryteai/toolwall-judge-v0.2``, a DeBERTa-v3-base sequence
classifier (pinned revision below). See ``training/MODEL_CARD_v0_2.md``.
The superseded v0.1 LoRA adapter (Qwen2.5-7B) loads only when
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
1.  If ``TOOLWALL_JUDGE_LOCAL_PATH`` is set, load the adapter from that
    directory (this is the path the trainer writes to). The
    in-repo default is ``models/judge-v0.1/``.
2.  Otherwise, fall back to the HF id ``bryteai/toolwall-judge-v0.1``.
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
_kind: str | None = None          # "lora" (v0.1) or "seqcls" (v0.2)
_threshold: float = 0.5

_MAX_INPUT_CHARS = 4_000

_pipeline: Any | None = None
_load_attempted = False
_source_used: str | None = None


def _resolve_adapter_source() -> tuple[str, str] | None:
    """Return ``(kind, location)`` for the adapter, or ``None`` if absent.

    ``kind`` is ``"local"`` or ``"hf"``. ``location`` is a filesystem
    path or HF id. Order: ``TOOLWALL_JUDGE_LOCAL_PATH``, then a local
    ``models/judge-v0.2``, then the pinned Hugging Face revision of
    ``bryteai/toolwall-judge-v0.2``.
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
    if (JUDGE_V02_LOCAL_PATH_DEFAULT / "config.json").exists():
        return ("local", str(JUDGE_V02_LOCAL_PATH_DEFAULT))
    # The superseded v0.1 LoRA judge (models/judge-v0.1) is used only when
    # TOOLWALL_JUDGE_LOCAL_PATH points at it; it is never picked by default.
    return ("hf", JUDGE_V02_HF_ID)


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
    is_lora = kind == "local" and (Path(location) / "adapter_config.json").exists()
    if not is_lora:
        try:
            import json as _json
            cfg_path = Path(location) / "toolwall_judge.json" if kind == "local" else None
            if cfg_path is not None and cfg_path.exists():
                _threshold = float(_json.loads(cfg_path.read_text())["threshold"])
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


def score(text: str) -> Detection | None:
    """Return a :class:`Detection` with score in ``[0,1]`` or ``None``.

    ``None`` means the judge could not opine (model not present, input
    empty, etc.) --- callers treat this as "no signal" and rely on the
    other detector layers.
    """
    if not text:
        return None
    pipeline = _try_load()
    if pipeline is None:
        return None

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
    "score",
]
