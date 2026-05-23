"""Judge-model wrapper.

The judge is the third detector layer. It is invoked only on residual text
that the pattern + unicode + markdown detectors did not already adjudicate.

v0.1 ships a LoRA adapter trained on ``Qwen/Qwen2.5-7B-Instruct``
(Apache-2.0; substituted for the gated ``meta-llama/Llama-3.1-8B-Instruct``
which requires Meta licence approval). See ``training/MODEL_CARD.md``
for the full rationale and dev-split metrics.

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
    Publishing to HF is deferred until launch day --- the local path is
    the canonical source for now.
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

# Default local adapter path. The day-5 trainer writes here.
_REPO_ROOT = Path(__file__).resolve().parents[3]
JUDGE_LOCAL_PATH_DEFAULT = _REPO_ROOT / "models" / "judge-v0.1"

_MAX_INPUT_CHARS = 4_000

_pipeline: Any | None = None
_load_attempted = False
_source_used: str | None = None


def _resolve_adapter_source() -> tuple[str, str] | None:
    """Return ``(kind, location)`` for the adapter, or ``None`` if absent.

    ``kind`` is ``"local"`` or ``"hf"``. ``location`` is a filesystem
    path or HF id.
    """
    env_path = os.environ.get("TOOLWALL_JUDGE_LOCAL_PATH")
    if env_path:
        p = Path(env_path).expanduser().resolve()
        if (p / "adapter_config.json").exists():
            return ("local", str(p))
        _LOG.warning(
            "TOOLWALL_JUDGE_LOCAL_PATH=%s but adapter_config.json not found there; ignoring",
            p,
        )
    if (JUDGE_LOCAL_PATH_DEFAULT / "adapter_config.json").exists():
        return ("local", str(JUDGE_LOCAL_PATH_DEFAULT))
    return ("hf", JUDGE_HF_ID)


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
        import torch  # type: ignore[import-not-found]
        from peft import PeftModel  # type: ignore[import-not-found]
        from transformers import (  # type: ignore[import-not-found]
            AutoModelForSequenceClassification,
            AutoTokenizer,
            pipeline,
        )
    except Exception:
        _LOG.warning(
            "transformers/peft/torch not installed; "
            "toolwall.detect.judge inactive. "
            "`pip install toolwall[judge]` to enable."
        )
        return None

    source = _resolve_adapter_source()
    if source is None:
        return None
    kind, location = source
    _source_used = f"{kind}:{location}"

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
