"""Composite IPI detector --- the layer the decorator calls.

Three sub-detectors run in cheap-to-expensive order:

1. :mod:`toolwall.detect.patterns`     --- regex over the cited corpus
2. :mod:`toolwall.detect.unicode_tags` --- U+E0000 / zero-width / bidi
3. :mod:`toolwall.detect.markdown_exfil` --- EchoLeak-class sinks
4. :mod:`toolwall.detect.judge`         --- LoRA-tuned Qwen2.5-7B-Instruct (optional)

The composite :class:`CompositeDetector` returns ``(max_score, detections)``
which fits the :class:`~toolwall.decorator.Detector` protocol. Importing this
module also registers the composite as the *default* detector for any
``@toolwall(...)`` decorator that does not pass an explicit ``detector=``.
"""

from __future__ import annotations

from typing import Any

from ..decorator import _set_default_detector
from . import markdown_exfil, patterns, unicode_tags
from ._types import Detection

try:
    from . import judge
except Exception:  # pragma: no cover --- judge is optional
    judge = None  # type: ignore[assignment]


class CompositeDetector:
    """Runs every sub-detector and returns the worst-case score.

    Parameters
    ----------
    markdown_allowlist:
        Hosts whose markdown image / link URLs should NOT be flagged. If
        empty (default), every cross-host image is flagged.
    use_judge:
        Whether to invoke the judge model. Default ``True``; set False on
        latency-critical paths or when the judge is not installed.
    """

    def __init__(
        self,
        *,
        markdown_allowlist: tuple[str, ...] = (),
        use_judge: bool = True,
    ) -> None:
        self._markdown_allowlist = markdown_allowlist
        self._use_judge = use_judge

    def score(self, text: str) -> tuple[float, list[dict[str, Any]]]:
        hits: list[Detection] = []
        hits.extend(patterns.detect(text))
        hits.extend(unicode_tags.detect(text))
        hits.extend(markdown_exfil.detect(text, self._markdown_allowlist))
        if self._use_judge:
            from . import judge as _judge

            j = _judge.score(text)
            if j is not None:
                hits.append(j)

        if not hits:
            return 0.0, []
        worst = max(h.score for h in hits)
        spans = [
            {
                "kind": h.kind,
                "span": h.span,
                "score": h.score,
                "evidence": h.evidence,
            }
            for h in hits
        ]
        return worst, spans


# Default detector instance --- auto-registered with the decorator on import.
default_detector = CompositeDetector()
_set_default_detector(default_detector)

__all__ = ["CompositeDetector", "Detection", "default_detector"]
