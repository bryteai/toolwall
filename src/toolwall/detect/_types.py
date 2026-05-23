"""Shared types for the detector layer."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any


@dataclass(frozen=True)
class Detection:
    """A single positive hit from one detector.

    Attributes
    ----------
    kind:
        Stable, kebab-case slug. Stable means: changing it breaks the audit
        log consumers. Examples: ``"ipi-instruction"``, ``"unicode-tag"``,
        ``"markdown-exfil"``.
    span:
        Half-open ``(start, end)`` byte offsets in the original input. Empty
        tuple ``(0, 0)`` if the detector cannot localize.
    score:
        Confidence in ``[0.0, 1.0]``. 1.0 means "certain this is hostile."
    evidence:
        Free-form mapping describing what the detector saw. Surfaced in
        :class:`~toolwall.exceptions.Blocked` ``.evidence``.
    """

    kind: str
    span: tuple[int, int]
    score: float
    evidence: dict[str, Any] = field(default_factory=dict)


__all__ = ["Detection"]
