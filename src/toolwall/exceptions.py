"""Public exception hierarchy.

All exceptions raised by `toolwall` derive from :class:`Blocked` so that user
code can catch a single base class. Each exception carries a short machine
``reason`` slug and a free-form ``evidence`` mapping describing what was seen
at the moment of the decision. The audit log records both verbatim.
"""

from __future__ import annotations

from typing import Any


class Blocked(Exception):
    """Base class for every enforcement decision that stops a tool call.

    Parameters
    ----------
    reason:
        Stable, kebab-case slug. Stable means: changing it is a breaking
        change. Examples: ``"url-not-allowlisted"``, ``"ipi-detected"``.
    evidence:
        Free-form mapping. May contain the offending input span, the
        detector score, the policy field that fired, etc. Surfaced to
        operators via the audit log; never round-tripped into the model.
    """

    reason: str
    evidence: dict[str, Any]

    def __init__(self, reason: str, evidence: dict[str, Any] | None = None) -> None:
        self.reason = reason
        self.evidence = dict(evidence or {})
        super().__init__(f"{reason}: {self.evidence}" if self.evidence else reason)


class PolicyViolation(Blocked):
    """A policy field was violated at request or response time."""


class BudgetExceeded(Blocked):
    """A rate, byte, or cost budget was exceeded."""


__all__ = ["Blocked", "BudgetExceeded", "PolicyViolation"]
