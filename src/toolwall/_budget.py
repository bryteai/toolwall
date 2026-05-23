"""Sliding-window rate and cost budgets, per decorated callable.

Each :class:`~toolwall.policy.Policy` plus each wrapped function gets a
private :class:`_Counter`. Calls are timestamped in a 60-second deque; once a
new call would exceed the limit, :class:`~toolwall.exceptions.BudgetExceeded`
is raised before the tool is invoked. Cost works the same way but in cents.

The implementation is intentionally lock-free and best-effort. We assume the
caller serializes its own concurrent tool calls; under heavy parallelism a
small overshoot is acceptable --- the policy is a control, not a guarantee.
"""

from __future__ import annotations

import time
from collections import deque
from dataclasses import dataclass, field

from .exceptions import BudgetExceeded


@dataclass
class _Counter:
    calls: deque[float] = field(default_factory=deque)
    costs: deque[tuple[float, int]] = field(default_factory=deque)

    def _evict(self, now: float, window: float = 60.0) -> None:
        cutoff = now - window
        while self.calls and self.calls[0] < cutoff:
            self.calls.popleft()
        while self.costs and self.costs[0][0] < cutoff:
            self.costs.popleft()

    def admit(self, calls_per_min: int, cost_cents_max: int | None) -> None:
        now = time.monotonic()
        self._evict(now)
        if calls_per_min and len(self.calls) >= calls_per_min:
            raise BudgetExceeded(
                "rate-limit",
                {"calls_per_min": calls_per_min, "observed": len(self.calls)},
            )
        if cost_cents_max is not None:
            total = sum(c for _, c in self.costs)
            if total >= cost_cents_max:
                raise BudgetExceeded(
                    "cost-budget",
                    {"cost_cents_max": cost_cents_max, "observed_cents": total},
                )
        self.calls.append(now)

    def add_cost(self, cents: int) -> None:
        self.costs.append((time.monotonic(), cents))


__all__ = ["_Counter"]
