"""The ``@toolwall`` decorator --- the entire public surface, one symbol.

Wraps any sync or async callable. Around each call:

1. **Request layer.** Bind arguments by inspection and check them against the
   policy (URL allowlist, path scope, shell metacharacters, per-arg regex).
2. **Budget admission.** Refuse if rate or cost budget would be exceeded.
3. **Invoke** the underlying tool.
4. **Response layer.** Enforce the byte cap, apply named redactions, then
   (if the optional ``detector`` is wired up) score for IPI and decide
   ``allow`` / ``redact`` / ``block`` per ``Policy.on_low_confidence`` and
   ``Policy.response_ipi_threshold``.
5. **Audit.** Every decision emits exactly one audit record.

The detector is intentionally pluggable. Without one wired up, only the
redactor runs; :mod:`toolwall.detect` plugs into this same call site.
"""

from __future__ import annotations

import asyncio
import functools
import hashlib
import inspect
from collections.abc import Awaitable, Callable
from typing import Any, Protocol, TypeVar, cast, overload

from . import _arg_inspect, _redact, audit
from ._budget import _Counter
from .boundary import filter_untrusted
from .exceptions import Blocked, BudgetExceeded, PolicyViolation
from .policy import Policy

F = TypeVar("F", bound=Callable[..., Any])


class Detector(Protocol):
    """Minimal IPI detector interface; :mod:`toolwall.detect` implements it."""

    def score(self, text: str) -> tuple[float, list[dict[str, Any]]]:
        """Return ``(score in [0,1], spans)`` --- 1.0 is "certain attack"."""


_NO_DETECTOR: Detector | None = None  # set by ``toolwall.detect`` at import time


def _bind(
    func: Callable[..., Any], args: tuple[Any, ...], kwargs: dict[str, Any]
) -> dict[str, Any]:
    try:
        sig = inspect.signature(func)
        bound = sig.bind_partial(*args, **kwargs)
        return dict(bound.arguments)
    except (TypeError, ValueError):
        # Builtins / C-implemented callables have no introspectable sig.
        out: dict[str, Any] = {f"arg{i}": a for i, a in enumerate(args)}
        out.update(kwargs)
        return out


def _stringify(result: Any) -> tuple[str, str]:
    """Return (text-for-inspection, original-repr-tag)."""
    if isinstance(result, str):
        return result, "str"
    if isinstance(result, (bytes, bytearray)):
        return result.decode("utf-8", errors="replace"), "bytes"
    return repr(result), type(result).__name__


def _restore(original_kind: str, text: str, original: Any) -> Any:
    if original_kind == "str":
        return text
    if original_kind == "bytes":
        return text.encode("utf-8")
    return original  # don't try to round-trip arbitrary objects


def _enforce_response(
    result: Any,
    policy: Policy,
    tool_name: str,
    detector: Detector | None,
) -> Any:
    text, kind = _stringify(result)

    if len(text.encode("utf-8", errors="replace")) > policy.response_max_bytes:
        raise BudgetExceeded(
            "response-too-large",
            {"limit": policy.response_max_bytes, "field": "response_max_bytes"},
        )

    decision = "allow"
    detector_score: float | None = None
    control_tokens_removed = False
    if policy.untrusted_delimiters and kind in ("str", "bytes"):
        filtered = filter_untrusted(text, policy.untrusted_delimiters)
        control_tokens_removed = filtered != text
        if control_tokens_removed:
            decision = "redact"
        text = filtered
    redacted, redactions = _redact.apply(text, policy.redact)
    if redactions:
        decision = "redact"

    if detector is not None:
        detector_score, _spans = detector.score(redacted)
        if detector_score >= policy.response_ipi_threshold:
            raise Blocked(
                "ipi-detected",
                {"score": detector_score, "threshold": policy.response_ipi_threshold},
            )
        if detector_score >= 0.3 and policy.on_low_confidence == "block":
            raise Blocked(
                "ipi-low-confidence-block",
                {"score": detector_score, "policy": "on_low_confidence=block"},
            )
        if detector_score >= 0.3 and policy.on_low_confidence == "redact" and decision == "allow":
            decision = "redact"

    audit.emit(
        decision=decision,
        tool=tool_name,
        reason=None,
        evidence={
            "redactions": [r["pattern"] for r in redactions],
            "control_tokens_removed": control_tokens_removed,
            "score": detector_score,
            "bytes": len(text),
        },
    )

    return _restore(kind, redacted, result)


def _schema_text(func: Callable[..., Any]) -> str:
    """What the model is told about a tool: name, docstring, signature, description."""
    try:
        sig = str(inspect.signature(func))
    except (TypeError, ValueError):
        sig = ""
    desc = getattr(func, "description", None)
    parts = (getattr(func, "__name__", ""), inspect.getdoc(func) or "", sig, desc if isinstance(desc, str) else "")
    return "\n".join(p for p in parts if p)


def _make_schema_gate(
    target: Callable[..., Any], policy: Policy, detector: Detector | None
) -> Callable[[], None]:
    """Build the per-call schema check for ``schema_lock`` and ``scan_schema``.

    ``schema_lock`` pins the SHA-256 of the schema text at wrap time and blocks a
    call if it has changed since (rug-pull). ``scan_schema`` runs the detector
    over the schema text (full-schema poisoning); results are cached per hash.
    Both see the wrapped Python function only, not a description stored
    elsewhere (for example inside an MCP SDK's own registry).
    """
    approved = hashlib.sha256(_schema_text(target).encode("utf-8")).hexdigest()
    scanned: dict[str, float] = {}

    def _gate() -> None:
        if not (policy.schema_lock or policy.scan_schema):
            return
        text = _schema_text(target)
        digest = hashlib.sha256(text.encode("utf-8")).hexdigest()
        if policy.schema_lock and digest != approved:
            raise Blocked(
                "schema-mismatch",
                {"approved_sha256": approved[:16], "current_sha256": digest[:16], "field": "schema_lock"},
            )
        if policy.scan_schema and detector is not None:
            if digest not in scanned:
                scanned[digest] = float(detector.score(text)[0])
            if scanned[digest] >= policy.response_ipi_threshold:
                raise Blocked(
                    "schema-poisoned",
                    {"score": scanned[digest], "threshold": policy.response_ipi_threshold, "field": "scan_schema"},
                )

    return _gate


def _qualname(func: Callable[..., Any]) -> str:
    mod = getattr(func, "__module__", "<unknown>")
    name = getattr(func, "__qualname__", None) or getattr(func, "__name__", repr(func))
    return f"{mod}.{name}"


@overload
def toolwall(func: F, /) -> F: ...


@overload
def toolwall(*, policy: Policy, detector: Detector | None = ...) -> Callable[[F], F]: ...


def toolwall(
    func: Callable[..., Any] | None = None,
    *,
    policy: Policy | None = None,
    detector: Detector | None = None,
) -> Any:
    """Wrap a tool callable so every invocation goes through the firewall.

    Usage::

        @toolwall(policy=policy.web_fetch(url_allowlist=("*.gov.uk",)))
        def fetch_url(url: str) -> str:
            return requests.get(url).text

    Sync and async callables are both supported; the wrapper preserves the
    original calling convention.
    """
    if func is not None and policy is None:
        raise TypeError("@toolwall requires policy=...; bare @toolwall is reserved")

    assert policy is not None  # narrowed by the guard above
    active_detector = detector if detector is not None else _NO_DETECTOR
    counter = _Counter()

    def _decorate(target: Callable[..., Any]) -> Callable[..., Any]:
        tool_name = _qualname(target)
        is_coro = asyncio.iscoroutinefunction(target)
        schema_gate = _make_schema_gate(target, policy, active_detector)

        if is_coro:

            @functools.wraps(target)
            async def _async_wrapper(*args: Any, **kwargs: Any) -> Any:
                bound = _bind(target, args, kwargs)
                try:
                    schema_gate()
                    _arg_inspect.inspect(bound, policy)
                    counter.admit(policy.calls_per_min, policy.cost_cents_max)
                except Blocked as exc:
                    audit.emit(
                        decision="block",
                        tool=tool_name,
                        reason=exc.reason,
                        evidence=exc.evidence,
                    )
                    raise

                result = await cast(Callable[..., Awaitable[Any]], target)(*args, **kwargs)

                try:
                    return _enforce_response(result, policy, tool_name, active_detector)
                except Blocked as exc:
                    audit.emit(
                        decision="block",
                        tool=tool_name,
                        reason=exc.reason,
                        evidence=exc.evidence,
                    )
                    raise

            return _async_wrapper

        @functools.wraps(target)
        def _sync_wrapper(*args: Any, **kwargs: Any) -> Any:
            bound = _bind(target, args, kwargs)
            try:
                schema_gate()
                _arg_inspect.inspect(bound, policy)
                counter.admit(policy.calls_per_min, policy.cost_cents_max)
            except Blocked as exc:
                audit.emit(
                    decision="block",
                    tool=tool_name,
                    reason=exc.reason,
                    evidence=exc.evidence,
                )
                raise

            result = target(*args, **kwargs)

            try:
                return _enforce_response(result, policy, tool_name, active_detector)
            except Blocked as exc:
                audit.emit(
                    decision="block",
                    tool=tool_name,
                    reason=exc.reason,
                    evidence=exc.evidence,
                )
                raise

        return _sync_wrapper

    if func is not None:
        return _decorate(func)
    return _decorate


def _set_default_detector(detector: Detector | None) -> None:
    """Internal hook used by ``toolwall.detect`` at import time."""
    global _NO_DETECTOR
    _NO_DETECTOR = detector


__all__ = ["Blocked", "BudgetExceeded", "Detector", "PolicyViolation", "toolwall"]
