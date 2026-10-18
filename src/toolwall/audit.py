"""Append-only audit log.

Every enforcement decision lands here. The log is JSON-lines so it can be
tailed, grepped, or shipped to a SIEM without parsing ceremony. Records are
intentionally small --- no full request bodies, no full responses --- to
avoid the log itself becoming a side-channel for the very content we just
blocked. The threat model (§2.2 ~A3) treats the log as untamperable host
state, not as defence state.
"""

from __future__ import annotations

import json
import os
import threading
import time
from pathlib import Path
from typing import Any


def _safe_log_path(raw: str | os.PathLike[str]) -> str:
    # The audit-log location is operator-controlled (env var or kwarg), not
    # an attacker-reachable surface. We still normalize it defensively so a
    # malformed value (NUL byte, empty string, embedded '..' traversal) fails
    # fast instead of corrupting open(). Operators wanting an unusual location
    # can pass an absolute path -- '..' segments are always rejected.
    s = os.fspath(raw)
    if not s or "\x00" in s:
        raise ValueError("toolwall audit log path is empty or contains NUL")
    expanded = os.path.expanduser(s)
    parts = Path(expanded).parts
    if any(part == ".." for part in parts):
        raise ValueError("toolwall audit log path must not contain '..' segments")
    return os.path.abspath(expanded)


_DEFAULT_LOG_PATH = _safe_log_path(os.environ.get("TOOLWALL_AUDIT_LOG", ".toolwall-audit.log"))
_lock = threading.Lock()


def _truncate(value: Any, limit: int = 200) -> Any:
    if isinstance(value, str) and len(value) > limit:
        return value[:limit] + f"...[+{len(value) - limit}]"
    if isinstance(value, dict):
        return {k: _truncate(v, limit) for k, v in value.items()}
    if isinstance(value, (list, tuple)):
        return [_truncate(v, limit) for v in value][:20]
    return value


def emit(
    *,
    decision: str,
    tool: str,
    reason: str | None = None,
    evidence: dict[str, Any] | None = None,
    path: str | None = None,
) -> None:
    """Write one audit record.

    Parameters
    ----------
    decision:
        One of ``"allow"``, ``"redact"``, ``"block"``, ``"quarantine"``.
    tool:
        Qualified name of the wrapped callable (``module.func``).
    reason:
        Optional stable slug from a :class:`~toolwall.exceptions.Blocked`.
    evidence:
        Optional mapping; will be size-truncated before serialization.
    path:
        Override audit log location. Defaults to ``$TOOLWALL_AUDIT_LOG`` or
        ``./.toolwall-audit.log``.
    """
    record = {
        "ts": time.time(),
        "decision": decision,
        "tool": tool,
        "reason": reason,
        "evidence": _truncate(evidence or {}),
    }
    target = _safe_log_path(path) if path else _DEFAULT_LOG_PATH
    with _lock, open(target, "a", encoding="utf-8") as f:
        f.write(json.dumps(record, default=str) + "\n")


__all__ = ["emit"]
