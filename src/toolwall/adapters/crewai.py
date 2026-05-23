"""Adapter for CrewAI.

CrewAI exposes tools in two shapes:

* A subclass of ``crewai.tools.BaseTool`` whose work lives in ``_run``.
* A function decorated with ``@tool`` from ``crewai.tools``; the SDK
  attaches the original callable as ``.func`` on the returned object.

This adapter mutates the tool in place --- the same instance you pass
to a ``Crew`` already has the firewall attached when control returns.
We refuse to silently re-wrap, because double-wrapping silently doubles
the audit log per call and that has bitten every middleware library in
existence at least once.

Usage
-----
::

    from crewai.tools import tool
    from toolwall import policy
    from toolwall.adapters.crewai import wrap

    @tool("search")
    def search(query: str) -> str:
        ...

    wrap(search, policy=policy.web_fetch())
"""

from __future__ import annotations

import contextlib
from typing import Any

from ..decorator import toolwall
from ..policy import Policy

_FLAG = "_toolwall_wrapped"


def wrap(tool: Any, *, policy: Policy) -> Any:
    """Wrap a CrewAI tool's executor with a toolwall policy.

    Accepts either a ``BaseTool`` instance (we patch ``_run``), a tool
    object exposing ``.func`` (we patch that), or a bare callable (we
    return a newly decorated callable).
    """
    if getattr(tool, _FLAG, False):
        return tool

    decorate = toolwall(policy=policy)

    if hasattr(tool, "_run") and callable(getattr(tool, "_run", None)):
        tool._run = decorate(tool._run)
        with contextlib.suppress(AttributeError, TypeError):
            setattr(tool, _FLAG, True)
        return tool

    if hasattr(tool, "func") and callable(getattr(tool, "func", None)):
        tool.func = decorate(tool.func)
        with contextlib.suppress(AttributeError, TypeError):
            setattr(tool, _FLAG, True)
        return tool

    if callable(tool):
        wrapped = decorate(tool)
        with contextlib.suppress(AttributeError, TypeError):
            setattr(wrapped, _FLAG, True)
        return wrapped

    raise TypeError("expected CrewAI BaseTool, decorated tool, or callable")


__all__ = ["wrap"]
