"""Adapter for LangGraph (``langgraph.prebuilt.ToolNode`` and friends).

LangGraph wires tools into a graph in two common shapes:

* A list of bare callables (or ``StructuredTool`` instances) passed to
  ``ToolNode(tools=[...])``. The node looks up the right callable by
  tool name and invokes it on each step.
* An ``@tool``-decorated callable from ``langchain_core.tools`` that
  the graph receives in its ``tools=`` list. The decorator attaches
  ``name``, ``description``, ``args_schema``, ``func`` (sync) and/or
  ``coroutine`` (async) attributes.

The adapter mutates the tool in place when given an instance, returns
a wrapped callable when given a bare function, and returns a new
``ToolNode``-shaped list when given a list. We refuse to fork
LangGraph --- the ``ToolNode`` class is not our problem to ship.

Idempotent via the ``_toolwall_wrapped`` attribute --- double-wrapping
silently doubles the audit-log entries per call and that has burned
every middleware library at least once.

Usage
-----
::

    from langchain_core.tools import tool
    from toolwall import policy
    from toolwall.adapters.langgraph import wrap

    @tool
    def search(query: str) -> str:
        ...

    wrap(search, policy=policy.web_fetch())   # mutates in place

    # or for a whole list
    from langgraph.prebuilt import ToolNode
    safe_tools = wrap([search, fetch_url], policy=policy.web_fetch())
    graph_node = ToolNode(tools=safe_tools)
"""

from __future__ import annotations

import contextlib
from typing import Any

from ..decorator import toolwall
from ..policy import Policy

_FLAG = "_toolwall_wrapped"


def _wrap_one(tool: Any, *, policy: Policy) -> Any:
    """Wrap a single LangGraph-shaped tool."""
    if getattr(tool, _FLAG, False):
        return tool

    decorate = toolwall(policy=policy)

    # langchain_core.tools.StructuredTool / Tool: ``.func`` (sync) and
    # ``.coroutine`` (async). Patch whichever is present.
    patched = False
    if hasattr(tool, "func") and callable(getattr(tool, "func", None)):
        tool.func = decorate(tool.func)
        patched = True
    if hasattr(tool, "coroutine") and callable(getattr(tool, "coroutine", None)):
        tool.coroutine = decorate(tool.coroutine)
        patched = True
    if patched:
        with contextlib.suppress(AttributeError, TypeError):
            setattr(tool, _FLAG, True)
        return tool

    # Some integrations expose ``.invoke`` / ``._run`` as the call point.
    if hasattr(tool, "_run") and callable(getattr(tool, "_run", None)):
        tool._run = decorate(tool._run)
        with contextlib.suppress(AttributeError, TypeError):
            setattr(tool, _FLAG, True)
        return tool

    if callable(tool):
        wrapped = decorate(tool)
        with contextlib.suppress(AttributeError, TypeError):
            setattr(wrapped, _FLAG, True)
        return wrapped

    raise TypeError(
        "expected LangGraph tool: bare callable, StructuredTool, or object with ._run / .func"
    )


def wrap(tool: Any, *, policy: Policy) -> Any:
    """Wrap a single LangGraph tool, or a list of them.

    If ``tool`` is a list/tuple, returns a list of wrapped tools (each
    item processed independently). Otherwise returns the wrapped
    single tool with the same shape.
    """
    if isinstance(tool, (list, tuple)):
        return [_wrap_one(t, policy=policy) for t in tool]
    return _wrap_one(tool, policy=policy)


__all__ = ["wrap"]
