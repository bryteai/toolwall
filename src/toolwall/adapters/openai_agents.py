"""Adapter for the OpenAI Agents SDK (``openai-agents`` on PyPI).

The OpenAI Agents SDK exposes tools as either:

* A function decorated with ``@function_tool`` from ``agents.tool``,
  which attaches ``name``, ``description``, ``params_json_schema`` and
  keeps the original callable accessible as ``__wrapped__`` (functools)
  or, on newer revisions, as ``on_invoke_tool``.
* A ``FunctionTool`` instance with ``.on_invoke_tool`` (the async entry
  point the runner actually calls).
* A bare ``async`` callable handed in as a one-off.

We patch the call site (``on_invoke_tool`` or the wrapped function)
without forking the SDK. Idempotent via the ``_toolwall_wrapped`` flag
because the agent loop may re-register the same tool on every
``Runner.run`` invocation and double-wrapping doubles the audit-log
entries per call (every middleware library learns this the hard way).

Usage
-----
::

    from agents import Agent, Runner, function_tool
    from toolwall import policy
    from toolwall.adapters.openai_agents import wrap

    @function_tool
    def fetch_url(url: str) -> str:
        ...

    safe_fetch = wrap(fetch_url, policy=policy.web_fetch())
    agent = Agent(name="researcher", tools=[safe_fetch])
"""

from __future__ import annotations

import contextlib
from typing import Any

from ..decorator import toolwall
from ..policy import Policy

_FLAG = "_toolwall_wrapped"


def wrap(tool: Any, *, policy: Policy) -> Any:
    """Wrap an OpenAI Agents SDK tool with a toolwall policy.

    Accepts a ``FunctionTool`` instance (patches ``on_invoke_tool``), a
    ``@function_tool``-decorated callable, or a bare callable. Returns
    the same shape with the firewall attached.
    """
    if getattr(tool, _FLAG, False):
        return tool

    decorate = toolwall(policy=policy)

    # FunctionTool instance: the runner invokes ``on_invoke_tool``.
    if hasattr(tool, "on_invoke_tool") and callable(getattr(tool, "on_invoke_tool", None)):
        tool.on_invoke_tool = decorate(tool.on_invoke_tool)
        with contextlib.suppress(AttributeError, TypeError):
            setattr(tool, _FLAG, True)
        return tool

    # @function_tool-decorated function: functools attaches the
    # original at ``__wrapped__``; patch that so the SDK's schema
    # generation still sees the same signature.
    if hasattr(tool, "__wrapped__") and callable(getattr(tool, "__wrapped__", None)):
        tool.__wrapped__ = decorate(tool.__wrapped__)
        with contextlib.suppress(AttributeError, TypeError):
            setattr(tool, _FLAG, True)
        return tool

    if callable(tool):
        wrapped = decorate(tool)
        # Preserve the SDK's metadata attributes so the agent loop
        # still emits the correct schema.
        for attr in ("name", "description", "params_json_schema", "strict"):
            if hasattr(tool, attr):
                with contextlib.suppress(AttributeError, TypeError):
                    setattr(wrapped, attr, getattr(tool, attr))
        with contextlib.suppress(AttributeError, TypeError):
            setattr(wrapped, _FLAG, True)
        return wrapped

    raise TypeError(
        "expected OpenAI Agents SDK tool: FunctionTool, @function_tool callable, or bare callable"
    )


__all__ = ["wrap"]
