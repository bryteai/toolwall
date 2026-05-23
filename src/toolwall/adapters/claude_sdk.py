"""Adapter for the Anthropic Claude Agent SDK.

In the Claude Agent SDK a tool is either:

* a callable already decorated with ``@tool`` from
  ``claude_agent_sdk`` (the SDK attaches ``name``, ``description``,
  ``input_schema`` attributes to the function), or
* a plain ``dict`` with a ``"handler"`` key plus the same metadata.

This adapter wraps the *handler* with :func:`toolwall.toolwall` while
preserving the tool's public schema --- the agent loop never notices
the firewall is there until a policy fires.

Usage
-----
::

    from claude_agent_sdk import tool
    from toolwall import policy
    from toolwall.adapters.claude_sdk import wrap

    @tool("fetch_url", "Fetch a URL", {"url": str})
    async def fetch_url(args: dict) -> dict:
        ...

    safe_fetch = wrap(fetch_url, policy=policy.web_fetch())
"""

from __future__ import annotations

import contextlib
from typing import Any

from ..decorator import toolwall
from ..policy import Policy

_PASSTHROUGH_ATTRS = ("name", "description", "input_schema", "__tool_name__")


def wrap(tool: Any, *, policy: Policy) -> Any:
    """Wrap a Claude Agent SDK tool with a toolwall policy.

    Accepts either a callable (the SDK's ``@tool``-decorated function)
    or a dict shaped as ``{"name", "description", "input_schema", "handler"}``.
    Returns the same shape with the handler firewalled.
    """
    if isinstance(tool, dict):
        if "handler" not in tool or not callable(tool["handler"]):
            raise TypeError("dict tool must include a callable 'handler'")
        wrapped = toolwall(policy=policy)(tool["handler"])
        new = dict(tool)
        new["handler"] = wrapped
        return new

    if not callable(tool):
        raise TypeError("expected callable Claude SDK tool or dict with 'handler'")

    wrapped_fn = toolwall(policy=policy)(tool)
    for attr in _PASSTHROUGH_ATTRS:
        if hasattr(tool, attr):
            with contextlib.suppress(AttributeError, TypeError):
                setattr(wrapped_fn, attr, getattr(tool, attr))
    return wrapped_fn


__all__ = ["wrap"]
