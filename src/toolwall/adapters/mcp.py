"""Middleware adapter for FastMCP servers.

The MCP class of attacks (tool poisoning, rug-pull, full-schema poisoning,
EchoLeak-style markdown exfil through tool responses) is the reason
toolwall exists --- so the MCP adapter is the load-bearing one.

We refuse to fork the MCP SDK. Instead :func:`wrap` patches an existing
``FastMCP`` server instance so every ``@server.tool()``-registered
function is firewalled before being handed to the SDK's registry. The
SDK still owns the JSON-RPC transport, schema introspection, sampling,
and so on; toolwall only owns the call boundary.

Idempotent: calling ``wrap(server, policy=...)`` twice on the same
instance is a no-op. Double-wrapping doubles audit log entries and has
ruined more than one production middleware library --- we refuse.

Usage
-----
::

    from mcp.server.fastmcp import FastMCP
    from toolwall import policy
    from toolwall.adapters.mcp import wrap

    server = FastMCP("calendar")
    wrap(server, policy=policy.mcp())

    @server.tool()
    def get_events(when: str) -> list[dict]:
        ...
"""

from __future__ import annotations

from typing import Any

from ..decorator import toolwall
from ..policy import Policy

_FLAG = "_toolwall_active"


def wrap(server: Any, *, policy: Policy) -> Any:
    """Patch a FastMCP server so every registered tool goes through toolwall.

    Returns the same server instance for chaining.
    """
    if getattr(server, _FLAG, False):
        return server

    if not hasattr(server, "tool") or not callable(server.tool):
        raise TypeError("expected a FastMCP-shaped server with a .tool() decorator method")

    original_tool = server.tool
    decorate = toolwall(policy=policy)

    def _patched_tool(*dec_args: Any, **dec_kwargs: Any) -> Any:
        # FastMCP's .tool(...) returns a decorator that takes the user's
        # function. We intercept that inner step so the function is firewalled
        # before the SDK sees it.
        registrar = original_tool(*dec_args, **dec_kwargs)

        def _register(fn: Any) -> Any:
            return registrar(decorate(fn))

        return _register

    # Preserve attribute name for introspection.
    _patched_tool.__name__ = getattr(original_tool, "__name__", "tool")
    _patched_tool.__doc__ = getattr(original_tool, "__doc__", None)

    try:
        server.tool = _patched_tool
        setattr(server, _FLAG, True)
    except (AttributeError, TypeError) as exc:
        raise TypeError(f"could not attach toolwall middleware to server: {exc}") from exc

    return server


__all__ = ["wrap"]
