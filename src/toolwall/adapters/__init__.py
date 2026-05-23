"""Framework adapters for ``toolwall``.

Each submodule exposes a single ``wrap(tool, *, policy=Policy)`` entry
point that returns the same tool shape with the firewall attached. The
public API surface is deliberately tiny --- if a user can write the
wrong thing in two different ways, the API is wrong.

Available adapters
------------------
* :mod:`toolwall.adapters.claude_sdk`    --- Anthropic Claude Agent SDK
* :mod:`toolwall.adapters.crewai`        --- CrewAI ``BaseTool`` / ``@tool``
* :mod:`toolwall.adapters.langgraph`     --- LangGraph ``ToolNode`` /
  ``langchain_core.tools``
* :mod:`toolwall.adapters.openai_agents` --- OpenAI Agents SDK
  ``FunctionTool`` / ``@function_tool``
* :mod:`toolwall.adapters.mcp`           --- FastMCP server middleware

The TS port (``packages/toolwall-core``) adds the
``@modelcontextprotocol/sdk`` middleware on the TypeScript side.
"""

from __future__ import annotations

__all__: list[str] = []
