"""Hand-curated cases (the contribution).

Importing :func:`bench.cases.mcp_v0_1.all_cases` returns the 200 new
MCP-specific cases that make ``toolwall-bench-v0.1`` a contribution
rather than a re-export of prior work.
"""

from . import mcp_v0_1

__all__ = ["mcp_v0_1"]
