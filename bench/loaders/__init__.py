"""Loaders for the two external corpora re-shipped in toolwall-bench-v0.1.

Both upstream datasets are permissively licensed; we re-ship them in
adapted form so the bench is a single self-contained artifact. Each
loader pins the upstream revision (git SHA / HuggingFace commit) so a
re-run produces byte-identical input. The downstream :func:`bench.build`
verifies these SHAs before assembling.
"""

from . import agentdojo, injecagent

__all__ = ["agentdojo", "injecagent"]
