"""``toolwall-bench-v0.1`` --- evaluation dataset for the IPI defense layer.

The bench is composed of three sources, each loaded by its own module
under :mod:`bench.loaders`:

* ``injecagent`` --- 500 cases from Zhan et al., ACL Findings 2024.
* ``agentdojo``  --- 354 cases from Debenedetti et al., NeurIPS D&B 2024.
* ``mcp_v0_1``   --- 200 NEW MCP-specific cases curated by Muhammad
  Hasnain (bryteai.studio), covering the 7 attack families that the
  prior two corpora do not adequately cover.

The new MCP cases are the contribution. The other two are licensed
permissively and re-shipped only to make the benchmark a single
self-contained artifact.

Splits (frozen, SHA-256 pinned in :mod:`bench.build`):

* ``train``     --- 600 (judge fine-tune set; OK to overlap detector corpus)
* ``dev``       --- 200 (early-stopping; sanity)
* ``test``      --- 254 (held-out; **never used during training or tuning**)

Loading the canonical bench from inside Python::

    from bench import load_bench
    bench = load_bench()          # dict with 'train', 'dev', 'test'
    for case in bench['test']:
        ...
"""

from __future__ import annotations

from .schema import AttackKind, Case, Split

__all__ = ["AttackKind", "Case", "Split", "load_bench"]


def load_bench() -> dict[str, list[Case]]:
    """Load the assembled, split bench from disk.

    Reads ``bench/build_artifacts/v0_1/{train,dev,test}.jsonl``. The
    artifacts are produced by ``python -m bench.build`` and committed
    to the repo so end-users do not need network access to reproduce
    eval results.
    """
    from .build import load_split

    return {
        "train": load_split("train"),
        "dev": load_split("dev"),
        "test": load_split("test"),
    }
