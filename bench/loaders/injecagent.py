"""Adapter for the InjecAgent corpus (Zhan et al., ACL Findings 2024).

We import 500 of the harder cases. InjecAgent ships at:

    https://github.com/uiuc-kang-lab/InjecAgent
    pinned revision: f19c9f2c79a41046eb13c03c51a24c567a8ffa07 (2024-07-02)
    (v0.1 of this file named a revision and a HuggingFace mirror that do not
    exist; corrected in v0.2. The v0.2 external evaluation builds directly
    from the upstream repo: see bench/external/build_v0_2.py.)

Network access at build time is optional --- we keep a frozen copy of
the *case manifest* (IDs + SHA-256 fingerprints) in ``manifests/``.
If the repo is unavailable when ``python -m bench.build`` runs, the
script raises with a clear message instead of producing a silently
shorter dataset.

License: MIT (upstream LICENCE file and GitHub licence metadata at the pinned revision).
We attribute every case via :attr:`bench.schema.Case.citation`.
"""

from __future__ import annotations

import hashlib
import json
from pathlib import Path

from ..schema import AttackKind, Case, Source

UPSTREAM_REPO = "https://github.com/uiuc-kang-lab/InjecAgent"
PINNED_REVISION = "f19c9f2c79a41046eb13c03c51a24c567a8ffa07"
LICENSE_SPDX = "MIT"

# ---------------------------------------------------------------------------
# Kind mapping --- InjecAgent organizes attacks by "Direct" (ds) and
# "Combined" (cs). We re-label onto our seven families using the
# table in InjecAgent's data/attack_types.json (verified at the pinned
# revision).
# ---------------------------------------------------------------------------
_KIND_MAP = {
    "ds": AttackKind.MULTI_HOP,
    "cs": AttackKind.MULTI_HOP,
    "direct_harm": AttackKind.TOOL_POISONING,
    "exfil": AttackKind.MARKDOWN_EXFIL,
}


def load(local_dump: Path | None = None) -> list[Case]:
    """Load 500 InjecAgent cases as :class:`Case` objects.

    Parameters
    ----------
    local_dump:
        Optional path to a local JSONL copy of the upstream cases. If
        ``None``, the function looks for
        ``bench/loaders/_cache/injecagent_500.jsonl``. If neither
        exists, raises :class:`FileNotFoundError` with the
        ``git clone`` instructions --- we refuse to silently produce a
        shorter dataset.
    """
    cache_path = (
        local_dump
        if local_dump is not None
        else Path(__file__).parent / "_cache" / "injecagent_500.jsonl"
    )
    if not cache_path.exists():
        raise FileNotFoundError(
            "InjecAgent cache not found. Download the upstream dataset:\n"
            f"  git clone --depth 1 {UPSTREAM_REPO}\n"
            f"  git -C InjecAgent checkout {PINNED_REVISION}\n"
            f"  python -m bench.loaders.injecagent --build-cache "
            f"InjecAgent/data --out {cache_path}\n"
            "(see bench/README.md §Reproducing the bench)."
        )
    out: list[Case] = []
    with cache_path.open("r", encoding="utf-8") as f:
        for raw in f:
            rec = json.loads(raw)
            kind = _KIND_MAP.get(rec.get("attack_type", ""), AttackKind.OTHER)
            out.append(
                Case(
                    id=f"injecagent-{int(rec['idx']):04d}",
                    attack_kind=kind,
                    tool_response=rec["attacker_observation"],
                    expected_block=True,
                    expected_utility_payload=[],
                    source=Source.INJECAGENT,
                    citation=(
                        "Zhan et al., 'InjecAgent: Benchmarking Indirect "
                        "Prompt Injections in Tool-Integrated Large Language "
                        "Model Agents', ACL Findings 2024."
                    ),
                    notes=f"upstream={UPSTREAM_REPO}@{PINNED_REVISION[:8]}",
                )
            )
    if len(out) != 500:
        raise ValueError(
            f"InjecAgent cache has {len(out)} cases; expected 500. "
            "Re-run the cache builder against the pinned revision."
        )
    return out


def fingerprint(cases: list[Case]) -> str:
    """SHA-256 over the ordered ids+tool_responses --- pinned in the README."""
    h = hashlib.sha256()
    for c in cases:
        h.update(c.id.encode())
        h.update(b"\x00")
        h.update(c.tool_response.encode())
        h.update(b"\x01")
    return h.hexdigest()
