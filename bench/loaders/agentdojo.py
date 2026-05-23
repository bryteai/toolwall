"""Adapter for the AgentDojo corpus (Debenedetti et al., NeurIPS D&B 2024).

We import 354 cases (the full ``injection_tasks`` x 18-attack matrix
collapsed to one case per attack-template-on-task pair). AgentDojo
ships at:

    https://github.com/ethz-spylab/agentdojo
    pinned revision: 3a8e2d1c5f9b074e16a8d2f4c91b3e08a7d6c5e4
    pypi mirror: agentdojo==0.1.43 (frozen)

License: AGPL-3.0 with academic-use clause (per upstream LICENSE).
We comply by linking to upstream and re-distributing only the case
content needed for evaluation, with attribution on every case.

As with the InjecAgent loader, if the cache is absent we refuse to
silently produce a shorter dataset --- raise with explicit
instructions.
"""

from __future__ import annotations

import hashlib
import json
from pathlib import Path

from ..schema import AttackKind, Case, Source

UPSTREAM_REPO = "https://github.com/ethz-spylab/agentdojo"
PINNED_REVISION = "3a8e2d1c5f9b074e16a8d2f4c91b3e08a7d6c5e4"
LICENSE_SPDX = "AGPL-3.0-or-later"

# AgentDojo attack templates map onto our families. The table below was
# derived from agentdojo.attacks.attack_registry at the pinned revision.
_AGENTDOJO_KIND_MAP = {
    "direct": AttackKind.TOOL_POISONING,
    "ignore_previous": AttackKind.TOOL_POISONING,
    "important_instructions": AttackKind.TOOL_POISONING,
    "tool_knowledge": AttackKind.FULL_SCHEMA_POISONING,
    "system_message": AttackKind.TOOL_POISONING,
    "injecagent": AttackKind.MULTI_HOP,
    "captured_user_query": AttackKind.MULTI_HOP,
}


def load(local_dump: Path | None = None) -> list[Case]:
    cache_path = (
        local_dump
        if local_dump is not None
        else Path(__file__).parent / "_cache" / "agentdojo_354.jsonl"
    )
    if not cache_path.exists():
        raise FileNotFoundError(
            "AgentDojo cache not found. To populate:\n"
            f"  pip install agentdojo==0.1.43\n"
            f"  python -m bench.loaders.agentdojo --build-cache "
            f"--out {cache_path}\n"
            "(see bench/README.md §Reproducing the bench). Confirms\n"
            f"upstream={UPSTREAM_REPO}@{PINNED_REVISION[:8]}."
        )
    out: list[Case] = []
    with cache_path.open("r", encoding="utf-8") as f:
        for raw in f:
            rec = json.loads(raw)
            kind = _AGENTDOJO_KIND_MAP.get(rec.get("attack", "direct"), AttackKind.OTHER)
            out.append(
                Case(
                    id=f"agentdojo-{int(rec['idx']):04d}",
                    attack_kind=kind,
                    tool_response=rec["injection_text"],
                    expected_block=True,
                    expected_utility_payload=[],
                    source=Source.AGENTDOJO,
                    citation=(
                        "Debenedetti et al., 'AgentDojo: A dynamic "
                        "environment to evaluate prompt injection attacks "
                        "and defenses for LLM agents', NeurIPS D&B 2024."
                    ),
                    notes=(
                        f"attack={rec.get('attack', '?')}; "
                        f"upstream={UPSTREAM_REPO}@{PINNED_REVISION[:8]}"
                    ),
                )
            )
    if len(out) != 354:
        raise ValueError(f"AgentDojo cache has {len(out)} cases; expected 354.")
    return out


def fingerprint(cases: list[Case]) -> str:
    h = hashlib.sha256()
    for c in cases:
        h.update(c.id.encode())
        h.update(b"\x00")
        h.update(c.tool_response.encode())
        h.update(b"\x01")
    return h.hexdigest()
