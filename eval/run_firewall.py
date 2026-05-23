"""Stage 2: run every defense against every attack JSONL row.

Reads ``attacks.jsonl`` from stage 1, instantiates each baseline in
:mod:`eval.baselines`, and writes ``decisions.jsonl`` --- one line per
(case_id, defense_name) pair.

We do NOT call any external LLM here. Toolwall's own ``CompositeDetector``
is a pure-Python pipeline (regex + Unicode tag scan + markdown-exfil
heuristic). The judge model is opt-in via ``--with-judge``.

Output shape per line::

    {
      "case_id": "mcp_v0_1-0001",
      "attack_kind": "tool_poisoning",
      "expected_block": true,
      "defense": "toolwall_rule_only",
      "blocked": false,
      "reason": "below-threshold",
      "score": 0.0,
      "evidence": []
    }
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any

from . import baselines


def _instantiate_defenses(use_judge: bool) -> list[Any]:
    return [
        baselines.NoDefense(),
        baselines.PromptSandwich(),
        baselines.Spotlight(),
        baselines.ToolwallRuleOnly(),
        baselines.Toolwall(use_judge=use_judge),
    ]


def run(
    attacks_path: Path,
    out_path: Path,
    *,
    use_judge: bool,
) -> int:
    defenses = _instantiate_defenses(use_judge=use_judge)
    out_path.parent.mkdir(parents=True, exist_ok=True)

    n = 0
    with (
        attacks_path.open("r", encoding="utf-8") as f_in,
        out_path.open("w", encoding="utf-8") as f_out,
    ):
        for raw in f_in:
            raw = raw.strip()
            if not raw:
                continue
            case = json.loads(raw)
            for defense in defenses:
                d = defense.decide(case["tool_response"])
                f_out.write(
                    json.dumps(
                        {
                            "case_id": case["id"],
                            "attack_kind": case["attack_kind"],
                            "expected_block": case["expected_block"],
                            "defense": defense.name,
                            "blocked": d.blocked,
                            "reason": d.reason,
                            "score": d.score,
                            "evidence": d.evidence,
                        },
                        ensure_ascii=False,
                    )
                    + "\n"
                )
                n += 1
    return n


def _cli() -> None:
    p = argparse.ArgumentParser()
    p.add_argument(
        "--attacks",
        type=Path,
        default=Path("eval/_artifacts/attacks.jsonl"),
    )
    p.add_argument(
        "--out",
        type=Path,
        default=Path("eval/_artifacts/decisions.jsonl"),
    )
    p.add_argument(
        "--with-judge",
        action="store_true",
        help="Enable the LoRA judge model (requires the HF weights).",
    )
    args = p.parse_args()
    n = run(args.attacks, args.out, use_judge=args.with_judge)
    print(f"wrote {n} decisions to {args.out}")


if __name__ == "__main__":
    _cli()
