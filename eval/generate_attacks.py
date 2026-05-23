"""Stage 1: materialize a bench split into the flat eval JSONL shape.

Reads either the in-house 200-case slice (offline, no network) or a
full bench split file produced by ``python -m bench.build``. Writes a
``attacks.jsonl`` where every line is::

    {
      "id": "mcp_v0_1-0001",
      "attack_kind": "tool_poisoning",
      "tool_response": "...",
      "expected_block": true,
      "expected_utility_payload": [...],
      "source": "mcp_v0_1"
    }

We refuse to silently re-shuffle. The order is the same byte-stable
order produced by ``bench.cases.mcp_v0_1.all_cases()`` (in-house) or
the split JSONL on disk (full bench).
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path

from bench.cases import mcp_v0_1
from bench.schema import Case


def from_inhouse() -> list[Case]:
    """Return the in-house 200 cases in canonical generator order."""
    return mcp_v0_1.all_cases()


def from_split_file(path: Path) -> list[Case]:
    """Load a bench split JSONL (test / dev / train) into Cases."""
    out: list[Case] = []
    with path.open("r", encoding="utf-8") as f:
        for raw in f:
            raw = raw.strip()
            if not raw:
                continue
            out.append(Case.model_validate_json(raw))
    return out


def write(cases: list[Case], out_path: Path) -> int:
    out_path.parent.mkdir(parents=True, exist_ok=True)
    with out_path.open("w", encoding="utf-8") as f:
        for c in cases:
            f.write(
                json.dumps(
                    {
                        "id": c.id,
                        "attack_kind": c.attack_kind.value,
                        "tool_response": c.tool_response,
                        "expected_block": c.expected_block,
                        "expected_utility_payload": c.expected_utility_payload,
                        "source": c.source.value,
                    },
                    ensure_ascii=False,
                )
                + "\n"
            )
    return len(cases)


def _cli() -> None:
    p = argparse.ArgumentParser()
    p.add_argument(
        "--inhouse-only",
        action="store_true",
        help="Use the 200-case in-house slice (offline).",
    )
    p.add_argument(
        "--split",
        type=Path,
        default=None,
        help="Path to a bench split JSONL (e.g. bench/build_artifacts/.../test.jsonl).",
    )
    p.add_argument(
        "--out",
        type=Path,
        default=Path("eval/_artifacts/attacks.jsonl"),
    )
    args = p.parse_args()

    if args.inhouse_only and args.split is not None:
        raise SystemExit("--inhouse-only and --split are mutually exclusive.")
    if not args.inhouse_only and args.split is None:
        raise SystemExit("Pass --inhouse-only or --split PATH.")

    cases = from_inhouse() if args.inhouse_only else from_split_file(args.split)
    n = write(cases, args.out)
    print(f"wrote {n} cases to {args.out}")


if __name__ == "__main__":
    _cli()
