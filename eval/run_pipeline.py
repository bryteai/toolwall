"""Stage 1 → 2 → 3 orchestrator. One command, reproducible.

Example::

    # Offline (in-house 200 cases only, no judge model needed):
    python -m eval.run_pipeline --inhouse-only

    # Full bench against rules+judge (requires HF judge weights):
    python -m eval.run_pipeline --split bench/build_artifacts/v0_1/test.jsonl \\
        --with-judge

The pipeline writes to ``eval/_artifacts/`` for the intermediate
artifacts and to ``results/`` for the final comparison CSV +
markdown. The harness refuses to overwrite ``results/v0.1.csv`` if
it already exists (use ``--bench-version`` to bump for a rerun).
"""

from __future__ import annotations

import argparse
from pathlib import Path

from . import generate_attacks, run_firewall, score


def main() -> None:
    p = argparse.ArgumentParser()
    g = p.add_mutually_exclusive_group(required=True)
    g.add_argument(
        "--inhouse-only",
        action="store_true",
        help="Use the offline 200-case in-house slice.",
    )
    g.add_argument(
        "--split",
        type=Path,
        help="Path to a bench split JSONL.",
    )
    p.add_argument(
        "--with-judge",
        action="store_true",
        help="Enable the LoRA judge model (requires HF weights).",
    )
    p.add_argument(
        "--bench-version",
        default="v0.1",
        help="Used in the results filename and the markdown footer.",
    )
    p.add_argument(
        "--artifacts-dir",
        type=Path,
        default=Path("eval/_artifacts"),
    )
    p.add_argument(
        "--results-dir",
        type=Path,
        default=Path("results"),
    )
    p.add_argument(
        "--force",
        action="store_true",
        help="Overwrite results if they already exist.",
    )
    args = p.parse_args()

    csv_out = args.results_dir / f"{args.bench_version}.csv"
    md_out = args.results_dir / f"{args.bench_version}.md"
    if csv_out.exists() and not args.force:
        raise SystemExit(f"{csv_out} already exists. Bump --bench-version or pass --force.")

    args.artifacts_dir.mkdir(parents=True, exist_ok=True)
    attacks_path = args.artifacts_dir / "attacks.jsonl"
    decisions_path = args.artifacts_dir / "decisions.jsonl"

    # Stage 1: materialize bench → attacks.jsonl
    cases = (
        generate_attacks.from_inhouse()
        if args.inhouse_only
        else generate_attacks.from_split_file(args.split)
    )
    n = generate_attacks.write(cases, attacks_path)
    print(f"[1/3] materialized {n} cases → {attacks_path}")

    # Stage 2: defenses → decisions.jsonl
    n = run_firewall.run(
        attacks_path,
        decisions_path,
        use_judge=args.with_judge,
    )
    print(f"[2/3] wrote {n} decisions → {decisions_path}")

    # Stage 3: aggregate → results/<version>.{csv,md}
    by_defense = score.run(
        decisions_path,
        csv_out,
        md_out,
        bench_version=args.bench_version,
        judge_active=args.with_judge,
    )
    print(f"[3/3] scored {len(by_defense)} defenses")
    print(f"      csv → {csv_out}")
    print(f"      md  → {md_out}")


if __name__ == "__main__":
    main()
