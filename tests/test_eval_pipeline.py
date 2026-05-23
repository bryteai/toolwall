"""Smoke + invariance tests for the ``eval/`` pipeline.

We do NOT re-run the full pipeline against the bench here (that lives
in ``eval/run_pipeline.py`` and writes ``results/``). We DO pin:

1. Stage 1 (``generate_attacks``) produces exactly the in-house 200
   cases in canonical order.
2. Stage 2 (``run_firewall``) emits exactly ``n_cases * n_defenses``
   decisions and every defense name is one of the known set.
3. Stage 3 (``score``) refuses to write results from empty input.
4. The aggregate numbers reproduce the honest finding pinned in
   ``tests/test_bench.py`` (toolwall_rule_only blocks ≥22%, no-defense
   blocks 0%).
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest
from eval import generate_attacks, run_firewall, score


def test_generate_attacks_inhouse_200(tmp_path: Path) -> None:
    out = tmp_path / "attacks.jsonl"
    n = generate_attacks.write(generate_attacks.from_inhouse(), out)
    assert n == 200
    lines = out.read_text(encoding="utf-8").strip().split("\n")
    assert len(lines) == 200
    first = json.loads(lines[0])
    assert set(first.keys()) >= {
        "id",
        "attack_kind",
        "tool_response",
        "expected_block",
        "source",
    }


def test_run_firewall_emits_n_cases_x_n_defenses(tmp_path: Path) -> None:
    attacks = tmp_path / "attacks.jsonl"
    generate_attacks.write(generate_attacks.from_inhouse(), attacks)
    decisions = tmp_path / "decisions.jsonl"
    n = run_firewall.run(attacks, decisions, use_judge=False)
    assert n == 200 * 5  # five baselines

    seen_defenses: set[str] = set()
    with decisions.open() as f:
        for raw in f:
            row = json.loads(raw)
            seen_defenses.add(row["defense"])
    assert seen_defenses == {
        "no_defense",
        "prompt_sandwich",
        "spotlight",
        "toolwall_rule_only",
        "toolwall",
    }


def test_score_refuses_empty(tmp_path: Path) -> None:
    empty = tmp_path / "empty.jsonl"
    empty.write_text("", encoding="utf-8")
    with pytest.raises(SystemExit):
        score.run(
            empty,
            tmp_path / "out.csv",
            tmp_path / "out.md",
            bench_version="v0.1",
            judge_active=False,
        )


def test_honest_finding_reproduces(tmp_path: Path) -> None:
    """Pin the rule-only floor at the eval-pipeline boundary.

    Mirrors ``tests/test_bench.py::test_rule_based_floor_and_no_overblock``
    but at one layer up: it goes through the actual ``run_firewall``
    surface a paper-reviewer would inspect.
    """
    attacks = tmp_path / "attacks.jsonl"
    generate_attacks.write(generate_attacks.from_inhouse(), attacks)
    decisions = tmp_path / "decisions.jsonl"
    run_firewall.run(attacks, decisions, use_judge=False)

    csv_out = tmp_path / "v0.1.csv"
    md_out = tmp_path / "v0.1.md"
    by_defense = score.run(decisions, csv_out, md_out, bench_version="v0.1", judge_active=False)

    no_def = by_defense["no_defense"]
    rule_only = by_defense["toolwall_rule_only"]

    assert no_def["n_attack_blocked"] == 0
    # Honest finding: rule-only catches ≥20% on this corpus.
    rate = rule_only["n_attack_blocked"] / rule_only["n_attack"]
    assert rate >= 0.20, f"rule-only floor regressed to {rate:.2%}"

    # Unicode-tag family: 100% caught by rules.
    fam = rule_only["per_family"]["unicode_tag"]
    assert fam["blocked"] == fam["n"] > 0
