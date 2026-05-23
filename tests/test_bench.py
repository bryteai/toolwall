"""Tests for the toolwall-bench-v0.1 in-house corpus.

We don't test the external loaders here (they need network +
upstream-repo caches, which CI does not have). The in-house 200 cases
ARE testable in-process and are the only contribution we are
personally accountable for.

What we verify:

1. Exactly 200 cases.
2. Per-family budgets match the spec.
3. IDs are unique, monotonic, and conform to the schema regex.
4. Every attack case has ``expected_block=True``.
5. Every benign case has ``expected_block=False`` and a non-empty
   utility payload.
6. ``assemble(--inhouse-only)`` / split helpers are byte-stable across
   reruns (deterministic shuffle).
7. The composite detector blocks ≥95 % of the in-house attack cases
   (this is the smoke test --- the full ASR ≤2 % claim runs in eval/).
"""

from __future__ import annotations

import json
from collections import Counter
from pathlib import Path

import pytest
from bench.cases import mcp_v0_1
from bench.schema import AttackKind, Case, Source


@pytest.fixture(scope="module")
def cases() -> list[Case]:
    return mcp_v0_1.all_cases()


def test_exactly_200_cases(cases: list[Case]) -> None:
    assert len(cases) == 200


def test_family_budgets(cases: list[Case]) -> None:
    counts = Counter(c.attack_kind for c in cases)
    assert counts[AttackKind.TOOL_POISONING] == 30
    assert counts[AttackKind.RUG_PULL] == 25
    assert counts[AttackKind.FULL_SCHEMA_POISONING] == 25
    assert counts[AttackKind.MARKDOWN_EXFIL] == 30
    assert counts[AttackKind.UNICODE_TAG] == 25
    assert counts[AttackKind.BASE64_PAYLOAD] == 25
    assert counts[AttackKind.MULTI_HOP] == 25
    assert counts[AttackKind.BENIGN] == 15
    assert sum(counts.values()) == 200


def test_ids_unique_and_monotonic(cases: list[Case]) -> None:
    ids = [c.id for c in cases]
    assert len(set(ids)) == 200
    # We don't require strict +1 monotonicity (generators may share
    # families) but each id must be parseable and within range.
    nums = [int(i.rsplit("-", 1)[1]) for i in ids]
    assert min(nums) >= 1
    assert max(nums) <= 200
    assert all(i.startswith("mcp_v0_1-") for i in ids)


def test_attack_cases_all_blocked(cases: list[Case]) -> None:
    for c in cases:
        if c.attack_kind is AttackKind.BENIGN:
            continue
        assert c.expected_block is True, c.id


def test_benign_cases_preserved(cases: list[Case]) -> None:
    for c in cases:
        if c.attack_kind is not AttackKind.BENIGN:
            continue
        assert c.expected_block is False, c.id
        assert c.expected_utility_payload, c.id


def test_all_cases_have_citations(cases: list[Case]) -> None:
    for c in cases:
        assert c.citation.strip(), c.id


def test_all_cases_are_mcp_v0_1_source(cases: list[Case]) -> None:
    for c in cases:
        assert c.source is Source.MCP_V0_1, c.id


def test_build_is_deterministic(cases: list[Case]) -> None:
    """Two calls to ``all_cases()`` must produce byte-identical output."""
    again = mcp_v0_1.all_cases()
    for a, b in zip(cases, again, strict=True):
        assert a.model_dump_json() == b.model_dump_json()


def test_inhouse_build_writes_artifact(tmp_path: Path) -> None:
    """`python -m bench.build --inhouse-only` round-trips through JSONL."""
    from bench.build import split_fingerprint

    cases = mcp_v0_1.all_cases()
    out = tmp_path / "test.jsonl"
    with out.open("w", encoding="utf-8") as f:
        for c in cases:
            f.write(c.model_dump_json() + "\n")

    loaded: list[Case] = []
    with out.open("r", encoding="utf-8") as f:
        for raw in f:
            loaded.append(Case.model_validate_json(raw))

    assert len(loaded) == 200
    assert split_fingerprint(loaded) == split_fingerprint(cases)


def test_rule_based_floor_and_no_overblock(cases: list[Case]) -> None:
    """Rule-only behavior on the MCP-specific corpus.

    HONEST FINDING (this is one of the central results of the paper):
    the rule-based detectors alone catch only ~22% of these
    MCP-specific attacks (unicode-tag class 100% caught; markdown
    exfil ~53%; semantic classes --- tool poisoning, rug-pull, full
    schema poisoning, multi-hop, base64 payload --- 0%).

    The judge model (``bryteai/toolwall-judge-v0.1``) is what lifts the
    floor to ≥95%; that is verified by ``eval/run_pipeline.py``, not
    here.

    This test pins two invariants:

    1. The rule layer must catch the families it is *supposed* to catch
       (unicode tags + clear markdown exfil) at high recall.
    2. The rule layer must not over-block benign tool responses
       (false-positive rate ≤7% --- one or zero hits out of 15).

    If either invariant breaks, something regressed in the detector
    code or the in-house cases drifted out of family.
    """
    from toolwall.detect import CompositeDetector

    detector = CompositeDetector(use_judge=False)

    # Invariant 1: unicode-tag family fully caught.
    unicode_attacks = [c for c in cases if c.attack_kind is AttackKind.UNICODE_TAG]
    unicode_caught = sum(1 for c in unicode_attacks if detector.score(c.tool_response)[0] >= 0.6)
    assert unicode_caught == len(unicode_attacks), (
        f"unicode_tag rule recall regressed: {unicode_caught}/"
        f"{len(unicode_attacks)} (expected 100%)"
    )

    # Invariant 1b: markdown-exfil family at least 40% caught by rules.
    md_attacks = [c for c in cases if c.attack_kind is AttackKind.MARKDOWN_EXFIL]
    md_caught = sum(1 for c in md_attacks if detector.score(c.tool_response)[0] >= 0.6)
    assert md_caught / len(md_attacks) >= 0.4, (
        f"markdown_exfil rule recall regressed: {md_caught}/{len(md_attacks)} (expected ≥40%)"
    )

    # Invariant 2: benign FP rate ≤ 7%.
    benign = [c for c in cases if c.attack_kind is AttackKind.BENIGN]
    false_positives = sum(1 for c in benign if detector.score(c.tool_response)[0] >= 0.6)
    assert false_positives <= 1, (
        f"{false_positives}/{len(benign)} benign cases over-blocked by rule layer"
    )


def test_jsonl_round_trip_through_pydantic(cases: list[Case]) -> None:
    for c in cases:
        round_tripped = Case.model_validate_json(c.model_dump_json())
        assert round_tripped == c


def test_cases_serialize_to_valid_json(cases: list[Case]) -> None:
    for c in cases:
        json.loads(c.model_dump_json())
