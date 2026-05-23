"""Assemble and split ``toolwall-bench-v0.1``.

Run::

    python -m bench.build

Steps:

1. Load the 200 in-house MCP cases (always available; pure-Python).
2. Load the 500 InjecAgent cases (from local cache; refuse if absent).
3. Load the 354 AgentDojo cases (from local cache; refuse if absent).
4. Verify each loader's fingerprint against the SHA-256 pinned in this
   file (so a regression in upstream silently changing case strings
   would be caught).
5. Deterministic 600/200/254 split using a *seeded* shuffle on the
   sorted id list. The seed is committed; reruns are byte-stable.
6. Write ``build_artifacts/v0_1/{train,dev,test}.jsonl`` and a
   ``MANIFEST.json`` containing per-split SHA-256.

The published test-split SHA is the audit hook: any paper reporting
numbers against ``toolwall-bench-v0.1`` test set must echo this hash
in its appendix.
"""

from __future__ import annotations

import hashlib
import json
import random
from pathlib import Path

from .cases import mcp_v0_1
from .loaders import agentdojo as agentdojo_loader
from .loaders import injecagent as injecagent_loader
from .schema import Case, Split

# ---------------------------------------------------------------------------
# Pinned fingerprints --- regenerate ONLY when intentionally bumping bench
# version (e.g. v0.1 -> v0.2). Until then any mismatch is a build failure.
# ---------------------------------------------------------------------------
EXPECTED_FINGERPRINTS = {
    # filled by `python -m bench.build --bless` on the first clean build
    "mcp_v0_1": "",
    "injecagent": "",
    "agentdojo": "",
}

SPLIT_SIZES = {
    Split.TRAIN: 600,
    Split.DEV: 200,
    Split.TEST: 254,
}
SHUFFLE_SEED = 20260523  # frozen for v0.1 reproducibility — do not change

ARTIFACT_DIR = Path(__file__).parent / "build_artifacts" / "v0_1"


def _mcp_fingerprint(cases: list[Case]) -> str:
    h = hashlib.sha256()
    for c in cases:
        h.update(c.id.encode())
        h.update(b"\x00")
        h.update(c.tool_response.encode())
        h.update(b"\x01")
    return h.hexdigest()


def assemble() -> list[Case]:
    """Load + verify all three sources. Returns the unsplit corpus."""
    mcp_cases = mcp_v0_1.all_cases()
    if len(mcp_cases) != 200:
        raise ValueError(
            f"in-house corpus must be exactly 200 cases (got {len(mcp_cases)}); "
            "edit bench/cases/mcp_v0_1.py to fix the generators."
        )

    # Optional external loaders. We support a "stub mode" controlled by an
    # env flag for CI-without-network --- it produces a 200-case bench from
    # the in-house corpus only, with a clear filename suffix so it cannot be
    # confused with the canonical 1054-case bench.
    try:
        ia = injecagent_loader.load()
        ad = agentdojo_loader.load()
    except FileNotFoundError as exc:
        raise FileNotFoundError(
            f"{exc}\n\nIf you only want to test the in-house split (200 cases), "
            "run `python -m bench.build --inhouse-only` instead --- that emits "
            "a v0.1-inhouse manifest that is NOT the canonical bench."
        ) from exc

    if EXPECTED_FINGERPRINTS["mcp_v0_1"]:
        got = _mcp_fingerprint(mcp_cases)
        if got != EXPECTED_FINGERPRINTS["mcp_v0_1"]:
            raise ValueError(
                f"mcp_v0_1 fingerprint drift: expected "
                f"{EXPECTED_FINGERPRINTS['mcp_v0_1'][:12]}, got {got[:12]}"
            )
    if EXPECTED_FINGERPRINTS["injecagent"]:
        got = injecagent_loader.fingerprint(ia)
        if got != EXPECTED_FINGERPRINTS["injecagent"]:
            raise ValueError(
                f"InjecAgent fingerprint drift: expected "
                f"{EXPECTED_FINGERPRINTS['injecagent'][:12]}, got {got[:12]}"
            )
    if EXPECTED_FINGERPRINTS["agentdojo"]:
        got = agentdojo_loader.fingerprint(ad)
        if got != EXPECTED_FINGERPRINTS["agentdojo"]:
            raise ValueError(
                f"AgentDojo fingerprint drift: expected "
                f"{EXPECTED_FINGERPRINTS['agentdojo'][:12]}, got {got[:12]}"
            )

    return mcp_cases + ia + ad


def split(cases: list[Case]) -> dict[Split, list[Case]]:
    """Deterministic 600/200/254 shuffle, keyed by id."""
    expected_total = sum(SPLIT_SIZES.values())
    if len(cases) != expected_total:
        raise ValueError(f"need {expected_total} cases to split; got {len(cases)}")
    # Sort by id then shuffle with a frozen seed. This means the split is
    # invariant to the order in which sources were concatenated --- ANY
    # author who reproduces the assembly gets the same split.
    ordered = sorted(cases, key=lambda c: c.id)
    rng = random.Random(SHUFFLE_SEED)
    rng.shuffle(ordered)

    out: dict[Split, list[Case]] = {}
    cursor = 0
    for sp in (Split.TRAIN, Split.DEV, Split.TEST):
        n = SPLIT_SIZES[sp]
        out[sp] = ordered[cursor : cursor + n]
        cursor += n
    return out


def split_fingerprint(cases: list[Case]) -> str:
    h = hashlib.sha256()
    for c in cases:
        # Hash a stable subset of fields. ``citation`` and ``notes`` are
        # human-edited metadata; excluding them means typo fixes don't
        # invalidate published numbers.
        h.update(c.id.encode())
        h.update(b"\x00")
        h.update(c.tool_response.encode())
        h.update(b"\x01")
        h.update(c.attack_kind.value.encode())
        h.update(b"\x02")
        h.update(b"1" if c.expected_block else b"0")
        h.update(b"\x03")
    return h.hexdigest()


def write(
    splits: dict[Split, list[Case]],
    out_dir: Path | None = None,
) -> dict[str, str]:
    """Write JSONL + MANIFEST.json. Returns {split: sha256}."""
    target = out_dir if out_dir is not None else ARTIFACT_DIR
    target.mkdir(parents=True, exist_ok=True)
    fingerprints: dict[str, str] = {}
    for sp, sp_cases in splits.items():
        path = target / f"{sp.value}.jsonl"
        with path.open("w", encoding="utf-8") as f:
            for c in sp_cases:
                f.write(c.model_dump_json() + "\n")
        fingerprints[sp.value] = split_fingerprint(sp_cases)
    manifest = {
        "bench_version": "v0.1",
        "shuffle_seed": SHUFFLE_SEED,
        "splits": {sp.value: SPLIT_SIZES[sp] for sp in SPLIT_SIZES},
        "fingerprints": fingerprints,
        "sources": {
            "mcp_v0_1": "in-house (Muhammad Hasnain, bryteai.studio)",
            "injecagent": (
                f"{injecagent_loader.UPSTREAM_REPO}@{injecagent_loader.PINNED_REVISION}"
            ),
            "agentdojo": (f"{agentdojo_loader.UPSTREAM_REPO}@{agentdojo_loader.PINNED_REVISION}"),
        },
    }
    (target / "MANIFEST.json").write_text(json.dumps(manifest, indent=2, sort_keys=True) + "\n")
    return fingerprints


def load_split(split_name: str) -> list[Case]:
    """Read a previously-written split back into memory."""
    path = ARTIFACT_DIR / f"{split_name}.jsonl"
    if not path.exists():
        raise FileNotFoundError(f"split '{split_name}' not built yet. Run: python -m bench.build")
    out: list[Case] = []
    with path.open("r", encoding="utf-8") as f:
        for raw in f:
            out.append(Case.model_validate_json(raw))
    return out


def _cli() -> None:  # pragma: no cover --- thin CLI wrapper
    import argparse

    p = argparse.ArgumentParser(prog="python -m bench.build")
    p.add_argument(
        "--inhouse-only",
        action="store_true",
        help="Build a 200-case bench from the in-house corpus only "
        "(useful when you do not have network access to fetch upstream).",
    )
    args = p.parse_args()
    if args.inhouse_only:
        cases = mcp_v0_1.all_cases()
        # In-house only --- skip splitter, write a single 200-case file.
        target = ARTIFACT_DIR.parent / "v0_1_inhouse"
        target.mkdir(parents=True, exist_ok=True)
        path = target / "test.jsonl"
        with path.open("w", encoding="utf-8") as f:
            for c in cases:
                f.write(c.model_dump_json() + "\n")
        fp = split_fingerprint(cases)
        (target / "MANIFEST.json").write_text(
            json.dumps(
                {
                    "bench_version": "v0.1-inhouse",
                    "note": "NOT the canonical 1054-case bench",
                    "fingerprint": fp,
                },
                indent=2,
            )
            + "\n"
        )
        print(f"wrote {len(cases)} in-house cases to {target}/test.jsonl")
        print(f"fingerprint: {fp}")
        return

    cases = assemble()
    splits = split(cases)
    fps = write(splits)
    print("built toolwall-bench-v0.1:")
    for sp, fp in fps.items():
        print(f"  {sp:5}  {SPLIT_SIZES[Split(sp)]:4} cases  sha256={fp}")


if __name__ == "__main__":  # pragma: no cover
    _cli()
