"""MinHash + character 5-gram Jaccard near-dup check between train_v0_1.jsonl
and the frozen test.jsonl. Output: results/train_test_similarity.json.

Flags any test case with max_jaccard > 0.4 against any train case as POTENTIAL_LEAK.

Pure stdlib + datasketch. Idempotent.
"""
from __future__ import annotations

import json
import sys
from collections import defaultdict
from pathlib import Path

from datasketch import MinHash, MinHashLSH

REPO_ROOT = Path(__file__).resolve().parent.parent
TEST = REPO_ROOT / "bench/build_artifacts/v0_1_inhouse/test.jsonl"
TRAIN_CANDIDATES = [
    REPO_ROOT / "training/_corpus/train_v0_1.jsonl",
    REPO_ROOT / "bench/build_artifacts/v0_1_inhouse/train.jsonl",
    REPO_ROOT / "training/data/train_v0_1.jsonl",
]
OUT = REPO_ROOT / "results/train_test_similarity.json"

N_PERM = 128
LSH_THRESH = 0.5
LEAK_THRESH = 0.4
NGRAM = 5


def find_train() -> Path:
    for p in TRAIN_CANDIDATES:
        if p.exists():
            return p
    sys.exit(f"no train file found, looked at: {TRAIN_CANDIDATES}")


def ngrams(s: str, n: int = NGRAM) -> set[str]:
    s = " ".join(s.lower().split())
    if len(s) < n:
        return {s}
    return {s[i : i + n] for i in range(len(s) - n + 1)}


def jaccard(a: set, b: set) -> float:
    if not a or not b:
        return 0.0
    inter = len(a & b)
    union = len(a | b)
    return inter / union if union else 0.0


def case_text(c: dict) -> str:
    return c.get("tool_response") or c.get("text") or c.get("input") or json.dumps(c)


def main():
    train_path = find_train()
    train = [json.loads(l) for l in train_path.open()]
    test = [json.loads(l) for l in TEST.open()]
    print(f"[load] train={len(train)} ({train_path.name}) test={len(test)}", flush=True)

    # Build MinHash sigs over 5-grams
    train_mh: list[tuple[str, MinHash, set[str]]] = []
    lsh = MinHashLSH(threshold=LSH_THRESH, num_perm=N_PERM)
    for i, c in enumerate(train):
        grams = ngrams(case_text(c))
        m = MinHash(num_perm=N_PERM)
        for g in grams:
            m.update(g.encode())
        key = f"train-{i}"
        lsh.insert(key, m)
        train_mh.append((key, m, grams))

    per_test = []
    leaks = []
    fam_max: dict[str, float] = defaultdict(float)
    fam_mean: dict[str, list[float]] = defaultdict(list)

    for j, t in enumerate(test):
        grams_t = ngrams(case_text(t))
        m_t = MinHash(num_perm=N_PERM)
        for g in grams_t:
            m_t.update(g.encode())
        # Candidates from LSH
        cands = lsh.query(m_t)
        # Exact Jaccard on candidates
        max_j = 0.0
        max_key = None
        for key in cands:
            idx = int(key.split("-")[1])
            j_val = jaccard(grams_t, train_mh[idx][2])
            if j_val > max_j:
                max_j = j_val
                max_key = key
        # If no LSH hits, max_j stays 0 (true low similarity)
        rec = {
            "test_id": t["id"],
            "attack_kind": t["attack_kind"],
            "max_jaccard5": max_j,
            "max_train_idx": max_key,
            "leak_flag": max_j > LEAK_THRESH,
        }
        per_test.append(rec)
        if rec["leak_flag"]:
            leaks.append(rec)
        fam_max[t["attack_kind"]] = max(fam_max[t["attack_kind"]], max_j)
        fam_mean[t["attack_kind"]].append(max_j)

    summary = {
        "train_source": str(train_path.relative_to(REPO_ROOT)),
        "train_n": len(train),
        "test_n": len(test),
        "ngram": NGRAM,
        "lsh_threshold": LSH_THRESH,
        "leak_threshold": LEAK_THRESH,
        "leak_count": len(leaks),
        "leaks": leaks[:50],
        "per_family_max_jaccard5": dict(fam_max),
        "per_family_mean_jaccard5": {k: sum(v) / len(v) for k, v in fam_mean.items()},
        "overall_max": max(r["max_jaccard5"] for r in per_test),
        "overall_mean": sum(r["max_jaccard5"] for r in per_test) / len(per_test),
        "ran_at": __import__("time").strftime("%Y-%m-%d"),
    }
    OUT.parent.mkdir(parents=True, exist_ok=True)
    OUT.write_text(json.dumps(summary, indent=2))
    print(json.dumps(summary, indent=2))
    if leaks:
        print(f"\n*** {len(leaks)} potential leak(s) above J5 > {LEAK_THRESH} ***", file=sys.stderr)
        sys.exit(2)


if __name__ == "__main__":
    main()
