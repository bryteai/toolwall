"""Score defenses on the external held-out set (bench/build_artifacts/external_v0_2).

Defenses are detectors: each returns blocked / not blocked for one tool response.

    python -m eval.run_external_v0_2 --defense toolwall_rule_only
    python -m eval.run_external_v0_2 --defense protectai_deberta_v2     # baseline (CPU ok)
    # toolwall (rules + judge) runs on a GPU host: eval/modal_external_v0_2.py

Writes results/external_v0_2/<defense>.decisions.jsonl and prints / saves a summary
with Wilson 95% intervals.
"""

from __future__ import annotations

import argparse
import json
import math
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
DATA = ROOT / "bench" / "build_artifacts" / "external_v0_2"
OUT = ROOT / "results" / "external_v0_2"
SETS = ["injecagent_base", "injecagent_enhanced", "injecagent_twin", "wiki_benign", "wiki_hardneg"]


def wilson(k: int, n: int, z: float = 1.96) -> tuple[float, float, float]:
    if n == 0:
        return (float("nan"),) * 3
    p = k / n
    d = 1 + z * z / n
    c = (p + z * z / (2 * n)) / d
    h = z * math.sqrt(p * (1 - p) / n + z * z / (4 * n * n)) / d
    return p, max(0.0, c - h), min(1.0, c + h)


def load_rows() -> list[dict]:
    rows = []
    for s in SETS:
        for line in open(DATA / f"{s}.jsonl", encoding="utf-8"):
            r = json.loads(line)
            r["set"] = s
            rows.append(r)
    return rows


def make_defense(name: str):
    if name == "toolwall_rule_only":
        from eval.baselines import ToolwallRuleOnly
        d = ToolwallRuleOnly()
        return lambda t: d.decide(t).blocked
    if name == "toolwall":
        from eval.baselines import Toolwall
        d = Toolwall(use_judge=True)
        return lambda t: d.decide(t).blocked
    if name == "protectai_deberta_v2":
        from transformers import pipeline  # type: ignore[import-not-found]
        clf = pipeline("text-classification", model="protectai/deberta-v3-base-prompt-injection-v2",
                       truncation=True, max_length=512)
        return lambda t: clf(t[:4000])[0]["label"].upper() == "INJECTION"
    raise SystemExit(f"unknown defense {name}")


def summarise(decisions: list[dict]) -> dict:
    out = {}
    for s in SETS:
        rs = [d for d in decisions if d["set"] == s]
        if not rs:
            continue
        k = sum(1 for d in rs if d["blocked"])
        if rs[0]["expected_block"]:
            asr, lo, hi = wilson(len(rs) - k, len(rs))   # attack success = not blocked
            out[s] = {"n": len(rs), "metric": "ASR", "value": asr, "ci95": [lo, hi]}
        else:
            fpr, lo, hi = wilson(k, len(rs))             # false positive = benign blocked
            out[s] = {"n": len(rs), "metric": "FPR", "value": fpr, "ci95": [lo, hi]}
    return out


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--defense", required=True)
    ap.add_argument("--decisions", type=Path, help="score an existing decisions file instead of running")
    a = ap.parse_args()
    OUT.mkdir(parents=True, exist_ok=True)
    if a.decisions:
        decisions = [json.loads(line) for line in open(a.decisions)]
    else:
        decide = make_defense(a.defense)
        decisions = []
        for r in load_rows():
            decisions.append({"id": r["id"], "set": r["set"], "expected_block": r["expected_block"],
                              "blocked": bool(decide(r["tool_response"]))})
        with open(OUT / f"{a.defense}.decisions.jsonl", "w") as f:
            for d in decisions:
                f.write(json.dumps(d) + "\n")
    summary = summarise(decisions)
    (OUT / f"{a.defense}.summary.json").write_text(json.dumps(summary, indent=2))
    for s, v in summary.items():
        print(f"{a.defense:24} {s:22} n={v['n']:5} {v['metric']} {v['value']:.3f} [{v['ci95'][0]:.3f}, {v['ci95'][1]:.3f}]")


if __name__ == "__main__":
    main()
