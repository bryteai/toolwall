"""Insert PromptGuard baseline + fix bench metadata + add wilson CIs to existing entries.

Idempotent — won't double-insert PromptGuard. Uses results/promptguard_summary.json as source.
"""
from __future__ import annotations

import json
import math
from collections import defaultdict
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
LB = REPO / "results/leaderboard.json"
PG = REPO / "results/promptguard_summary.json"
JUDGE_PREDS = REPO / "results/judge_predictions.jsonl"
TEST = REPO / "bench/build_artifacts/v0_1_inhouse/test.jsonl"


def wilson(k: int, n: int, z: float = 1.96):
    if n == 0:
        return [0.0, 1.0]
    p = k / n
    d = 1 + z * z / n
    c = (p + z * z / (2 * n)) / d
    h = (z / d) * math.sqrt(p * (1 - p) / n + z * z / (4 * n * n))
    return [max(0.0, c - h), min(1.0, c + h)]


def main():
    lb = json.loads(LB.read_text())

    # Fix bench block: reality is in_house only has test=200, train=4000, no dev
    lb["bench"] = {
        "huggingface_repo": "bryteai/toolwall-bench-v0.1",
        "name": "toolwall-bench-v0.1",
        "version": "0.1.0",
        "splits": {
            "in_house_test": 200,
            "in_house_train_used_for_judge_lora": 4000,
        },
        "test_split_sha256_pin": "ce685e7a36b716b0981f359834e7febf6b237c51059dc74af15d7bf46a0c74f2",
        "total_test_cases": 200,
        "n_attack_in_test": 185,
        "n_benign_in_test": 15,
        "attack_families_in_test": [
            "tool_poisoning",
            "rug_pull",
            "full_schema_poisoning",
            "markdown_exfil",
            "unicode_tag",
            "base64_payload",
            "multi_hop",
        ],
    }

    # Add wilson CIs to existing toolwall entries
    n_attack_total = 185
    n_benign_total = 15
    for e in lb["entries"]:
        if "n_attack" in e and "asr_wilson95" not in e:
            n = e["n_attack"]
            asr_k = int(round(e["asr"] * n))
            e["asr_wilson95"] = wilson(asr_k, n)
        if "n_benign" in e and "utility_wilson95" not in e:
            n = e["n_benign"]
            if n > 0 and e.get("utility") is not None:
                util_k = int(round(e["utility"] * n))
                e["utility_wilson95"] = wilson(util_k, n)

    # Insert PromptGuard baseline (skip if already present)
    if not any(e["defense"] == "promptguard_llama_v2_86m" for e in lb["entries"]):
        pg = json.loads(PG.read_text())
        # Per-family format compatibility: keep only the float ASR map
        pf = {fam: round(info["asr"], 4) for fam, info in pg["per_family"].items()}
        lb["entries"].append(
            {
                "defense": "promptguard_llama_v2_86m",
                "category": "third-party-baseline",
                "git_tag": "v0.1.0",
                "judge_revision": pg["model_id"],
                "asr": round(pg["asr"], 4),
                "asr_wilson95": [round(pg["asr_wilson95"][0], 4), round(pg["asr_wilson95"][1], 4)],
                "utility": round(pg["utility"], 4),
                "utility_wilson95": [round(pg["utility_wilson95"][0], 4), round(pg["utility_wilson95"][1], 4)],
                "n_attack": pg["n_attack"],
                "n_benign": pg["n_benign"],
                "per_family": pf,
                "loc": -1,  # category-error: it's a deps-heavy model not a defense layer
                "loc_note": "Not directly comparable to toolwall LoC: this is a model not an integration. ~150MB safetensors + transformers dep.",
                "ran_at": pg["ran_at"],
                "split": "in-house-200",
                "submitter": "bryteai.studio",
            }
        )

    # Provenance pointers
    lb["provenance"] = lb.get("provenance", {})
    lb["provenance"]["minhash_train_test_similarity"] = "results/train_test_similarity.json"
    lb["provenance"]["promptguard_predictions"] = "results/promptguard_predictions.jsonl"
    lb["provenance"]["judge_predictions"] = "results/judge_predictions.jsonl"
    lb["provenance"]["novel_attacks_crewai"] = "eval/_artifacts/novel_attacks_crewai.jsonl"
    lb["provenance"]["novel_attacks_score"] = "results/novel_attacks_score.json"

    # Add novel-attack generalization probe (rule-layer-only, judge deferred to v0.2)
    if not any(e["defense"] == "toolwall_rules_only" and e.get("split") == "novel_attacks_crewai_holdout" for e in lb["entries"]):
        try:
            nv = json.loads((REPO / "results/novel_attacks_score.json").read_text())
            lb["entries"].append(
                {
                    "defense": "toolwall_rules_only",
                    "category": "generalization-probe",
                    "git_tag": "v0.1.0",
                    "judge_revision": None,
                    "asr": round(nv["asr"], 4),
                    "asr_wilson95": [round(nv["asr_wilson95"][0], 4), round(nv["asr_wilson95"][1], 4)],
                    "utility": None,
                    "n_attack": nv["n_attack"],
                    "n_benign": 0,
                    "per_family": {fam: round(info["asr"], 4) for fam, info in nv["per_family"].items()},
                    "loc": 4,
                    "note": "Rule layer ONLY against 10 CrewAI-generated novel-family attacks NOT in known 7. Judge-layer scoring on this set queued for v0.2.",
                    "ran_at": nv["ran_at"],
                    "split": "novel_attacks_crewai_holdout",
                    "submitter": "bryteai.studio",
                }
            )
        except FileNotFoundError:
            pass

    LB.write_text(json.dumps(lb, indent=2, sort_keys=False) + "\n")
    print(f"[ok] wrote {LB}")
    print(f"[ok] {len(lb['entries'])} entries")
    for e in lb["entries"]:
        ci = e.get("asr_wilson95", ["?", "?"])
        util_str = f"util={e['utility']:.4f}" if e.get("utility") is not None else "util=n/a"
        split_str = e.get("split", "in-house-200")
        print(
            f"  {e['defense']:30s} [{split_str:32s}] ASR={e['asr']:.4f} CI=[{ci[0]:.3f},{ci[1]:.3f}] {util_str}"
        )


if __name__ == "__main__":
    main()
