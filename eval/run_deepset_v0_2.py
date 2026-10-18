"""Out-of-distribution test: deepset/prompt-injections (Apache-2.0), test split (116 rows,
60 injections, English and German), each text placed inside a web-fetch tool response.

    python -m eval.run_deepset_v0_2 --defense toolwall_v0_2|toolwall_rule_only|protectai_deberta_v2
"""
from __future__ import annotations
import argparse, json, os
from pathlib import Path
from eval.run_external_v0_2 import wilson

ROOT = Path(__file__).resolve().parents[1]
CACHE = ROOT / "bench" / "loaders" / "_upstream" / "deepset_pi_test.json"
FILE = "data/test-00000-of-00001-701d16158af87368.parquet"

def rows() -> list[dict]:
    if not CACHE.exists():
        import pyarrow.parquet as pq
        from huggingface_hub import hf_hub_download
        CACHE.write_text(json.dumps(pq.read_table(hf_hub_download("deepset/prompt-injections", FILE, repo_type="dataset")).to_pylist()))
    data = json.loads(CACHE.read_text())
    return [{"id": f"deepset-test-{i:03d}", "expected_block": bool(r["label"]),
             "tool_response": json.dumps({"url": "https://example.org/page", "title": "Page", "content": r["text"]}, ensure_ascii=False)}
            for i, r in enumerate(data)]

def main() -> None:
    ap = argparse.ArgumentParser(); ap.add_argument("--defense", required=True); a = ap.parse_args()
    if a.defense == "toolwall_rule_only":
        os.environ["TOOLWALL_DISABLE_JUDGE"] = "1"
        from eval.baselines import ToolwallRuleOnly; d = ToolwallRuleOnly(); f = lambda t: d.decide(t).blocked
    elif a.defense == "toolwall_v0_2":
        os.environ.setdefault("TOOLWALL_JUDGE_LOCAL_PATH", str(ROOT / "models" / "judge-v0.2"))
        from eval.baselines import Toolwall; d = Toolwall(use_judge=True); f = lambda t: d.decide(t).blocked
    else:
        from transformers import pipeline
        clf = pipeline("text-classification", model="protectai/deberta-v3-base-prompt-injection-v2", truncation=True, max_length=512)
        f = lambda t: clf(t[:4000])[0]["label"].upper() == "INJECTION"
    rs = rows()
    dec = [{"id": r["id"], "set": "deepset_test", "expected_block": r["expected_block"], "blocked": bool(f(r["tool_response"]))} for r in rs]
    (ROOT / "results" / "heldout_v0_2" / f"{a.defense}.deepset.decisions.jsonl").write_text("".join(json.dumps(x) + "\n" for x in dec))
    att = [x for x in dec if x["expected_block"]]; ben = [x for x in dec if not x["expected_block"]]
    v, lo, hi = wilson(sum(not x["blocked"] for x in att), len(att)); w, lo2, hi2 = wilson(sum(x["blocked"] for x in ben), len(ben))
    print(f"{a.defense:22} deepset n_att={len(att)} ASR {v:.3f} [{lo:.3f}, {hi:.3f}] | n_ben={len(ben)} FPR {w:.3f} [{lo2:.3f}, {hi2:.3f}]")

if __name__ == "__main__":
    main()
