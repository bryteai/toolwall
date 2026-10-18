"""Final, one-shot test on BIPIA (Microsoft, MIT; commit a004b69). Run once after the judge
was frozen (models/judge-v0.2.3, sha256 prefix 34dc0cc929250b61); not used for any choice.

    python -m eval.run_final_bipia_v0_2
"""
from __future__ import annotations
import json, os
from pathlib import Path
from eval.run_external_v0_2 import wilson

ROOT = Path(__file__).resolve().parents[1]
rows = [json.loads(l) for l in open(ROOT / "bench" / "build_artifacts" / "final_bipia_v0_2.jsonl", encoding="utf-8")]
os.environ.setdefault("TOOLWALL_JUDGE_LOCAL_PATH", str(ROOT / "models" / "judge-v0.2.3"))
from eval.baselines import Toolwall, ToolwallRuleOnly  # noqa: E402
from toolwall.detect import judge  # noqa: E402
from transformers import pipeline  # noqa: E402
tw, ro = Toolwall(use_judge=True), ToolwallRuleOnly()
pg = pipeline("text-classification", model="protectai/deberta-v3-base-prompt-injection-v2", truncation=True, max_length=512)
defs = {"toolwall_v0_2": lambda t: tw.decide(t).blocked, "toolwall_rule_only": lambda t: ro.decide(t).blocked,
        "protectai_deberta_v2": lambda t: pg(t[:4000])[0]["label"].upper() == "INJECTION"}
out = {}
for name, f in defs.items():
    dec = [{**{k: r[k] for k in ("id", "expected_block", "task")}, "blocked": bool(f(r["tool_response"]))} for r in rows]
    (ROOT / "results" / "final_bipia_v0_2").mkdir(parents=True, exist_ok=True)
    (ROOT / "results" / "final_bipia_v0_2" / f"{name}.decisions.jsonl").write_text("".join(json.dumps(x) + "\n" for x in dec))
    for task in ("email", "table", "all"):
        rs = [d for d in dec if task == "all" or d["task"] == task]
        att = [d for d in rs if d["expected_block"]]; ben = [d for d in rs if not d["expected_block"]]
        a = wilson(sum(not d["blocked"] for d in att), len(att)); b = wilson(sum(d["blocked"] for d in ben), len(ben))
        out.setdefault(name, {})[task] = {"n_attack": len(att), "ASR": a, "n_benign": len(ben), "FPR": b}
        print(f"{name:22} {task:6} ASR {a[0]:.3f} [{a[1]:.3f},{a[2]:.3f}] n={len(att)} | FPR {b[0]:.3f} [{b[1]:.3f},{b[2]:.3f}] n={len(ben)}")
print("judge used:", judge._source_used, judge._kind)
(ROOT / "results" / "final_bipia_v0_2" / "summary.json").write_text(json.dumps(out, indent=2))
