"""Evaluate the frozen v0.2 judge with the released code on every held-out set (Modal).

This is the run the README reports. It uses:
  * the code in src/ as released (v0.2.0, which includes the v0.1.1 rule changes);
  * the frozen judge weights (model.safetensors sha256 34dc0cc9...68fe, checked below);
  * the held-out sets listed in TEST_SETS, plus the one-shot BIPIA final set.
No training, no threshold change, no model choice happens here.

    MODAL_PROFILE=<profile> modal run eval/modal_eval_v0_2.py
"""

from __future__ import annotations

import json
from pathlib import Path

import modal

ROOT = Path(__file__).resolve().parents[1]
JUDGE_SHA256 = "34dc0cc929250b61ee2bc24f901ba31da87c38f923f7623bfe31924a796768fe"
app = modal.App("toolwall-eval-v0-2")
vol = modal.Volume.from_name("toolwall-judge-v0-2-3")
hf_cache = modal.Volume.from_name("toolwall-hf-cache", create_if_missing=True)

image = (
    modal.Image.debian_slim(python_version="3.11")
    .pip_install(
        "torch==2.4.0", "transformers==4.46.0", "sentencepiece==0.2.0", "tokenizers==0.20.3",
        "protobuf==5.28.3", "pydantic>=2.6", "regex>=2024.5.15", "tiktoken==0.8.0",
    )
    .env({"HF_HOME": "/hf", "PYTHONPATH": "/repo/src:/repo", "TOKENIZERS_PARALLELISM": "false"})
    .add_local_dir(str(ROOT / "src"), remote_path="/repo/src", ignore=["__pycache__"])
    .add_local_dir(str(ROOT / "eval"), remote_path="/repo/eval", ignore=["__pycache__"])
    .add_local_dir(str(ROOT / "bench" / "build_artifacts" / "heldout_v0_2"), remote_path="/test/heldout")
    .add_local_file(str(ROOT / "bench" / "build_artifacts" / "external_v0_2" / "wiki_benign.jsonl"), "/test/wiki_benign.jsonl")
    .add_local_file(str(ROOT / "bench" / "build_artifacts" / "external_v0_2" / "wiki_hardneg.jsonl"), "/test/wiki_hardneg.jsonl")
    .add_local_file(str(ROOT / "bench" / "build_artifacts" / "final_bipia_v0_2.jsonl"), "/test/final_bipia.jsonl")
)

TEST_SETS = {
    "ia_test_base": "/test/heldout/ia_test_base.jsonl",
    "ia_test_enhanced": "/test/heldout/ia_test_enhanced.jsonl",
    "ia_test_twin": "/test/heldout/ia_test_twin.jsonl",
    "wiki_benign": "/test/wiki_benign.jsonl",
    "wiki_hardneg": "/test/wiki_hardneg.jsonl",
    "inhouse_200": "/repo/eval/_artifacts/attacks.jsonl",
    "novel_10": "/repo/eval/_artifacts/novel_attacks_crewai.jsonl",
    "deepset_test": "/test/heldout/deepset_test.jsonl",
    "gandalf_test": "/test/heldout/gandalf_test.jsonl",
    "enron_requests": "/test/heldout/enron_requests.jsonl",
    "short_benign_test": "/test/heldout/short_benign_test.jsonl",
    "short_probe": "/test/heldout/short_probe.jsonl",
    "final_bipia": "/test/final_bipia.jsonl",
}


@app.function(image=image, gpu="A10G", cpu=8, timeout=5400, volumes={"/w": vol, "/hf": hf_cache})
def evaluate() -> dict:
    import hashlib
    import os

    from transformers import pipeline

    path = "/w/judge-v0.2.3"
    h = hashlib.sha256()
    with open(f"{path}/model.safetensors", "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    assert h.hexdigest() == JUDGE_SHA256, h.hexdigest()
    os.environ["TOOLWALL_JUDGE_LOCAL_PATH"] = path

    import toolwall
    from eval.baselines import Toolwall, ToolwallRuleOnly
    from toolwall.detect import judge as judge_mod

    load = lambda p: [json.loads(line) for line in open(p, encoding="utf-8")]
    tw, rules = Toolwall(use_judge=True), ToolwallRuleOnly()
    base_clf = pipeline("text-classification", model="protectai/deberta-v3-base-prompt-injection-v2",
                        truncation=True, max_length=512, device=0)
    results: dict[str, list[dict]] = {"toolwall_v0_2": [], "toolwall_rule_only": [], "protectai_deberta_v2": []}
    for name, p in TEST_SETS.items():
        rows = load(p)
        texts = [r["tool_response"] for r in rows]
        preds = base_clf([t[:4000] for t in texts], batch_size=32)
        for r, t, pb in zip(rows, texts, preds):
            common = {"id": r["id"], "set": name, "expected_block": bool(r["expected_block"])}
            if "task" in r:
                common["task"] = r["task"]
            results["toolwall_v0_2"].append({**common, "blocked": bool(tw.decide(t).blocked)})
            results["toolwall_rule_only"].append({**common, "blocked": bool(rules.decide(t).blocked)})
            results["protectai_deberta_v2"].append({**common, "blocked": pb["label"].upper() == "INJECTION"})
        print(name, len(rows), flush=True)
    return {"toolwall_version": toolwall.__version__, "judge_sha256": h.hexdigest(),
            "judge_source": judge_mod._source_used, "judge_kind": judge_mod._kind,
            "judge_threshold": judge_mod._threshold, "decisions": results}


@app.local_entrypoint()
def main() -> None:
    res = evaluate.remote()
    out = ROOT / "results" / "v0_2"
    out.mkdir(parents=True, exist_ok=True)
    for name, decisions in res.pop("decisions").items():
        with open(out / f"{name}.decisions.jsonl", "w") as f:
            for d in decisions:
                f.write(json.dumps(d) + "\n")
    (out / "run.json").write_text(json.dumps(res, indent=2))
    print(json.dumps(res, indent=2))
