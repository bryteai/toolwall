"""GPU run for the external v0.2 evaluation (Modal).

Runs two detectors over every row of bench/build_artifacts/external_v0_2:
  * toolwall           — the published code path: CompositeDetector(use_judge=True)
                         with the LoRA judge in models/judge-v0.1 on Qwen2.5-7B-Instruct
  * protectai_deberta_v2 — protectai/deberta-v3-base-prompt-injection-v2 (Apache-2.0),
                           an open prompt-injection classifier used as the baseline

    modal run eval/modal_external_v0_2.py

Decisions are written to results/external_v0_2/<defense>.decisions.jsonl locally;
score them with:  python -m eval.run_external_v0_2 --defense <name> --decisions <file>
"""

from __future__ import annotations

import json
from pathlib import Path

import modal

ROOT = Path(__file__).resolve().parents[1]
app = modal.App("toolwall-external-v0-2")
hf_cache = modal.Volume.from_name("toolwall-hf-cache", create_if_missing=True)

image = (
    modal.Image.debian_slim(python_version="3.11")
    .pip_install(
        "torch==2.4.0", "transformers==4.46.0", "peft==0.13.2", "accelerate==1.0.1",
        "sentencepiece==0.2.0", "tokenizers==0.20.3", "pydantic>=2.6", "regex>=2024.5.15",
        "protobuf==5.28.3", "tiktoken==0.8.0",
    )
    .env({"HF_HOME": "/hf", "PYTHONPATH": "/repo/src:/repo", "TOKENIZERS_PARALLELISM": "false"})
    .add_local_dir(str(ROOT / "src"), remote_path="/repo/src")
    .add_local_dir(str(ROOT / "eval"), remote_path="/repo/eval", ignore=["_artifacts", "__pycache__"])
    .add_local_dir(str(ROOT / "bench" / "build_artifacts" / "external_v0_2"), remote_path="/data")
    .add_local_dir(str(ROOT / "models" / "judge-v0.1"), remote_path="/repo/models/judge-v0.1")
)

SETS = ["injecagent_base", "injecagent_enhanced", "injecagent_twin", "wiki_benign", "wiki_hardneg"]


@app.function(image=image, gpu="A10G", timeout=5400, volumes={"/hf": hf_cache})
def run_all() -> dict[str, list[dict]]:
    import os
    import time

    os.environ["TOOLWALL_JUDGE_LOCAL_PATH"] = "/repo/models/judge-v0.1"
    rows = []
    for s in SETS:
        for line in open(f"/data/{s}.jsonl", encoding="utf-8"):
            r = json.loads(line)
            r["set"] = s
            rows.append(r)

    out: dict[str, list[dict]] = {}

    # Baseline first (small model).
    from transformers import pipeline
    t0 = time.time()
    clf = pipeline("text-classification", model="protectai/deberta-v3-base-prompt-injection-v2",
                   truncation=True, max_length=512, device=0)
    preds = clf([r["tool_response"][:4000] for r in rows], batch_size=32)
    out["protectai_deberta_v2"] = [
        {"id": r["id"], "set": r["set"], "expected_block": r["expected_block"],
         "blocked": p["label"].upper() == "INJECTION", "score": float(p["score"])}
        for r, p in zip(rows, preds)
    ]
    print(f"baseline done in {time.time() - t0:.0f}s")

    # toolwall full stack, exactly as shipped.
    from eval.baselines import Toolwall
    from toolwall.detect import judge as judge_mod
    t0 = time.time()
    d = Toolwall(use_judge=True)
    res = []
    for i, r in enumerate(rows):
        dec = d.decide(r["tool_response"])
        res.append({"id": r["id"], "set": r["set"], "expected_block": r["expected_block"],
                    "blocked": bool(dec.blocked), "score": float(dec.score), "reason": dec.reason})
        if i == 0:
            print("judge source:", judge_mod._source_used, "loaded:", judge_mod._pipeline is not None)
        if i % 500 == 0:
            print(f"toolwall {i}/{len(rows)} {time.time() - t0:.0f}s")
    out["toolwall"] = res
    hf_cache.commit()
    return out


@app.local_entrypoint()
def main() -> None:
    out_dir = ROOT / "results" / "external_v0_2"
    out_dir.mkdir(parents=True, exist_ok=True)
    result = run_all.remote()
    for name, decisions in result.items():
        p = out_dir / f"{name}.decisions.jsonl"
        with open(p, "w") as f:
            for d in decisions:
                f.write(json.dumps(d) + "\n")
        print("wrote", p, len(decisions))
