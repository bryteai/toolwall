"""Run examples/role_separated/quickstart.py once on a GPU and record the outputs (benign inputs only).

Also scores the three tool outputs with toolwall's default detector (rules + judge v0.3), to show what a detector
that reads only the tool output does with the third one (data that is itself an instruction to be processed).

    MODAL_PROFILE=muhammadfsd01 modal run eval/modal_example_role_separated.py
"""
from __future__ import annotations

import json
from pathlib import Path

import modal

ROOT = Path(__file__).resolve().parents[1]
app = modal.App("toolwall-example-role-separated")
v03 = modal.Volume.from_name("toolwall-judge-v0-3")
hf_cache = modal.Volume.from_name("toolwall-hf-cache", create_if_missing=True)
image = (
    modal.Image.debian_slim(python_version="3.11")
    .pip_install("torch==2.6.0", "transformers==4.53.2", "accelerate==1.8.1", "sentencepiece==0.2.0",
                 "protobuf==5.29.3", "huggingface_hub>=0.27", "pydantic>=2.6", "regex>=2024.5.15", "numpy<2.3")
    .env({"HF_HOME": "/hf", "TOKENIZERS_PARALLELISM": "false", "PYTHONPATH": "/repo/src:/repo"})
    .add_local_dir(str(ROOT / "src"), remote_path="/repo/src", ignore=["__pycache__"])
    .add_local_dir(str(ROOT / "examples"), remote_path="/repo/examples", ignore=["__pycache__"])
)


@app.function(image=image, gpu="A10G", timeout=3600, volumes={"/v03": v03, "/hf": hf_cache},
              secrets=[modal.Secret.from_name("hf-bryteai")])
def run() -> dict:
    import os

    import torch
    from transformers import AutoModelForCausalLM, AutoTokenizer

    os.environ["TOOLWALL_JUDGE_LOCAL_PATH"] = "/v03/judge-v0.3-deberta"
    from examples.role_separated import quickstart as qs
    from toolwall.boundary import untrusted_messages
    from toolwall.detect import CompositeDetector

    det = CompositeDetector(use_judge=True)
    tok = AutoTokenizer.from_pretrained(qs.MODEL, revision=qs.REVISION)
    model = AutoModelForCausalLM.from_pretrained(qs.MODEL, revision=qs.REVISION, torch_dtype=torch.bfloat16,
                                                 device_map="cuda")
    rows = []
    for task, page in qs.TASKS:
        tool_output = qs.fetch(page)
        score, spans = det.score(tool_output)
        messages = untrusted_messages(task, tool_output)
        ids = tok.apply_chat_template(messages, add_generation_prompt=True, return_tensors="pt").to("cuda")
        out = model.generate(ids, max_new_tokens=200, do_sample=False)
        rows.append({"task": task, "tool_output": tool_output, "detector_score": round(float(score), 4),
                     "detector_blocks": bool(score >= 0.6), "detections": sorted({str(s["kind"]) for s in spans}),
                     "model_reply": tok.decode(out[0][ids.shape[1]:], skip_special_tokens=True).strip()})
    return {"model": qs.MODEL, "revision": qs.REVISION, "rows": rows}


@app.local_entrypoint()
def main() -> None:
    res = run.remote()
    out = ROOT / "results" / "v0_4_role_separated_example.json"
    out.write_text(json.dumps(res, indent=1, ensure_ascii=False))
    for r in res["rows"]:
        print(f"- {r['task']}\n  detector {r['detector_score']} (blocks={r['detector_blocks']})\n  model: {r['model_reply'][:300]}")
