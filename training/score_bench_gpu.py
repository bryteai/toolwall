"""Run the trained judge over the bench test split on a GPU host.

Why this exists: the LoRA adapter was trained on a single A10G-class
GPU; pulling the 7-B base + adapter down to a CPU laptop for 200
inferences would take 2-3 hours. Instead, we mount the bench test
JSONL to the same container image we trained on, load the adapter
from the persistent volume, score every case once, and write a tiny
predictions JSONL back.

The local eval pipeline then merges those predictions with the
rule-layer detector output via :mod:`eval.judge_cache` (a thin
``CompositeDetector`` extension that reads the cached predictions
instead of materialising the model).

Run on the operator's GPU container platform of choice. On an
A10G-class GPU, scoring 200 records takes a few minutes.
"""

from __future__ import annotations

import modal

app = modal.App("toolwall-judge-bench-score")

image = (
    modal.Image.debian_slim(python_version="3.11")
    .pip_install(
        "torch==2.4.0",
        "transformers==4.46.0",
        "peft==0.13.2",
        "bitsandbytes==0.44.1",
        "accelerate==1.0.1",
        "sentencepiece==0.2.0",
        "tokenizers==0.20.3",
    )
    .add_local_dir(
        "bench/build_artifacts/v0_1_inhouse",
        remote_path="/bench",
    )
)

adapter_volume = modal.Volume.from_name("toolwall-judge-v0_1", create_if_missing=False)


@app.function(
    image=image,
    gpu="A10G",
    timeout=900,
    volumes={"/adapter": adapter_volume},
)
def score_bench() -> list[dict[str, object]]:
    """Score every bench test case through the trained judge."""
    import json
    from pathlib import Path

    import torch
    from peft import PeftModel
    from transformers import (
        AutoModelForSequenceClassification,
        AutoTokenizer,
    )

    BASE_MODEL = "Qwen/Qwen2.5-7B-Instruct"
    ADAPTER_DIR = "/adapter/judge-v0.1"
    LABELS = ["benign", "suspicious", "attack"]
    MAX_LEN = 512

    print(f"loading tokenizer + base model: {BASE_MODEL}")
    tokenizer = AutoTokenizer.from_pretrained(ADAPTER_DIR)
    if tokenizer.pad_token_id is None:
        tokenizer.pad_token = tokenizer.eos_token

    base = AutoModelForSequenceClassification.from_pretrained(
        BASE_MODEL,
        num_labels=len(LABELS),
        torch_dtype=torch.float16,
        device_map="auto",
    )
    base.config.pad_token_id = tokenizer.pad_token_id
    model = PeftModel.from_pretrained(base, ADAPTER_DIR)
    model.eval()
    device = next(model.parameters()).device
    print(f"model on device {device}")

    cases: list[dict[str, object]] = []
    with Path("/bench/test.jsonl").open("r", encoding="utf-8") as f:
        for raw in f:
            cases.append(json.loads(raw))
    print(f"loaded {len(cases)} bench cases")

    out: list[dict[str, object]] = []
    with torch.no_grad():
        for i, case in enumerate(cases):
            text = str(case.get("tool_response", ""))[:4_000]
            enc = tokenizer(
                text,
                truncation=True,
                max_length=MAX_LEN,
                return_tensors="pt",
                padding=False,
            ).to(device)
            logits = model(**enc).logits[0]
            probs = torch.softmax(logits.float(), dim=-1).cpu().tolist()
            pred_idx = int(torch.argmax(logits).item())
            out.append(
                {
                    "id": case["id"],
                    "attack_kind": case.get("attack_kind"),
                    "expected_block": case.get("expected_block"),
                    "judge_label": LABELS[pred_idx],
                    "judge_score": float(probs[pred_idx]),
                    "probs": {LABELS[k]: float(probs[k]) for k in range(3)},
                }
            )
            if (i + 1) % 20 == 0:
                print(f"  scored {i + 1}/{len(cases)}")

    print(f"done. {len(out)} predictions.")
    return out


@app.local_entrypoint()
def main() -> None:
    """Pull predictions back and write to results/judge_predictions.jsonl."""
    import json
    from pathlib import Path

    preds = score_bench.remote()
    out_path = Path("results/judge_predictions.jsonl")
    out_path.parent.mkdir(parents=True, exist_ok=True)
    with out_path.open("w", encoding="utf-8") as f:
        for p in preds:
            f.write(json.dumps(p, sort_keys=True) + "\n")
    print(f"wrote {len(preds)} predictions to {out_path}")
    counts: dict[str, int] = {}
    for p in preds:
        lbl = str(p["judge_label"])
        counts[lbl] = counts.get(lbl, 0) + 1
    print(f"label distribution: {counts}")
