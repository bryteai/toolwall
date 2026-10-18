"""Train toolwall-judge-v0.2.3 (v0.2 corpus + deepset train + Enron ham train + short benign; containers balanced across labels) and evaluate it on held-out data (Modal, one A10G).

1. Fine-tune microsoft/deberta-v3-base (MIT) as a binary classifier (benign / attack)
   on training/_corpus_v0_2/train.jsonl; select the best epoch on dev.
2. Calibrate the decision threshold on dev only: the lowest threshold whose dev
   false-positive rate on benign rows is <= 1%.
3. Evaluate on held-out sets only, with the shipped code path
   (CompositeDetector: rules + judge v0.2), and the ProtectAI baseline on the same rows.

    modal run training/modal_train_judge_v0_2.py
    modal volume get toolwall-judge-v0-2 /judge-v0.2 models/   # fetch weights
"""

from __future__ import annotations

import json
from pathlib import Path

import modal

ROOT = Path(__file__).resolve().parents[1]
app = modal.App("toolwall-judge-v0-2-3")
vol = modal.Volume.from_name("toolwall-judge-v0-2-3", create_if_missing=True)
hf_cache = modal.Volume.from_name("toolwall-hf-cache", create_if_missing=True)

image = (
    modal.Image.debian_slim(python_version="3.11")
    .pip_install(
        "torch==2.4.0", "transformers==4.46.0", "accelerate==1.0.1", "datasets==3.0.1",
        "sentencepiece==0.2.0", "tokenizers==0.20.3", "protobuf==5.28.3", "scikit-learn==1.5.2",
        "pydantic>=2.6", "regex>=2024.5.15", "peft==0.13.2", "tiktoken==0.8.0",
    )
    .env({"HF_HOME": "/hf", "PYTHONPATH": "/repo/src:/repo", "TOKENIZERS_PARALLELISM": "false"})
    .add_local_dir(str(ROOT / "src"), remote_path="/repo/src")
    .add_local_dir(str(ROOT / "eval"), remote_path="/repo/eval", ignore=["__pycache__"])
    .add_local_dir(str(ROOT / "training" / "_corpus_v0_2_3"), remote_path="/corpus")
    .add_local_dir(str(ROOT / "bench" / "build_artifacts" / "heldout_v0_2"), remote_path="/test/heldout")
    .add_local_file(str(ROOT / "bench" / "build_artifacts" / "external_v0_2" / "wiki_benign.jsonl"), "/test/wiki_benign.jsonl")
    .add_local_file(str(ROOT / "bench" / "build_artifacts" / "external_v0_2" / "wiki_hardneg.jsonl"), "/test/wiki_hardneg.jsonl")
)

BASE = "microsoft/deberta-v3-base"
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
}


@app.function(image=image, gpu="A10G", timeout=5400, volumes={"/out": vol, "/hf": hf_cache})
def train_and_eval() -> dict:
    import os
    import numpy as np
    import torch
    from datasets import Dataset
    from transformers import (AutoModelForSequenceClassification, AutoTokenizer, DataCollatorWithPadding,
                              Trainer, TrainingArguments, pipeline)

    torch.manual_seed(20261019)
    load = lambda p: [json.loads(line) for line in open(p, encoding="utf-8")]
    train, dev = load("/corpus/train.jsonl"), load("/corpus/dev.jsonl")
    tok = AutoTokenizer.from_pretrained(BASE)
    enc = lambda rows: Dataset.from_list([{"text": r["text"], "label": r["label"]} for r in rows]).map(
        lambda b: tok(b["text"], truncation=True, max_length=512), batched=True, remove_columns=["text"])
    ds_train, ds_dev = enc(train), enc(dev)
    model = AutoModelForSequenceClassification.from_pretrained(
        BASE, num_labels=2, id2label={0: "benign", 1: "attack"}, label2id={"benign": 0, "attack": 1})

    def metrics(p):
        pred = p.predictions.argmax(-1)
        y = p.label_ids
        tp = int(((pred == 1) & (y == 1)).sum()); fp = int(((pred == 1) & (y == 0)).sum()); fn = int(((pred == 0) & (y == 1)).sum())
        prec = tp / max(1, tp + fp); rec = tp / max(1, tp + fn)
        return {"f1": 2 * prec * rec / max(1e-9, prec + rec), "precision": prec, "recall": rec,
                "fpr": fp / max(1, int((y == 0).sum()))}

    args = TrainingArguments(output_dir="/tmp/run", per_device_train_batch_size=16, per_device_eval_batch_size=32,
                             learning_rate=2e-5, num_train_epochs=3, warmup_ratio=0.1, weight_decay=0.01,
                             eval_strategy="epoch", save_strategy="epoch", load_best_model_at_end=True,
                             metric_for_best_model="f1", fp16=True, logging_steps=50, report_to=[], seed=20261019)
    trainer = Trainer(model=model, args=args, train_dataset=ds_train, eval_dataset=ds_dev, tokenizer=tok,
                      data_collator=DataCollatorWithPadding(tok), compute_metrics=metrics)
    trainer.train()
    dev_metrics = trainer.evaluate()

    # Threshold calibration on dev only.
    logits = trainer.predict(ds_dev).predictions
    p_attack = torch.softmax(torch.tensor(logits), -1)[:, 1].numpy()
    y = np.array([r["label"] for r in dev])
    benign_p = np.sort(p_attack[y == 0])
    k = int(np.floor(0.01 * len(benign_p)))           # allow at most 1% of dev benign above threshold
    threshold = float(min(0.99, max(0.5, benign_p[-(k + 1)] + 1e-4))) if len(benign_p) else 0.5
    dev_at_t = {"threshold": threshold, "dev_fpr": float((p_attack[y == 0] >= threshold).mean()),
                "dev_tpr": float((p_attack[y == 1] >= threshold).mean())}

    out_dir = "/out/judge-v0.2.3"
    trainer.save_model(out_dir)
    tok.save_pretrained(out_dir)
    Path(out_dir, "toolwall_judge.json").write_text(json.dumps({
        "version": "0.2.3", "base_model": BASE, "labels": ["benign", "attack"], **dev_at_t,
        "dev_metrics_argmax": {k: float(v) for k, v in dev_metrics.items() if isinstance(v, (int, float))},
        "train_rows": len(train), "dev_rows": len(dev)}, indent=2))
    vol.commit()

    # Held-out evaluation with the shipped code path.
    os.environ["TOOLWALL_JUDGE_LOCAL_PATH"] = out_dir
    from eval.baselines import Toolwall, ToolwallRuleOnly
    from toolwall.detect import judge as judge_mod
    tw, rules = Toolwall(use_judge=True), ToolwallRuleOnly()
    base_clf = pipeline("text-classification", model="protectai/deberta-v3-base-prompt-injection-v2",
                        truncation=True, max_length=512, device=0)
    results: dict[str, list[dict]] = {"toolwall_v0_2_3": [], "toolwall_rule_only": [], "protectai_deberta_v2": []}
    for name, path in TEST_SETS.items():
        rows = load(path)
        texts = [r["tool_response"] for r in rows]
        preds = base_clf([t[:4000] for t in texts], batch_size=32)
        for r, t, pb in zip(rows, texts, preds):
            common = {"id": r["id"], "set": name, "expected_block": bool(r["expected_block"])}
            results["toolwall_v0_2_3"].append({**common, "blocked": bool(tw.decide(t).blocked)})
            results["toolwall_rule_only"].append({**common, "blocked": bool(rules.decide(t).blocked)})
            results["protectai_deberta_v2"].append({**common, "blocked": pb["label"].upper() == "INJECTION"})
    return {"calibration": dev_at_t, "dev_metrics": {k: float(v) for k, v in dev_metrics.items() if isinstance(v, (int, float))},
            "judge_source": judge_mod._source_used, "judge_kind": judge_mod._kind, "decisions": results}


@app.local_entrypoint()
def main() -> None:
    res = train_and_eval.remote()
    out = ROOT / "results" / "heldout_v0_2_3"
    out.mkdir(parents=True, exist_ok=True)
    for name, decisions in res.pop("decisions").items():
        with open(out / f"{name}.decisions.jsonl", "w") as f:
            for d in decisions:
                f.write(json.dumps(d) + "\n")
    (out / "training_run.json").write_text(json.dumps(res, indent=2))
    print(json.dumps(res, indent=2))
