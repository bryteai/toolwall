"""Modal training entrypoint for ``toolwall-judge-v0.1``.

Run::

    modal run training/train_judge.py

What it does:

1. Uploads the local 4000-pair training corpus to a Modal volume.
2. Spins an A10G container with torch/transformers/peft/bitsandbytes.
3. Loads ``Qwen/Qwen2.5-7B-Instruct`` (Apache-2.0; substituted for the
   gated Llama-3.1-8B-Instruct --- rationale documented in the model
   card).
4. Adds a sequence-classification head (3 labels: attack/suspicious/benign).
5. LoRA r=16, alpha=32, dropout 0.05, target q_proj/v_proj.
6. 4-bit base quantization via bitsandbytes (so 7B + LoRA fits on A10G).
7. Trains 3 epochs on 3600 examples; evaluates on a 400-example dev split.
8. Reports accuracy + per-class F1; refuses to mark "shippable" unless
   accuracy ≥ 0.92 AND attack-F1 ≥ 0.85 (spec targets).
9. Saves the LoRA adapter to a Modal volume; download with
   ``modal volume get toolwall-judge-v0.1 /adapter /tmp/judge``.

The training corpus lives at ``training/_corpus/train_v0_1.jsonl``
and is built by ``python -m training.build_corpus``. The corpus is
disjoint from the published test split --- enforced inside
``training.build_corpus`` (refuses to write a contaminated corpus).
"""

from __future__ import annotations

import modal

app = modal.App("toolwall-judge-train")

# --- Modal image -----------------------------------------------------------
# Pinned versions chosen for compatibility on A10G (CUDA 12.1, sm_86).
image = (
    modal.Image.debian_slim(python_version="3.11")
    .pip_install(
        "torch==2.4.0",
        "transformers==4.46.0",
        "peft==0.13.2",
        "bitsandbytes==0.44.1",
        "accelerate==1.0.1",
        "datasets==3.0.1",
        "scikit-learn==1.5.2",
        "sentencepiece==0.2.0",
        "tiktoken==0.8.0",
        "tokenizers==0.20.3",
    )
    .add_local_dir("training/_corpus", remote_path="/corpus")
)

# Modal volume that persists the trained adapter across runs.
adapter_volume = modal.Volume.from_name("toolwall-judge-v0_1", create_if_missing=True)


@app.function(
    image=image,
    gpu="A10G",
    timeout=7200,  # 2 hr budget; spec says 30-45 min for 3 epochs on A10
    volumes={"/adapter": adapter_volume},
)
def train() -> dict[str, float]:
    """Fine-tune Qwen2.5-7B-Instruct as a 3-class IPI judge.

    Returns the dev-set metrics. The caller decides shippability based on
    the spec thresholds: accuracy ≥ 0.92 AND attack-class F1 ≥ 0.85.
    """
    import json
    import random
    from pathlib import Path

    import numpy as np
    import torch
    from datasets import Dataset
    from peft import LoraConfig, TaskType, get_peft_model, prepare_model_for_kbit_training
    from sklearn.metrics import accuracy_score, classification_report, f1_score
    from transformers import (
        AutoModelForSequenceClassification,
        AutoTokenizer,
        BitsAndBytesConfig,
        DataCollatorWithPadding,
        Trainer,
        TrainingArguments,
    )

    BASE_MODEL = "Qwen/Qwen2.5-7B-Instruct"
    LABELS = ["benign", "suspicious", "attack"]
    LABEL2ID = {lbl: i for i, lbl in enumerate(LABELS)}
    ID2LABEL = {i: lbl for lbl, i in LABEL2ID.items()}
    MAX_LEN = 512
    DEV_SIZE = 400
    SEED = 20260524

    # --- Load corpus -------------------------------------------------------
    corpus_path = Path("/corpus/train_v0_1.jsonl")
    records: list[dict[str, str]] = []
    with corpus_path.open("r", encoding="utf-8") as f:
        for raw in f:
            records.append(json.loads(raw))
    if len(records) != 4000:
        raise RuntimeError(f"expected 4000 corpus records, got {len(records)}")

    # Deterministic dev split: stratified-ish (proportional per class).
    rng = random.Random(SEED)
    by_label: dict[str, list[dict[str, str]]] = {lbl: [] for lbl in LABELS}
    for r in records:
        by_label[r["label"]].append(r)
    for v in by_label.values():
        rng.shuffle(v)
    dev: list[dict[str, str]] = []
    train_recs: list[dict[str, str]] = []
    per_class_dev = DEV_SIZE // len(LABELS)
    for lbl in LABELS:
        bucket = by_label[lbl]
        dev.extend(bucket[:per_class_dev])
        train_recs.extend(bucket[per_class_dev:])
    # Top up dev to exactly DEV_SIZE from the benign pool (largest class).
    while len(dev) < DEV_SIZE:
        dev.append(train_recs.pop())
    rng.shuffle(train_recs)
    rng.shuffle(dev)
    print(f"train: {len(train_recs)}  dev: {len(dev)}")

    def _to_ds(rs: list[dict[str, str]]) -> Dataset:
        return Dataset.from_list([{"text": r["text"], "label": LABEL2ID[r["label"]]} for r in rs])

    ds_train = _to_ds(train_recs)
    ds_dev = _to_ds(dev)

    # --- Tokenizer + base model (4-bit) ------------------------------------
    print(f"loading tokenizer + base model: {BASE_MODEL}")
    tokenizer = AutoTokenizer.from_pretrained(BASE_MODEL)
    if tokenizer.pad_token_id is None:
        tokenizer.pad_token = tokenizer.eos_token

    bnb = BitsAndBytesConfig(
        load_in_4bit=True,
        bnb_4bit_quant_type="nf4",
        bnb_4bit_compute_dtype=torch.float16,
        bnb_4bit_use_double_quant=True,
    )

    model = AutoModelForSequenceClassification.from_pretrained(
        BASE_MODEL,
        num_labels=len(LABELS),
        id2label=ID2LABEL,
        label2id=LABEL2ID,
        quantization_config=bnb,
        torch_dtype=torch.float16,
        device_map="auto",
    )
    model.config.pad_token_id = tokenizer.pad_token_id
    model = prepare_model_for_kbit_training(model)

    lora = LoraConfig(
        r=16,
        lora_alpha=32,
        lora_dropout=0.05,
        bias="none",
        task_type=TaskType.SEQ_CLS,
        target_modules=["q_proj", "v_proj"],
    )
    model = get_peft_model(model, lora)
    model.print_trainable_parameters()

    # --- Tokenize ----------------------------------------------------------
    def tok(batch: dict[str, list]) -> dict[str, list]:
        return tokenizer(batch["text"], truncation=True, max_length=MAX_LEN, padding=False)

    ds_train_tok = ds_train.map(tok, batched=True, remove_columns=["text"])
    ds_dev_tok = ds_dev.map(tok, batched=True, remove_columns=["text"])

    # --- Metrics -----------------------------------------------------------
    def compute_metrics(pred) -> dict[str, float]:  # type: ignore[no-untyped-def]
        logits, labels = pred
        preds = np.argmax(logits, axis=-1)
        macro_f1 = f1_score(labels, preds, average="macro")
        attack_f1 = f1_score(labels, preds, labels=[LABEL2ID["attack"]], average="macro")
        return {
            "accuracy": accuracy_score(labels, preds),
            "macro_f1": float(macro_f1),
            "attack_f1": float(attack_f1),
        }

    # --- Train -------------------------------------------------------------
    out_dir = "/adapter/run"
    args = TrainingArguments(
        output_dir=out_dir,
        num_train_epochs=3,
        per_device_train_batch_size=8,
        per_device_eval_batch_size=16,
        gradient_accumulation_steps=4,
        learning_rate=2e-4,
        warmup_ratio=0.03,
        lr_scheduler_type="cosine",
        logging_steps=20,
        eval_strategy="epoch",
        save_strategy="epoch",
        save_total_limit=1,
        fp16=True,
        report_to=[],
        load_best_model_at_end=True,
        metric_for_best_model="macro_f1",
        greater_is_better=True,
        seed=SEED,
    )

    trainer = Trainer(
        model=model,
        args=args,
        train_dataset=ds_train_tok,
        eval_dataset=ds_dev_tok,
        tokenizer=tokenizer,
        data_collator=DataCollatorWithPadding(tokenizer=tokenizer, padding="longest"),
        compute_metrics=compute_metrics,
    )

    trainer.train()
    metrics = trainer.evaluate()
    print("=== dev metrics ===")
    for k, v in metrics.items():
        print(f"  {k}: {v}")

    # Full per-class report for the model card.
    preds_full = trainer.predict(ds_dev_tok)
    preds_idx = np.argmax(preds_full.predictions, axis=-1).tolist()
    labels_idx = preds_full.label_ids.tolist()
    report = classification_report(
        labels_idx,
        preds_idx,
        target_names=LABELS,
        digits=4,
        output_dict=True,
        zero_division=0,
    )
    print("=== classification report ===")
    print(json.dumps(report, indent=2))

    # --- Save adapter ------------------------------------------------------
    adapter_dir = Path("/adapter/judge-v0.1")
    adapter_dir.mkdir(parents=True, exist_ok=True)
    model.save_pretrained(adapter_dir)
    tokenizer.save_pretrained(adapter_dir)

    summary = {
        "base_model": BASE_MODEL,
        "labels": LABELS,
        "dev_size": DEV_SIZE,
        "metrics": {
            "accuracy": float(metrics.get("eval_accuracy", 0.0)),
            "macro_f1": float(metrics.get("eval_macro_f1", 0.0)),
            "attack_f1": float(metrics.get("eval_attack_f1", 0.0)),
            "eval_loss": float(metrics.get("eval_loss", 0.0)),
        },
        "classification_report": report,
        "spec_thresholds": {"accuracy": 0.92, "attack_f1": 0.85},
        "shippable": (
            float(metrics.get("eval_accuracy", 0.0)) >= 0.92
            and float(metrics.get("eval_attack_f1", 0.0)) >= 0.85
        ),
    }
    (adapter_dir / "training_summary.json").write_text(
        json.dumps(summary, indent=2, sort_keys=True) + "\n"
    )
    adapter_volume.commit()
    print(f"adapter saved to {adapter_dir}")
    return summary["metrics"]  # type: ignore[return-value]


@app.local_entrypoint()
def main() -> None:
    """Kick off training and print metrics."""
    metrics = train.remote()
    print("=== final dev metrics ===")
    for k, v in metrics.items():
        print(f"  {k}: {v:.4f}")
