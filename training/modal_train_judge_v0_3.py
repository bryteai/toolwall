"""Train toolwall-judge-v0.3 candidates on Modal: task-aware, windowed, span-labelled.

Each training row is (user task, tool output, label, attack character span). The tool output is cut into token
windows; a window is positive only if it contains the attack span, so the model must find the injected text instead
of judging the whole document by its length or genre. At inference the document score is the maximum window score.

Two backbones are trained with the same data and compared on dev only:
    deberta  microsoft/deberta-v3-base   windows of 512 tokens (incl. task), stride 256
    modern   answerdotai/ModernBERT-base windows of 1024 tokens (incl. task), stride 512

Dev evaluation (never the final tests): dev split of the v0.3 corpus, and the robustness probe used on v0.2
(80 held-out InjecAgent attacks + 80 benign twins; formatting, MCP wrapper, 1,000 benign characters before/after).

    MODAL_PROFILE=muhammadfsd01 modal run training/modal_train_judge_v0_3.py --backbones deberta,modern
"""
from __future__ import annotations

import json
from pathlib import Path

import modal

ROOT = Path(__file__).resolve().parents[1]
app = modal.App("toolwall-judge-v0-3")
vol = modal.Volume.from_name("toolwall-judge-v0-3", create_if_missing=True)
hf_cache = modal.Volume.from_name("toolwall-hf-cache", create_if_missing=True)
image = (
    modal.Image.debian_slim(python_version="3.11")
    .pip_install("torch==2.6.0", "transformers==4.53.2", "accelerate==1.8.1", "sentencepiece==0.2.0",
                 "protobuf==5.29.3", "scikit-learn==1.6.1", "numpy<2.3")
    .env({"HF_HOME": "/hf", "TOKENIZERS_PARALLELISM": "false", "LANG": "C.UTF-8", "LC_ALL": "C.UTF-8", "PYTHONUTF8": "1"})
    .add_local_dir(str(ROOT / "training" / "_corpus_v0_3"), remote_path="/corpus")
    .add_local_dir(str(ROOT / "bench" / "build_artifacts" / "heldout_v0_2"), remote_path="/probe")
    .add_local_file(str(ROOT / "bench" / "build_artifacts" / "external_v0_2" / "wiki_benign.jsonl"), "/probe/wiki_benign.jsonl")
)
CFG = {
    "deberta": {"base": "microsoft/deberta-v3-base", "max_len": 512, "stride": 256, "lr": 2e-5, "bs": 16, "epochs": 2},
    "modern": {"base": "answerdotai/ModernBERT-base", "max_len": 1024, "stride": 512, "lr": 4e-5, "bs": 8, "epochs": 2},
    "small": {"base": "microsoft/deberta-v3-small", "max_len": 512, "stride": 256, "lr": 4e-5, "bs": 16, "epochs": 3},
    "xsmall": {"base": "microsoft/deberta-v3-xsmall", "max_len": 512, "stride": 256, "lr": 6e-5, "bs": 16, "epochs": 3},
}
SEED = 20261020
TASK_MAX = 64


def make_windows(tok, task: str, text: str, max_len: int, stride: int) -> list[dict]:
    task_ids = tok(task, add_special_tokens=False)["input_ids"][:TASK_MAX] if task else []
    enc = tok(text, add_special_tokens=False, return_offsets_mapping=True)
    ids, offs = enc["input_ids"], enc["offset_mapping"]
    room = max_len - len(task_ids) - (4 if task_ids else 2)
    step = max(1, min(stride, room))
    out, start = [], 0
    while True:
        end = min(len(ids), start + room)
        piece = ids[start:end]
        model_in = tok.prepare_for_model(task_ids, piece, add_special_tokens=True, truncation=False) if task_ids \
            else tok.prepare_for_model(piece, add_special_tokens=True, truncation=False)
        lo = offs[start][0] if piece else 0
        hi = offs[end - 1][1] if piece else 0
        out.append({"input_ids": model_in["input_ids"], "chars": (lo, hi)})
        if end >= len(ids):
            break
        start += step
    return out


def window_label(chars: tuple[int, int], span: list[int] | None) -> int | None:
    if not span:
        return 0
    ov = max(0, min(chars[1], span[1]) - max(chars[0], span[0]))
    need = min(0.6 * (span[1] - span[0]), 300)
    if ov >= need:
        return 1
    return None if ov > 0 else 0


@app.function(image=image, gpu="A10G", timeout=6 * 3600, volumes={"/out": vol, "/hf": hf_cache})
def train_one(name: str, smoke: bool = False) -> dict:
    import random
    import time

    import numpy as np
    import torch
    from sklearn.metrics import roc_auc_score
    from transformers import AutoModelForSequenceClassification, AutoTokenizer, get_linear_schedule_with_warmup

    cfg = CFG[name]
    rng = random.Random(SEED)
    torch.manual_seed(SEED)
    tok = AutoTokenizer.from_pretrained(cfg["base"])
    load = lambda p: [json.loads(line) for line in open(p, encoding="utf-8")]
    train, dev = load("/corpus/train.jsonl"), load("/corpus/dev.jsonl")
    if smoke:
        train, dev = train[:300], dev[:120]
        cfg = {**cfg, "epochs": 1}

    examples = []
    for r in train:
        ws = make_windows(tok, r["task"], r["text"], cfg["max_len"], cfg["stride"])
        labelled = [(w, window_label(w["chars"], r["span"])) for w in ws]
        pos = [w for w, lab in labelled if lab == 1]
        neg = [w for w, lab in labelled if lab == 0]
        keep = pos + rng.sample(neg, min(len(neg), 2 if pos else 3))
        for w in keep:
            examples.append((w["input_ids"], 1 if w in pos else 0))
    rng.shuffle(examples)
    n_pos = sum(lab for _, lab in examples)

    def collate(batch):
        m = max(len(x) for x, _ in batch)
        ids = torch.full((len(batch), m), tok.pad_token_id)
        att = torch.zeros((len(batch), m), dtype=torch.long)
        for i, (x, _) in enumerate(batch):
            ids[i, :len(x)] = torch.tensor(x); att[i, :len(x)] = 1
        return ids, att, torch.tensor([lab for _, lab in batch])

    model = AutoModelForSequenceClassification.from_pretrained(cfg["base"], num_labels=2,
                                                               id2label={0: "benign", 1: "attack"},
                                                               label2id={"benign": 0, "attack": 1}).cuda()
    # length-bucketed batches keep padding small
    examples.sort(key=lambda e: len(e[0]))
    batches = [examples[i:i + cfg["bs"]] for i in range(0, len(examples), cfg["bs"])]
    opt = torch.optim.AdamW(model.parameters(), lr=cfg["lr"], weight_decay=0.01)
    total = len(batches) * cfg["epochs"]
    sched = get_linear_schedule_with_warmup(opt, int(0.06 * total), total)
    scaler_dtype = torch.bfloat16

    @torch.no_grad()
    def score_docs(rows: list[dict]) -> np.ndarray:
        model.eval()
        scores = []
        for r in rows:
            ws = make_windows(tok, r.get("task", ""), r["text"], cfg["max_len"], cfg["stride"])
            best = 0.0
            for i in range(0, len(ws), 16):
                ids, att, _ = collate([(w["input_ids"], 0) for w in ws[i:i + 16]])
                with torch.autocast("cuda", dtype=scaler_dtype):
                    p = torch.softmax(model(input_ids=ids.cuda(), attention_mask=att.cuda()).logits.float(), -1)[:, 1]
                best = max(best, float(p.max()))
            scores.append(best)
        model.train()
        return np.array(scores)

    def dev_report(scores: np.ndarray) -> dict:
        y = np.array([r["label"] for r in dev])
        benign = np.sort(scores[y == 0])
        k = int(np.floor(0.01 * len(benign)))
        thr = float(max(0.5, benign[-(k + 1)] + 1e-4)) if len(benign) else 0.5
        by_src = {}
        for src in sorted({r["src"] for r in dev}):
            idx = [i for i, r in enumerate(dev) if r["src"] == src]
            ys = y[idx]; ss = scores[idx]
            by_src[src] = {"n": len(idx), "flagged": int((ss >= thr).sum()), "label": int(ys.mean() > 0.5)}
        return {"auroc": float(roc_auc_score(y, scores)), "threshold_at_1pct_fpr": thr,
                "tpr": float((scores[y == 1] >= thr).mean()), "fpr": float((scores[y == 0] >= thr).mean()), "by_src": by_src}

    log = []
    best, best_state = -1.0, None
    t0 = time.time()
    model.train()
    for ep in range(cfg["epochs"]):
        order = list(range(len(batches)))
        rng.shuffle(order)
        for step, bi in enumerate(order):
            ids, att, lab = collate(batches[bi])
            with torch.autocast("cuda", dtype=scaler_dtype):
                out = model(input_ids=ids.cuda(), attention_mask=att.cuda(), labels=lab.cuda())
            out.loss.backward()
            torch.nn.utils.clip_grad_norm_(model.parameters(), 1.0)
            opt.step(); sched.step(); opt.zero_grad()
            if step % 200 == 0:
                log.append({"epoch": ep, "step": step, "loss": float(out.loss), "min": round((time.time() - t0) / 60, 1)})
        rep = dev_report(score_docs(dev))
        rep["epoch"] = ep
        log.append(rep)
        if rep["tpr"] - rep["fpr"] > best:
            best = rep["tpr"] - rep["fpr"]
            best_state = {k: v.detach().cpu().clone() for k, v in model.state_dict().items()}
            best_rep = rep
    model.load_state_dict(best_state)

    out_dir = f"/out/judge-v0.3-{name}" + ("-smoke" if smoke else "")
    model.save_pretrained(out_dir)
    tok.save_pretrained(out_dir)
    Path(out_dir, "dev_report.json").write_text(json.dumps({"dev": best_rep, "log": log}, indent=1))
    vol.commit()

    # Robustness probe (same rows and transforms as the v0.2 probe)
    import ast
    def rows_of(path, positive):
        rs = [json.loads(line)["tool_response"] for line in open(path, encoding="utf-8") if bool(json.loads(line).get("expected_block")) == positive]
        random.Random(11).shuffle(rs)
        return rs[:8] if smoke else rs[:80]
    atk = rows_of("/probe/ia_test_base.jsonl", True)
    ben = rows_of("/probe/ia_test_twin.jsonl", False)
    pad = " ".join(json.loads(line)["tool_response"] for line in open("/probe/wiki_benign.jsonl", encoding="utf-8"))[:1000]
    def obj(t):
        for f in (ast.literal_eval, json.loads):
            try:
                return f(t)
            except Exception:
                pass
    V = {"original": lambda t: t,
         "indented JSON": lambda t: json.dumps(obj(t), indent=2) if obj(t) is not None else t,
         "MCP content block": lambda t: json.dumps({"content": [{"type": "text", "text": t}], "isError": False}),
         "+1000 chars before": lambda t: pad + "\n\n" + t, "+1000 chars after": lambda t: t + "\n\n" + pad}
    thr = best_rep["threshold_at_1pct_fpr"]
    probe = {}
    for v, f in V.items():
        sa = score_docs([{"text": f(t), "task": ""} for t in atk])
        sb = score_docs([{"text": f(t), "task": ""} for t in ben])
        probe[v] = {"attacks_caught": int((sa >= thr).sum()), "benign_flagged": int((sb >= thr).sum()), "n": 80}
    pad_alone = float(score_docs([{"text": pad, "task": ""}])[0])

    meta = {"version": f"0.3-{name}", "base_model": cfg["base"], "max_len": cfg["max_len"], "stride": cfg["stride"],
            "task_max_tokens": TASK_MAX, "threshold": thr, "train_windows": len(examples), "train_pos_windows": n_pos,
            "dev": best_rep, "probe": probe, "padding_alone_score": pad_alone, "log": log,
            "minutes": round((time.time() - t0) / 60, 1)}
    Path(out_dir, "toolwall_judge.json").write_text(json.dumps(meta, indent=1))
    vol.commit()
    return meta


@app.local_entrypoint()
def main(backbones: str = "deberta,modern", smoke: bool = False) -> None:
    names = [b.strip() for b in backbones.split(",") if b.strip()]
    out = ROOT / "results" / ("v0_3_dev_smoke" if smoke else "v0_3_dev")
    out.mkdir(parents=True, exist_ok=True)
    for name, meta in zip(names, train_one.map(names, kwargs={"smoke": smoke}, return_exceptions=True)):
        if isinstance(meta, BaseException):
            print(f"== {name}: FAILED {type(meta).__name__}: {str(meta)[:300]}")
            continue
        (out / f"{name}.json").write_text(json.dumps(meta, indent=1))
        d, p = meta["dev"], meta["probe"]
        print(f"== {name}: dev AUROC {d['auroc']:.4f} | TPR {d['tpr']:.3f} at FPR {d['fpr']:.3f} (thr {d['threshold_at_1pct_fpr']:.3f})")
        for v, x in p.items():
            print(f"   probe {v:20} caught {x['attacks_caught']}/80 · false alarms {x['benign_flagged']}/80")
        print(f"   padding alone score {meta['padding_alone_score']:.3f} · {meta['minutes']} min")
