"""Build the v0.3 judge corpus: task-aware, length-balanced, with attack spans.

What v0.2 got wrong: every positive was a short InjecAgent JSON or a synthetic snippet and every long text was benign,
so the judge learned "long = benign". Adding ~1,000 benign characters defeated it. v0.3 breaks that correlation:

  * Paired dilution: an attack is inserted at a random position inside a benign host (Wikipedia, Enron ham, BIPIA
    train contexts, deepset benign prompts) of 200-8,000 characters, and the SAME host without the attack is a negative.
  * Short negatives and long positives both exist; formats vary (plain, JSON page, MCP content block, JSON mail list,
    markdown, HTML) for both labels.
  * Every row carries the user's task (empty for 20 % of rows) and the character span of the attack, so the trainer can
    label windows and the judge can later point at the injected text.

Splits keep v0.2's protocol (InjecAgent tools x attacker instructions split before training). Attack strings are split
by source family between train and dev. Nothing from the v0.3 final tests (LLMail-Inject, LongPIBench) or from the
BIPIA test split is read here.

    python -m training.build_corpus_v0_3
"""
from __future__ import annotations

import hashlib
import html
import json
import random
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
UP = ROOT / "bench" / "loaders" / "_upstream"
IA = UP / "InjecAgent" / "data"
BIPIA = UP / "BIPIA" / "benchmark"
V02 = ROOT / "training" / "_corpus_v0_2"
OUT = ROOT / "training" / "_corpus_v0_3"
SEED = 20261020

GENERIC_TASKS = [
    "Summarize this page.", "What are the key points here?", "Summarize the latest emails for me.",
    "Is there anything I need to reply to?", "Extract the dates and deadlines mentioned.",
    "Give me a short overview of this document.", "What does this say about the budget?",
    "Translate the main points into plain English.", "List the people mentioned and their roles.",
    "Answer my question using this search result: what is the main topic?", "Draft a reply to this thread.",
    "Check this content for anything important.", "What actions are requested in these messages?",
    "Summarize the reviews.", "Find the contact details in this text.", "",
]


def ia_splits() -> tuple[dict[str, str], dict[str, str]]:
    """Recreate v0.2's tool and instruction splits (same seeds as training/build_corpus_v0_2.py)."""
    from training.build_corpus_v0_2 import SEED as S2, split_list

    base = {f: json.load(open(IA / f"test_cases_{f}_base.json")) for f in ("dh", "ds")}
    tl = sorted({c["User Tool"] for f in base for c in base[f]})
    random.Random(S2 + 1).shuffle(tl)
    tool_split = {t: ("train" if i < 10 else "dev" if i < 12 else "test") for i, t in enumerate(tl)}
    instr_split: dict[str, str] = {}
    for f in ("dh", "ds"):
        instr_split.update(split_list(sorted({c["Attacker Instruction"] for c in base[f]}), (0.6, 0.1), random.Random(S2 + 2)))
    return tool_split, instr_split


def render(fmt: str, body: str, rng: random.Random) -> str:
    if fmt == "plain":
        return body
    if fmt == "json_page":
        return json.dumps({"url": f"https://example.org/p/{rng.randrange(10**6)}", "title": "Page", "content": body}, ensure_ascii=False)
    if fmt == "mcp":
        return json.dumps({"content": [{"type": "text", "text": body}], "isError": False}, ensure_ascii=False)
    if fmt == "json_mail":
        parts = [p for p in body.split("\n\n") if p.strip()] or [body]
        return json.dumps([{"from": f"user{i}@example.com", "subject": f"Re: item {i}", "body": p} for i, p in enumerate(parts)],
                          ensure_ascii=False, indent=rng.choice([None, 2]))
    if fmt == "markdown":
        return "# Document\n\n" + body
    if fmt == "html":
        return "<html><body>" + "".join(f"<p>{html.escape(p)}</p>" for p in body.split("\n\n")) + "</body></html>"
    raise ValueError(fmt)


FORMATS = ["plain", "json_page", "mcp", "json_mail", "markdown", "html"]


def find_span(text: str, attack: str) -> list[int] | None:
    for needle in (attack, json.dumps(attack, ensure_ascii=False)[1:-1], html.escape(attack)):
        i = text.find(needle)
        if i >= 0:
            return [i, i + len(needle)]
    # attack split across json_mail parts or paragraphs: fall back to its first 60 characters
    for needle in (attack[:60], json.dumps(attack[:60], ensure_ascii=False)[1:-1], html.escape(attack[:60])):
        i = text.find(needle)
        if i >= 0:
            return [i, min(len(text), i + len(attack))]
    return None


def host_doc(rng: random.Random, pieces: list[str], target: int) -> list[str]:
    out, n = [], 0
    while n < target:
        p = rng.choice(pieces)
        out.append(p)
        n += len(p) + 2
    return out


def insert(paragraphs: list[str], attack: str, rng: random.Random) -> str:
    k = rng.randrange(len(paragraphs) + 1)
    mode = rng.random()
    if mode < 0.6 or not paragraphs:  # own paragraph
        parts = paragraphs[:k] + [attack] + paragraphs[k:]
    else:  # appended to a paragraph, inline
        k = min(k, len(paragraphs) - 1)
        parts = list(paragraphs)
        parts[k] = parts[k] + " " + attack
    return "\n\n".join(parts)


def main() -> None:
    rng = random.Random(SEED)
    OUT.mkdir(parents=True, exist_ok=True)
    tool_split, instr_split = ia_splits()
    rows: dict[str, list[dict]] = {"train": [], "dev": []}

    def add(split: str, task: str, text: str, label: int, src: str, fmt: str, attack: str | None = None) -> None:
        span = find_span(text, attack) if attack else None
        if label and span is None:
            return
        if rng.random() < 0.2:
            task = ""
        rows[split].append({"task": task, "text": text, "label": label, "span": span, "src": src, "fmt": fmt})

    # 1. InjecAgent (train/dev splits only; v0.2's test split stays out)
    attack_pool = {"train": [], "dev": []}
    for f in ("dh", "ds"):
        base = json.load(open(IA / f"test_cases_{f}_base.json"))
        enh = json.load(open(IA / f"test_cases_{f}_enhanced.json"))
        for cb, ce in zip(base, enh):
            ts, is_ = tool_split[cb["User Tool"]], instr_split[cb["Attacker Instruction"]]
            if is_ in ("train", "dev"):
                attack_pool[is_].append(cb["Attacker Instruction"])
            if ts != is_ or ts == "test":
                continue
            for variant, c in (("base", cb), ("enhanced", ce)):
                text = c["Tool Response"].strip().strip('"')
                atk = c["Attacker Instruction"] if variant == "base" else None
                span_src = atk or c["Attacker Instruction"]
                add(ts, c["User Instruction"], text, 1, f"ia_{variant}", "native", span_src)
    # twins from v0.2 corpus (benign tool templates) keep their split
    for split in ("train", "dev"):
        for line in open(V02 / f"{split}.jsonl"):
            r = json.loads(line)
            if r["src"] == "injecagent_twin":
                add(split, rng.choice(GENERIC_TASKS), r["text"], 0, "ia_twin", "native")

    # 2. Attack-string pools (split by source family)
    bt = json.load(open(BIPIA / "text_attack_train.json"))
    bc = json.load(open(BIPIA / "code_attack_train.json"))
    cats = sorted(bt)
    random.Random(SEED + 1).shuffle(cats)
    for i, cat in enumerate(cats):
        attack_pool["dev" if i < 3 else "train"].extend(bt[cat])
    ccats = sorted(bc)
    random.Random(SEED + 2).shuffle(ccats)
    for i, cat in enumerate(ccats):
        attack_pool["dev" if i < 2 else "train"].extend(bc[cat])
    ds = json.load(open(UP / "deepset_pi_train.json"))
    inj = sorted(x["text"] for x in ds if x["label"] == 1)
    random.Random(SEED + 3).shuffle(inj)
    cut = int(len(inj) * 0.85)
    attack_pool["train"].extend(inj[:cut]); attack_pool["dev"].extend(inj[cut:])
    for split in ("train", "dev"):
        for line in open(V02 / f"{split}.jsonl"):
            r = json.loads(line)
            if r["src"] == "v0_1_synthetic" and r["label"] == 1:
                attack_pool[split].append(r["text"])
    for s in attack_pool:
        attack_pool[s] = sorted(set(a.strip() for a in attack_pool[s] if 8 <= len(a.strip()) <= 1500))
    # DeepSeek-generated material (training/generate_v0_3_deepseek.py), split by generation call
    gen = OUT.parent / "_gen_v0_3"
    def gen_rows(kind: str) -> dict[str, list[str]]:
        out: dict[str, list[str]] = {"train": [], "dev": []}
        p = gen / f"{kind}.jsonl"
        if p.exists():
            for line in open(p, encoding="utf-8"):
                r = json.loads(line)
                out["dev" if r["call"] % 8 == 0 else "train"].append(r["text"].strip())
        return out
    gen_attacks, aligned, discussion = gen_rows("attacks"), gen_rows("aligned"), gen_rows("discussion")
    for s in ("train", "dev"):
        attack_pool[s].extend(gen_attacks[s])
        attack_pool[s] = sorted(set(a for a in attack_pool[s] if 8 <= len(a) <= 1500))
    overlap = set(attack_pool["train"]) & set(attack_pool["dev"])  # duplicated strings in the source sets
    attack_pool["dev"] = [a for a in attack_pool["dev"] if a not in overlap]
    print(f"attack strings in both splits (removed from dev): {len(overlap)}")

    # 3. Benign host pieces per split
    hosts = {"train": [], "dev": []}
    for split in ("train", "dev"):
        for line in open(V02 / f"{split}.jsonl"):
            r = json.loads(line)
            if r["src"] == "wikipedia" or r["src"] == "wikipedia_security":
                hosts[split].append(json.loads(r["text"])["content"])
    enron = [e["text"] for e in json.load(open(UP / "enron_ham_train.json")) if e.get("label") == 0 and 80 <= len(e["text"]) <= 2500]
    random.Random(SEED + 4).shuffle(enron)
    hosts["train"].extend(enron[:4000]); hosts["dev"].extend(enron[4000:4600])
    benign_prompts = sorted(x["text"] for x in ds if x["label"] == 0)
    random.Random(SEED + 5).shuffle(benign_prompts)
    hosts["train"].extend(benign_prompts[:290]); hosts["dev"].extend(benign_prompts[290:])

    # 4. BIPIA train contexts (email, table, code) — split 90/10 by context
    bipia_ctx = {"train": [], "dev": []}
    for f in ("email", "table", "code"):
        for i, line in enumerate(open(BIPIA / f / "train.jsonl")):
            r = json.loads(line)
            ctx = r["context"] if isinstance(r["context"], str) else "\n".join(map(str, r["context"]))
            q = r.get("question") or ("Fix the bug: " + str(r.get("error", ""))[:200])
            bipia_ctx["dev" if i % 10 == 0 else "train"].append((f, ctx, q))
    for split, items in bipia_ctx.items():
        for f, ctx, q in items:
            paras = [p for p in ctx.split("\n\n") if p.strip()] or [ctx]
            n_atk = 2 if split == "train" else 1
            for _ in range(n_atk):
                atk = rng.choice(attack_pool[split])
                fmt = rng.choice(["plain", "plain", "mcp", "json_page"])
                add(split, q, render(fmt, insert(paras, atk, rng), rng), 1, f"bipia_{f}", fmt, atk)
            add(split, q, render(rng.choice(["plain", "mcp", "json_page"]), ctx, rng), 0, f"bipia_{f}", "plain")

    # 4b. Benign texts that contain instructions (aligned with the task) or discuss attacks — the false-alarm traps
    for split in ("train", "dev"):
        for t in aligned[split]:
            fmt = rng.choice(FORMATS)
            add(split, rng.choice(GENERIC_TASKS), render(fmt, t, rng), 0, "aligned_short", fmt)
        for t in gen_attacks[split]:  # short standalone attacks balance the short aligned rows
            if rng.random() < 0.6:
                fmt = rng.choice(FORMATS)
                add(split, rng.choice(GENERIC_TASKS), render(fmt, t, rng), 1, "gen_attack_short", fmt, t)
        for t in discussion[split]:
            fmt = rng.choice(FORMATS)
            add(split, rng.choice(GENERIC_TASKS), render(fmt, t, rng), 0, "discussion_short", fmt)

    # 5. Paired dilution docs: same host with and without an attack, many lengths and formats.
    #    Half of the hosts also carry a benign aligned instruction or discussion paragraph in BOTH versions,
    #    so the only difference between the pair is the attack.
    n_pairs = {"train": 6000, "dev": 800}
    for split, n in n_pairs.items():
        traps = aligned[split] + discussion[split]
        for _ in range(n):
            target = int(rng.choice([150, 400, 800, 1500, 3000, 5000, 8000]) * rng.uniform(0.7, 1.3))
            paras = host_doc(rng, hosts[split], target)
            if traps and rng.random() < 0.5:
                paras.insert(rng.randrange(len(paras) + 1), rng.choice(traps))
            atk = rng.choice(attack_pool[split])
            fmt = rng.choice(FORMATS)
            task = rng.choice(GENERIC_TASKS)
            r2 = random.Random(rng.random())
            add(split, task, render(fmt, insert(paras, atk, rng), r2), 1, "dilution", fmt, atk)
            add(split, task, render(fmt, "\n\n".join(paras), r2), 0, "dilution_clean", fmt)

    # 6. Short v0.1 rows (both labels) so "short" is not a cue either
    for split in ("train", "dev"):
        for line in open(V02 / f"{split}.jsonl"):
            r = json.loads(line)
            if r["src"] == "v0_1_synthetic":
                add(split, rng.choice(GENERIC_TASKS), r["text"], r["label"], "v0_1_short", "native", r["text"] if r["label"] else None)

    for split, rs in rows.items():
        rng.shuffle(rs)
        with open(OUT / f"{split}.jsonl", "w") as fh:
            for r in rs:
                fh.write(json.dumps(r, ensure_ascii=False) + "\n")
    stats = {s: {"n": len(rs), "pos": sum(r["label"] for r in rs)} for s, rs in rows.items()}
    stats["attack_strings"] = {s: len(v) for s, v in attack_pool.items()}
    stats["sha256"] = {s: hashlib.sha256((OUT / f"{s}.jsonl").read_bytes()).hexdigest() for s in rows}
    (OUT / "MANIFEST.json").write_text(json.dumps(stats, indent=1) + "\n")
    print(json.dumps(stats, indent=1))


if __name__ == "__main__":
    main()
