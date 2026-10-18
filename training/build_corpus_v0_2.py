"""Build the v0.2 judge corpus with a strict held-out protocol.

Why v0.2 exists: the v0.1 judge (LoRA on Qwen2.5-7B) was trained only on synthetic
templates. On external data it blocked 98% of benign Wikipedia pages (see
results/external_v0_2/). v0.2 retrains a small classifier on more varied data and
tests it only on material it could not have seen.

Split protocol (InjecAgent, commit f19c9f2, MIT):
  * the 17 user tools are split 10 / 2 / 5 into train / dev / test;
  * the 62 attacker instructions are split 60% / 10% / 30% within each family (dh, ds);
  * a case is kept only if its tool AND its instruction fall in the same split.
  Base and enhanced variants of a case always share a split.
Benign twins reuse each split's own tool templates with neutral sentences taken from
that split's own Wikipedia pool. Wikipedia test pages (bench/build_artifacts/
external_v0_2/wiki_benign.jsonl) and the hard-negative titles are excluded from
training. The v0.1 synthetic corpus is added to train/dev ("suspicious" rows dropped).

    python -m training.build_corpus_v0_2
"""

from __future__ import annotations

import hashlib
import json
import random
import re
import time
from pathlib import Path

from bench.external.build_v0_2 import (
    HARDNEG_TITLES, _wiki, fetch_random_intros, first_sentence, strip_outer_quotes,
)

ROOT = Path(__file__).resolve().parents[1]
IA = ROOT / "bench" / "loaders" / "_upstream" / "InjecAgent" / "data"
EXT = ROOT / "bench" / "build_artifacts" / "external_v0_2"
OUT_TRAIN = ROOT / "training" / "_corpus_v0_2"
OUT_TEST = ROOT / "bench" / "build_artifacts" / "heldout_v0_2"
SEED = 20261019
TRAIN_SECURITY_TITLES = [
    "Malware", "Ransomware", "Buffer overflow", "Denial-of-service attack", "Man-in-the-middle attack",
    "Spoofing attack", "Session hijacking", "Directory traversal attack", "Data breach", "Penetration test",
    "Computer worm", "Trojan horse (computing)", "Password cracking", "Zero-day vulnerability", "Botnet",
]


def split_list(items: list[str], fracs: tuple[float, float], rng: random.Random) -> dict[str, str]:
    items = sorted(items)
    rng.shuffle(items)
    n = len(items)
    a, b = round(n * fracs[0]), round(n * (fracs[0] + fracs[1]))
    return {x: ("train" if i < a else "dev" if i < b else "test") for i, x in enumerate(items)}


def security_paragraphs(titles: list[str]) -> list[str]:
    out = []
    for t in titles:
        d = _wiki({"action": "query", "titles": t, "prop": "extracts", "explaintext": 1})
        for p in d.get("query", {}).get("pages", {}).values():
            for para in re.split(r"\n\s*\n|\n(?===)", p.get("extract") or ""):
                para = para.strip()
                if len(para) >= 200 and not para.startswith("=="):
                    out.append(json.dumps({"title": p.get("title", t), "content": para[:1500]}, ensure_ascii=False))
        time.sleep(1.0)
    return out


def main() -> None:
    rng = random.Random(SEED)
    OUT_TRAIN.mkdir(parents=True, exist_ok=True)
    OUT_TEST.mkdir(parents=True, exist_ok=True)

    base = {f: json.load(open(IA / f"test_cases_{f}_base.json")) for f in ("dh", "ds")}
    enh = {f: json.load(open(IA / f"test_cases_{f}_enhanced.json")) for f in ("dh", "ds")}
    tools = sorted({c["User Tool"] for f in base for c in base[f]})
    rt = random.Random(SEED + 1)
    tl = sorted(tools)
    rt.shuffle(tl)
    tool_split = {t: ("train" if i < 10 else "dev" if i < 12 else "test") for i, t in enumerate(tl)}
    instr_split = {}
    for f in ("dh", "ds"):
        instr_split.update(split_list(sorted({c["Attacker Instruction"] for c in base[f]}), (0.6, 0.1), random.Random(SEED + 2)))

    # Wikipedia pools: test pages are fixed (external_v0_2/wiki_benign); train/dev pages are fresh and disjoint.
    test_titles = {json.loads(line)["attack_kind"] and json.loads(json.loads(line)["tool_response"])["title"]
                   for line in open(EXT / "wiki_benign.jsonl")}
    fresh = [x for x in fetch_random_intros(1400) if x["title"] not in test_titles]
    rng.shuffle(fresh)
    wiki_train, wiki_dev = fresh[:1150], fresh[1150:1350]
    test_pool = [first_sentence(json.loads(json.loads(line)["tool_response"])["content"])
                 for line in open(EXT / "wiki_benign.jsonl")]
    pools = {"train": [first_sentence(x["text"]) for x in wiki_train], "dev": [first_sentence(x["text"]) for x in wiki_dev],
             "test": test_pool}

    rows = {"train": [], "dev": []}
    test_sets: dict[str, list[dict]] = {"ia_test_base": [], "ia_test_enhanced": [], "ia_test_twin": []}
    templates = {s: set() for s in ("train", "dev", "test")}
    for f in ("dh", "ds"):
        for c_b, c_e in zip(base[f], enh[f]):
            ts, is_ = tool_split[c_b["User Tool"]], instr_split[c_b["Attacker Instruction"]]
            templates[ts].add(c_b["Tool Response Template"])
            if ts != is_:
                continue
            for variant, c in (("base", c_b), ("enhanced", c_e)):
                text = strip_outer_quotes(c["Tool Response"])
                if ts == "test":
                    test_sets[f"ia_test_{variant}"].append({"id": f"ia-{f}-{variant}-{len(test_sets[f'ia_test_{variant}']):04d}",
                                                            "tool_response": text, "expected_block": True})
                else:
                    rows[ts].append({"text": text, "label": 1, "src": f"injecagent_{variant}"})
    for s, temps in templates.items():
        for tmpl in sorted(temps):
            n = 40 if s == "train" else 15 if s == "dev" else 30
            for _ in range(n):
                text = tmpl.replace("<Attacker Instruction>", rng.choice(pools[s]).replace("'", "’"))
                if s == "test":
                    test_sets["ia_test_twin"].append({"id": f"ia-twin-{len(test_sets['ia_test_twin']):04d}",
                                                      "tool_response": text, "expected_block": False})
                else:
                    rows[s].append({"text": text, "label": 0, "src": "injecagent_twin"})
    for s, pages in (("train", wiki_train), ("dev", wiki_dev)):
        for x in pages:
            rows[s].append({"text": json.dumps({"url": x["url"], "title": x["title"], "content": x["text"]}, ensure_ascii=False),
                            "label": 0, "src": "wikipedia"})
    assert not set(TRAIN_SECURITY_TITLES) & set(HARDNEG_TITLES)
    sec = security_paragraphs(TRAIN_SECURITY_TITLES)
    rng.shuffle(sec)
    for i, t in enumerate(sec):
        rows["dev" if i % 8 == 0 else "train"].append({"text": t, "label": 0, "src": "wikipedia_security"})
    v01 = [json.loads(line) for line in open(ROOT / "training" / "_corpus" / "train_v0_1.jsonl")]
    for i, r in enumerate(v01):
        if r["label"] == "suspicious":
            continue
        rows["dev" if i % 10 == 0 else "train"].append({"text": r["text"], "label": int(r["label"] == "attack"), "src": "v0_1_synthetic"})

    # Leakage guard: no exact training text may appear in any held-out test set.
    train_texts = {r["text"] for s in rows for r in rows[s]}
    for name, rs in test_sets.items():
        assert not any(r["tool_response"] in train_texts for r in rs), f"leak into {name}"
    manifest = {"seed": SEED, "tool_split": tool_split, "n": {}}
    for s, rs in rows.items():
        rng.shuffle(rs)
        p = OUT_TRAIN / f"{s}.jsonl"
        data = "".join(json.dumps(r, ensure_ascii=False) + "\n" for r in rs)
        p.write_text(data, encoding="utf-8")
        manifest["n"][s] = {"total": len(rs), "attack": sum(r["label"] for r in rs),
                            "sha256": hashlib.sha256(data.encode()).hexdigest()}
    for name, rs in test_sets.items():
        data = "".join(json.dumps(r, ensure_ascii=False) + "\n" for r in rs)
        (OUT_TEST / f"{name}.jsonl").write_text(data, encoding="utf-8")
        manifest["n"][name] = {"total": len(rs), "sha256": hashlib.sha256(data.encode()).hexdigest()}
    (OUT_TRAIN / "MANIFEST.json").write_text(json.dumps(manifest, indent=2))
    print(json.dumps(manifest["n"], indent=1))
    print("test tools:", sorted(t for t, s in tool_split.items() if s == "test"))


if __name__ == "__main__":
    main()
