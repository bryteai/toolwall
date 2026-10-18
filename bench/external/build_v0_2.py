"""Build the external, held-out evaluation set for toolwall v0.2.

Nothing here was seen by the v0.1 judge (it was trained only on the synthetic
templates in ``training/build_corpus.py``).

Sources
-------
* InjecAgent (Zhan et al., Findings of ACL 2024), MIT licence,
  https://github.com/uiuc-kang-lab/InjecAgent at commit
  f19c9f2c79a41046eb13c03c51a24c567a8ffa07 (2024-07-02).
  - ``injecagent_base``     : 1,054 attacked tool responses (dh + ds, base setting)
  - ``injecagent_enhanced`` : 1,054 attacked tool responses (enhanced setting)
  - ``injecagent_twin``     : 1,054 benign twins: the same tool-response template
    with the attacker instruction replaced by a neutral sentence taken from a
    random Wikipedia article summary (paired false-positive test).
* Wikipedia (CC BY-SA 4.0), fetched through the public MediaWiki API:
  - ``wiki_benign``  : random article introductions, wrapped as web-fetch results
  - ``wiki_hardneg`` : paragraphs from security articles that *discuss* injection
    attacks (benign, but lexically close to attacks). Reported separately.

Run::

    python -m bench.external.build_v0_2 --upstream bench/loaders/_upstream/InjecAgent \
        --out bench/build_artifacts/external_v0_2
"""

from __future__ import annotations

import argparse
import hashlib
import json
import random
import re
import time
import urllib.parse
import urllib.request
from pathlib import Path

INJECAGENT_COMMIT = "f19c9f2c79a41046eb13c03c51a24c567a8ffa07"
UA = "toolwall-bench/0.2 (research; contact hasnain@bryteai.studio)"
SEED = 20261018
HARDNEG_TITLES = [
    "Prompt injection", "SQL injection", "Code injection", "Cross-site scripting",
    "Phishing", "Social engineering (security)", "Email spoofing", "Clickjacking",
    "Command injection", "Large language model",
]


def _wiki(params: dict) -> dict:
    url = "https://en.wikipedia.org/w/api.php?" + urllib.parse.urlencode({**params, "format": "json"})
    req = urllib.request.Request(url, headers={"User-Agent": UA})
    with urllib.request.urlopen(req, timeout=30) as r:
        return json.load(r)


def fetch_random_intros(n: int) -> list[dict]:
    out: dict[int, dict] = {}
    while len(out) < n:
        d = _wiki({"action": "query", "generator": "random", "grnnamespace": 0, "grnlimit": 20,
                   "prop": "extracts|info", "exintro": 1, "explaintext": 1, "inprop": "url"})
        for p in d.get("query", {}).get("pages", {}).values():
            text = (p.get("extract") or "").strip()
            if len(text) >= 200:
                out[p["pageid"]] = {"title": p["title"], "url": p.get("fullurl", ""), "text": text[:1500]}
        time.sleep(1.0)
    return list(out.values())[:n]


def fetch_hardneg_paragraphs() -> list[dict]:
    rows = []
    for title in HARDNEG_TITLES:
        d = _wiki({"action": "query", "titles": title, "prop": "extracts|info", "explaintext": 1, "inprop": "url"})
        for p in d.get("query", {}).get("pages", {}).values():
            for para in re.split(r"\n\s*\n|\n(?===)", p.get("extract") or ""):
                para = para.strip()
                if len(para) >= 200 and not para.startswith("=="):
                    rows.append({"title": p["title"], "url": p.get("fullurl", ""), "text": para[:1500]})
        time.sleep(1.0)
    return rows


def first_sentence(text: str) -> str:
    s = re.split(r"(?<=[.!?])\s", text.strip())[0]
    return s[:300]


def strip_outer_quotes(s: str) -> str:
    s = s.strip()
    return s[1:-1] if len(s) >= 2 and s[0] == s[-1] == '"' else s


def row(rid: str, kind: str, text: str, block: bool, source: str, citation: str) -> dict:
    return {"id": rid, "attack_kind": kind, "tool_response": text, "expected_block": block,
            "expected_utility_payload": [], "source": source, "citation": citation}


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--upstream", type=Path, required=True)
    ap.add_argument("--out", type=Path, required=True)
    ap.add_argument("--n-wiki", type=int, default=400)
    a = ap.parse_args()
    rng = random.Random(SEED)
    a.out.mkdir(parents=True, exist_ok=True)
    cite_ia = f"InjecAgent (Zhan et al., ACL Findings 2024), MIT, commit {INJECAGENT_COMMIT[:12]}"

    intros = fetch_random_intros(a.n_wiki)
    pool = [first_sentence(x["text"]) for x in intros]

    sets: dict[str, list[dict]] = {k: [] for k in ("injecagent_base", "injecagent_enhanced", "injecagent_twin", "wiki_benign", "wiki_hardneg")}
    for setting in ("base", "enhanced"):
        for family in ("dh", "ds"):
            cases = json.load(open(a.upstream / "data" / f"test_cases_{family}_{setting}.json"))
            for i, c in enumerate(cases):
                rid = f"ia-{family}-{setting}-{i:04d}"
                kind = "tool_poisoning" if family == "dh" else "markdown_exfil" if False else "multi_hop"
                sets[f"injecagent_{setting}"].append(
                    row(rid, kind, strip_outer_quotes(c["Tool Response"]), True, f"injecagent_{setting}", cite_ia))
                if setting == "base":
                    benign = c["Tool Response Template"].replace("<Attacker Instruction>", rng.choice(pool).replace("'", "’"))
                    sets["injecagent_twin"].append(
                        row(f"ia-{family}-twin-{i:04d}", "benign", benign, False, "injecagent_twin",
                            cite_ia + "; filler sentences from Wikipedia (CC BY-SA 4.0)"))
    for j, x in enumerate(intros):
        text = json.dumps({"url": x["url"], "title": x["title"], "content": x["text"]}, ensure_ascii=False)
        sets["wiki_benign"].append(row(f"wiki-{j:04d}", "benign", text, False, "wiki_benign",
                                       f"Wikipedia, '{x['title']}', CC BY-SA 4.0"))
    for j, x in enumerate(fetch_hardneg_paragraphs()):
        text = json.dumps({"url": x["url"], "title": x["title"], "content": x["text"]}, ensure_ascii=False)
        sets["wiki_hardneg"].append(row(f"hardneg-{j:04d}", "benign", text, False, "wiki_hardneg",
                                        f"Wikipedia, '{x['title']}', CC BY-SA 4.0"))

    manifest = {"injecagent_commit": INJECAGENT_COMMIT, "seed": SEED, "files": {}}
    for name, rows in sets.items():
        p = a.out / f"{name}.jsonl"
        data = "".join(json.dumps(r, ensure_ascii=False) + "\n" for r in rows)
        p.write_text(data, encoding="utf-8")
        manifest["files"][name] = {"n": len(rows), "sha256": hashlib.sha256(data.encode()).hexdigest()}
        print(f"{name:22} {len(rows):5}")
    (a.out / "MANIFEST.json").write_text(json.dumps(manifest, indent=2))


if __name__ == "__main__":
    main()
