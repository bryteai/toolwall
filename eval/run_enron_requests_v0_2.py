"""Hard-negative test: benign workplace emails that contain requests to the human reader.

Source: SetFit/enron_spam (ham rows, test split), derived from the Enron-Spam corpus
(Metsis et al., 2006). Only message IDs are redistributed (bench/build_artifacts/
heldout_v0_2/enron_requests_ids.json); the text is fetched at run time.

    python -m eval.run_enron_requests_v0_2 --defense toolwall_v0_2|toolwall_rule_only|protectai_deberta_v2
"""
from __future__ import annotations
import argparse, json, os, re, urllib.request
from pathlib import Path
from eval.run_external_v0_2 import wilson

ROOT = Path(__file__).resolve().parents[1]
IDS = ROOT / "bench" / "build_artifacts" / "heldout_v0_2" / "enron_requests_ids.json"
REQ = re.compile(r"\b(please|could you|can you|would you|let me know|send me|call me|forward|need you to)\b", re.I)

CACHE = ROOT / "bench" / "loaders" / "_upstream" / "enron_ham_test.json"   # gitignored local cache

def fetch() -> list[dict]:
    if CACHE.exists():
        return json.loads(CACHE.read_text())
    import time
    rows, off = [], 0
    while off < 4000:
        u = f"https://datasets-server.huggingface.co/rows?dataset=SetFit%2Fenron_spam&config=default&split=test&offset={off}&length=100"
        d = json.load(urllib.request.urlopen(urllib.request.Request(u, headers={"User-Agent": "toolwall-bench/0.2"}), timeout=40))
        rows += [r["row"] for r in d.get("rows", []) if r["row"].get("label") == 0]
        off += 100
        time.sleep(2)
    CACHE.write_text(json.dumps(rows))
    return rows

def build() -> list[dict]:
    ham = fetch()
    keep = [x for x in ham if REQ.search((x.get("message") or x.get("text") or "")[:1500])]
    if IDS.exists():
        want = set(json.loads(IDS.read_text()))
        keep = [x for x in keep if x["message_id"] in want]
    else:
        IDS.write_text(json.dumps(sorted(x["message_id"] for x in keep)))
    return [{"id": f"enron-{x['message_id']}", "expected_block": False,
             "tool_response": json.dumps({"subject": x.get("subject", ""), "body": (x.get("message") or x.get("text") or "")[:1500]}, ensure_ascii=False)}
            for x in keep]

def main() -> None:
    ap = argparse.ArgumentParser(); ap.add_argument("--defense", required=True); a = ap.parse_args()
    rows = build()
    if a.defense == "toolwall_rule_only":
        os.environ["TOOLWALL_DISABLE_JUDGE"] = "1"
        from eval.baselines import ToolwallRuleOnly; d = ToolwallRuleOnly(); f = lambda t: d.decide(t).blocked
    elif a.defense == "toolwall_v0_2":
        os.environ.setdefault("TOOLWALL_JUDGE_LOCAL_PATH", str(ROOT / "models" / "judge-v0.2"))
        from eval.baselines import Toolwall; d = Toolwall(use_judge=True); f = lambda t: d.decide(t).blocked
    else:
        from transformers import pipeline
        clf = pipeline("text-classification", model="protectai/deberta-v3-base-prompt-injection-v2", truncation=True, max_length=512)
        f = lambda t: clf(t[:4000])[0]["label"].upper() == "INJECTION"
    out = ROOT / "results" / "heldout_v0_2" / f"{a.defense}.enron_requests.decisions.jsonl"
    dec = [{"id": r["id"], "set": "enron_requests", "expected_block": False, "blocked": bool(f(r["tool_response"]))} for r in rows]
    out.write_text("".join(json.dumps(x) + "\n" for x in dec))
    k = sum(x["blocked"] for x in dec); v, lo, hi = wilson(k, len(dec))
    print(f"{a.defense:22} enron_requests n={len(dec)} FPR {v:.3f} [{lo:.3f}, {hi:.3f}]")

if __name__ == "__main__":
    main()
