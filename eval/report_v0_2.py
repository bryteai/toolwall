"""Summarise results/v0_2/*.decisions.jsonl (from eval/modal_eval_v0_2.py) with Wilson 95% CIs.

Writes results/v0_2/summary.json and results/v0_2/tables.md (the README tables).

    python -m eval.report_v0_2
"""

from __future__ import annotations

import json
from pathlib import Path

from eval.run_external_v0_2 import wilson

ROOT = Path(__file__).resolve().parents[1]
DIR = ROOT / "results" / "v0_2"
DEFENSES = [("toolwall_v0_2", "**toolwall v0.2**"), ("toolwall_rule_only", "rules only"), ("protectai_deberta_v2", "ProtectAI v2")]
HELDOUT = [
    ("ia_test_base", "ASR", "InjecAgent, unseen tools × unseen instructions (base)"),
    ("ia_test_enhanced", "ASR", "InjecAgent, same, \"enhanced\" setting"),
    ("inhouse_200", "ASR", "In-house MCP attacks (tool poisoning, rug-pull, exfiltration…)"),
    ("novel_10", "ASR", "Novel attack families (red-team probe)"),
    ("deepset_test", "ASR", "deepset/prompt-injections, test split, inside a web page"),
    ("gandalf_test", "ASR", "Lakera Gandalf, test split, inside a web page"),
    ("ia_test_twin", "FPR", "InjecAgent benign twins (same templates, neutral text)"),
    ("wiki_benign", "FPR", "Wikipedia articles, random"),
    ("wiki_hardneg", "FPR", "Wikipedia security articles (injection, phishing, LLMs)"),
    ("enron_requests", "FPR", "Workplace emails containing requests (Enron-Spam ham)"),
    ("deepset_test", "FPR", "deepset benign rows, inside a web page"),
    ("inhouse_200", "FPR", "In-house benign MCP responses"),
    ("short_benign_test", "FPR", "Short tool outputs (status lines, ids, URLs, listings)"),
]
BIPIA = [("email", "BIPIA email QA contexts"), ("table", "BIPIA table QA contexts"), ("all", "BIPIA, both")]


def cell(rows: list[dict], metric: str) -> tuple[int, int, tuple[float, float, float]] | None:
    rs = [r for r in rows if r["expected_block"] == (metric == "ASR")]
    if not rs:
        return None
    k = sum((not r["blocked"]) if metric == "ASR" else r["blocked"] for r in rs)
    return k, len(rs), wilson(k, len(rs))


def fmt(c, best: bool) -> str:
    v, lo, hi = c[2]
    s = f"{v:.3f}"
    return (f"**{s}**" if best else s) + f" [{lo:.3f}, {hi:.3f}]"


def table(spec, select) -> tuple[list[str], dict]:
    data = {d: [json.loads(line) for line in open(DIR / f"{d}.decisions.jsonl")] for d, _ in DEFENSES}
    out = {}
    lines = ["| Set | n | Metric | " + " | ".join(h for _, h in DEFENSES) + " |", "|---|---:|---|" + "---|" * len(DEFENSES)]
    for key, metric, label in spec:
        cells = [cell(select(data[d], key), metric) for d, _ in DEFENSES]
        if cells[0] is None:
            continue
        best = min(c[2][0] for c in cells)
        lines.append(f"| {label} | {cells[0][1]} | {metric} | " + " | ".join(fmt(c, c[2][0] == best) for c in cells) + " |")
        out[f"{key}:{metric}"] = {d: {"k": c[0], "n": c[1], "value": c[2][0], "ci95": [c[2][1], c[2][2]]}
                                  for (d, _), c in zip(DEFENSES, cells)}
    return lines, out


def main() -> None:
    held_lines, held = table(HELDOUT, lambda rows, s: [r for r in rows if r["set"] == s])
    bipia_rows = lambda rows, task: [r for r in rows if r["set"] == "final_bipia" and (task == "all" or r.get("task") == task)]
    bip_spec = [(t, m, f"{label}") for t, label in BIPIA for m in ("ASR", "FPR")]
    bip_lines, bip = table(bip_spec, bipia_rows)
    probe = [json.loads(line) for line in open(DIR / "toolwall_v0_2.decisions.jsonl") if '"short_probe"' in line]
    run = json.loads((DIR / "run.json").read_text())
    summary = {"run": run, "heldout": held, "final_bipia": bip,
               "short_probe_blocked": sum(r["blocked"] for r in probe), "short_probe_n": len(probe)}
    (DIR / "summary.json").write_text(json.dumps(summary, indent=2))
    md = "### Held-out sets\n\n" + "\n".join(held_lines) + "\n\n### Final check (BIPIA)\n\n" + "\n".join(bip_lines) + "\n"
    (DIR / "tables.md").write_text(md)
    print(md)
    print("short probe blocked:", summary["short_probe_blocked"], "/", summary["short_probe_n"])
    print("run:", json.dumps(run))


if __name__ == "__main__":
    main()
