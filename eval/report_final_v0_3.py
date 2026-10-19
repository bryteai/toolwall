"""Summarise results/v0_3_final/*.decisions.jsonl into tables with Wilson 95 % intervals.

    python -m eval.report_final_v0_3
"""
from __future__ import annotations

import collections
import json
import math
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
DIR = ROOT / "results" / "v0_3_final"
ORDER = ["toolwall_v0_3", "toolwall_v0_3_notask", "toolwall_v0_3_xsmall", "toolwall_v0_2", "protectai_v2", "piguard",
         "promptguard2_86m", "promptguard2_22m", "deepset"]
NAMES = {"toolwall_v0_3": "toolwall v0.3 (with task)", "toolwall_v0_3_notask": "toolwall v0.3 (no task)",
         "toolwall_v0_3_xsmall": "toolwall v0.3-xsmall (with task)", "toolwall_v0_2": "toolwall v0.2",
         "protectai_v2": "ProtectAI v2", "piguard": "PIGuard", "promptguard2_86m": "Prompt Guard 2 86M",
         "promptguard2_22m": "Prompt Guard 2 22M", "deepset": "deepset"}


def wilson(k: int, n: int, z: float = 1.96) -> tuple[float, float, float]:
    if n == 0:
        return float("nan"), float("nan"), float("nan")
    p = k / n
    d = 1 + z * z / n
    c = (p + z * z / (2 * n)) / d
    h = z * math.sqrt(p * (1 - p) / n + z * z / (4 * n * n)) / d
    return p, max(0.0, c - h), min(1.0, c + h)


def fmt(k: int, n: int) -> str:
    p, lo, hi = wilson(k, n)
    return f"{p:.3f} [{lo:.3f}, {hi:.3f}] ({k}/{n})"


def main() -> None:
    rows = collections.defaultdict(list)
    for f in sorted(DIR.glob("*.decisions.jsonl")):
        for d in map(json.loads, open(f, encoding="utf-8")):
            rows[(f.name.split(".")[0], d["protocol"])].append(d)
    summary: dict = {}
    lines = ["# v0.3 final evaluation (one run)", "",
             "Detection = share of attack rows blocked (higher is better). False alarms = share of benign rows blocked "
             "(lower is better). Wilson 95 % intervals. HF guards: `truncate512` = first 512 tokens; `chunk512` = "
             "LongPIBench protocol (any 512-token chunk ≥ 0.5).", ""]
    for ds in ("llmail", "longpibench", "bipia"):
        lines += [f"## {ds}", "", "| Guard | protocol | detection | false alarms |", "|---|---|---|---|"]
        for g in ORDER:
            for proto in ("toolwall", "truncate512", "chunk512"):
                rs = [r for r in rows.get((g, proto), []) if r["set"] == ds]
                if not rs:
                    continue
                pos = [r for r in rs if r["label"] == 1]
                neg = [r for r in rs if r["label"] == 0]
                tp, fp = sum(r["blocked"] for r in pos), sum(r["blocked"] for r in neg)
                summary.setdefault(ds, {}).setdefault(f"{g}/{proto}", {})["all"] = {"tp": tp, "n_pos": len(pos), "fp": fp, "n_neg": len(neg)}
                subs = collections.defaultdict(lambda: [0, 0])
                for r in rs:
                    subs[(r["sub"], r["label"])][0] += int(r["blocked"])
                    subs[(r["sub"], r["label"])][1] += 1
                summary[ds][f"{g}/{proto}"]["by_sub"] = {f"{s}|{lab}": v for (s, lab), v in sorted(subs.items())}
                lines.append(f"| {NAMES[g]} | {proto} | {fmt(tp, len(pos))} | {fmt(fp, len(neg))} |")
        lines.append("")
    # per-subset tables for the main guard protocols
    for ds in ("llmail", "longpibench"):
        subs = sorted({k.split("|")[0] for v in summary.get(ds, {}).values() for k in v["by_sub"]})
        lines += [f"### {ds} by subset (blocked / rows)", "", "| Guard | " + " | ".join(subs) + " |", "|---|" + "---|" * len(subs)]
        for key, v in summary.get(ds, {}).items():
            g, proto = key.split("/")
            if proto == "truncate512":
                continue
            cells = []
            for s in subs:
                vals = [v["by_sub"].get(f"{s}|{lab}") for lab in (1, 0)]
                cells.append(" · ".join(f"{x[0]}/{x[1]}" for x in vals if x))
            lines.append(f"| {NAMES[g]} ({proto}) | " + " | ".join(cells) + " |")
        lines.append("")
    (DIR / "summary.json").write_text(json.dumps(summary, indent=1) + "\n")
    (DIR / "tables.md").write_text("\n".join(lines) + "\n")
    print("\n".join(lines))


if __name__ == "__main__":
    main()
