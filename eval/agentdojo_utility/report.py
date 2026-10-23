"""Summarise benign utility runs: per model and policy, with the census class of each task.

  python -I eval/agentdojo_utility/report.py results/v0_6_agentdojo_utility

Reads raw/<model>__<policy>__r<k>.json and ../v0_5_agentdojo_census/authority_census.csv. Utility per task is the mean
over repeats; intervals are 95 % percentile bootstraps over tasks (10,000 resamples, seed 0). A lost task is one the
undefended agent solves in a majority of repeats and the policy run does not; it is "refusal-caused" if the policy run
refused a call in that task in a majority of repeats. The paired difference is the mean over tasks of the undefended
minus the policy utility of the same task, bootstrapped over tasks in the same way.
"""
import collections
import csv
import glob
import json
import os
import random
import sys

DIR = sys.argv[1]
CENSUS = os.path.join(DIR, "..", "v0_5_agentdojo_census", "authority_census.csv")
CLASSES = ["NO_AUTHORITY_ARG", "PROMPT", "CLEAN", "TAINTED", "UNOBSERVED"]
POLICIES = ["none", "prompt_only", "provenance"]


def bootstrap(values, n=10_000, seed=0):
    rng = random.Random(seed)
    k = len(values)
    means = sorted(sum(rng.choice(values) for _ in range(k)) / k for _ in range(n))
    return means[int(0.025 * n)], means[int(0.975 * n) - 1]


def load():
    runs = collections.defaultdict(lambda: collections.defaultdict(list))   # (model, policy) -> task -> [rows]
    for path in sorted(glob.glob(os.path.join(DIR, "raw", "*__*__r*.json"))):
        model, policy, _ = os.path.basename(path)[:-5].split("__")
        for r in json.load(open(path)):
            runs[(model, policy)][(r["suite"], r["task"])].append(r)
    return runs


def main():
    census = {(r["suite"], r["task"]): r["class"] for r in csv.DictReader(open(CENSUS))}
    runs = load()
    models = sorted({m for m, _ in runs})
    out = {"models": {}}
    lines = ["| Model | Policy | Repeats | Utility (95 % CI) | " + " | ".join(CLASSES) + " |",
             "|---|---|---:|---|" + "---:|" * len(CLASSES)]
    for m in models:
        out["models"][m] = {}
        base = runs.get((m, "none"), {})
        base_ok = {t: sum(r["utility"] for r in rs) * 2 > len(rs) for t, rs in base.items()}
        base_mean = {t: sum(r["utility"] for r in rs) / len(rs) for t, rs in base.items()}
        for p in POLICIES:
            tasks = runs.get((m, p))
            if not tasks:
                continue
            reps = min(len(rs) for rs in tasks.values())
            per_task = {t: sum(r["utility"] for r in rs) / len(rs) for t, rs in tasks.items()}
            vals = list(per_task.values())
            mean, (lo, hi) = sum(vals) / len(vals), bootstrap(vals)
            by_class = {c: [v for t, v in per_task.items() if census[t] == c] for c in CLASSES}
            lost = [t for t, ok in base_ok.items() if ok and t in per_task and per_task[t] * 2 <= 1] if p != "none" else []
            refusal_caused = [t for t in lost
                              if sum(r["refused"] > 0 for r in tasks[t]) * 2 > len(tasks[t])]
            usage = collections.Counter()
            for rs in tasks.values():
                for r in rs:
                    usage.update(r.get("usage", {}))
            # Paired over tasks: undefended minus policy utility, same task, each a mean over its repeats.
            diffs = [base_mean[t] - v for t, v in per_task.items() if t in base_mean] if p != "none" else []
            paired = {"mean": sum(diffs) / len(diffs), "ci95": list(bootstrap(diffs))} if diffs else None
            out["models"][m][p] = {
                "tasks": len(vals), "repeats": reps, "utility": mean, "ci95": [lo, hi], "paired_none_minus": paired,
                "by_class": {c: {"n": len(v), "utility": (sum(v) / len(v) if v else None)} for c, v in by_class.items()},
                "lost_vs_none": sorted("/".join(t) for t in lost),
                "lost_refusal_caused": sorted("/".join(t) for t in refusal_caused),
                "tasks_with_refusal": sum(1 for rs in tasks.values() if sum(r["refused"] > 0 for r in rs) * 2 > len(rs)),
                "usage": dict(usage),
            }
            cells = " | ".join("-" if not v else f"{100 * sum(v) / len(v):.0f} % (n={len(v)})" for v in by_class.values())
            lines.append(f"| {m} | {p} | {reps} | {100 * mean:.1f} % ({100 * lo:.1f}–{100 * hi:.1f}) | {cells} |")
    json.dump(out, open(os.path.join(DIR, "summary.json"), "w"), indent=1)
    open(os.path.join(DIR, "summary.md"), "w").write("\n".join(lines) + "\n")
    print("\n".join(lines))
    for m, ps in out["models"].items():
        for p, s in ps.items():
            if p != "none":
                d = s["paired_none_minus"]
                print(f"{m} {p}: lost vs none {len(s['lost_vs_none'])} (refusal-caused {len(s['lost_refusal_caused'])}),"
                      f" tasks with a refusal {s['tasks_with_refusal']}"
                      + (f", none minus {p} {100 * d['mean']:.1f} pp ({100 * d['ci95'][0]:.1f}–{100 * d['ci95'][1]:.1f})"
                         if d else ""))


main()
