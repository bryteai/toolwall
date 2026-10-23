"""Cross-tabulate the authority census with FIDES's task taxonomy (Costa et al., arXiv 2505.23643v2, Table 5).

FIDES classifies AgentDojo user tasks by whether the planner must see tool results: data independent (DI), data
independent with a quarantined query_llm call (DIQ) and data dependent (DD). The census classifies them by where their
authority arguments come from. Table 5 lists slack user_task_17 under both DIQ and DD; Table 2's slack percentages
(19.0 / 38.1 / 42.9 % of 21 tasks = 4 / 8 / 9) imply a single category, so it is reported here as "DIQ|DD".

  python -I eval/agentdojo_census/fides_crosstab.py results/v0_5_agentdojo_census/authority_census.csv
"""
import collections
import csv
import sys

TABLE5 = {   # task indices per category, transcribed from Table 5 (arXiv 2505.23643v2, p. 36)
    "workspace": {"DI": [0, 2, 3, 5, 6, 7, 8, 9, 10, 11, 12, 16, 20, 21, 24, 26, 27, 35, 38],
                  "DIQ": [1, 4, 14, 15, 17, 18, 22, 23, 25, 28, 29, 30, 31, 32, 33, 34, 36, 37, 39],
                  "DD": [13, 19]},
    "travel": {"DI": [], "DIQ": list(range(2, 20)), "DD": [0, 1]},
    "banking": {"DI": [1, 3, 4], "DIQ": [0, 2, 5, 6, 7, 8], "DD": [9, 10, 11, 12, 13, 14, 15]},
    "slack": {"DI": [0, 5, 9, 12], "DIQ": [2, 3, 7, 8, 10, 13, 14, 17], "DD": [1, 4, 6, 11, 15, 16, 17, 18, 19, 20]},
}
CLASSES = ["NO_AUTHORITY_ARG", "PROMPT", "CLEAN", "TAINTED", "UNOBSERVED"]
CATS = ["DI", "DIQ", "DD", "DIQ|DD"]


def fides_category(suite, task):
    i = int(task.split("_")[-1])
    cats = [c for c, ids in TABLE5[suite].items() if i in ids]
    return "|".join(cats)


census = list(csv.DictReader(open(sys.argv[1])))
table = collections.Counter((fides_category(r["suite"], r["task"]), r["class"]) for r in census)
assert sum(table.values()) == 97 and all(fides_category(r["suite"], r["task"]) for r in census)
print(f"{'FIDES / census':16s}" + "".join(f"{c:>18s}" for c in CLASSES) + f"{'all':>6s}")
for cat in CATS:
    n = [table[(cat, c)] for c in CLASSES]
    print(f"{cat:16s}" + "".join(f"{x:>18d}" for x in n) + f"{sum(n):>6d}")
for r in census:
    if r["class"] in ("TAINTED", "UNOBSERVED"):
        print(f"  {r['suite']}/{r['task']}: census {r['class']}, FIDES {fides_category(r['suite'], r['task'])}")
