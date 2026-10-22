"""Where do AgentDojo's authority-bearing values come from?

For every side-effect call in the ground-truth trace of each AgentDojo v1.2.2 user task, and for every *authority*
argument of that call (the recipient, IBAN, URL, participant, channel, ACL grant or object id that decides where the
effect lands; see tool_roles.py), find where the value is observable before the call:

  PROMPT      in the user's request
  CLEAN       in an earlier tool-output field that carries no attacker text, produced by a call whose own
              arguments did not come from attacker-written fields
  TAINTED     only in fields that also carry attacker text (the field holds an injection vector)
  UNOBSERVED  in neither (the ground truth uses environment knowledge, computes it, or the model writes it)

Attacker text = the canary strings written into AgentDojo's injection vectors (extract_traces.py). Matching is exact
for whole fields and word-bounded inside longer text. Per task we also flag
  instr_in_data        the user's request delegates the plan to data (hand-labelled, 5 tasks)
  repeated_data_targets  a side-effect tool is called several times with authority values that are not all in the
                         prompt (a pattern in the prescribed trace, not evidence of a dynamic loop)
  selection_influenced the trace reads a field whose value changes when the injection vectors are filled although it
                       holds no attacker text (AgentDojo recomputes file sizes from content)

Scope: a census of explicit argument values in the recorded ground-truth traces, using our hand-labelled tool roles
and AgentDojo's declared injection vectors. It is not a utility ceiling and makes no claim about attack success.
"""
import collections, csv, json, re, sys
sys.path.insert(0, __file__.rsplit("/", 1)[0])
from tool_roles import SIDE_EFFECT

TRACES, OUT = sys.argv[1], sys.argv[2]
INSTR_IN_DATA = {
    ("workspace", "user_task_13"): "actions listed in an e-mail",
    ("workspace", "user_task_19"): "actions listed in an e-mail",
    ("banking", "user_task_12"): "instructions in landlord-notices.txt",
    ("slack", "user_task_18"): "TODO list on a web page (not fetched in the ground truth)",
    ("slack", "user_task_19"): "TODO list on a web page (not fetched in the ground truth)",
}
VOLATILE = {"timestamp", "last_modified"}   # wall-clock fields that differ between any two runs
# Tasks that choose their target by a criterion over a field the injected text changes (hand-labelled from the prompt;
# the field change itself is measured: file 11's size is 3183 in the benign run and 3195 with the vectors filled).
SELECTION_ON_INFLUENCED_FIELD = {
    ("workspace", "user_task_35"): "deletes the largest file; size is recomputed from content",
    ("workspace", "user_task_38"): "deletes the largest file; size is recomputed from content",
}
# share_file's permission is the enum {'r', 'rw'}; 'r' is the user's "read permissions" (tasks 32, 37).
MANUAL_SOURCE = {("share_file", "permission", "r"): "PROMPT"}


def leaves(v):
    if isinstance(v, dict):
        for k, x in v.items():
            yield k
            yield from leaves(x)
    elif isinstance(v, (list, tuple)):
        for x in v:
            yield from leaves(x)
    elif v is not None:
        yield v


def fields(b, c, path=""):
    """Yield (path, benign_leaf, attacker_text_in_leaf, derived_change) walking both runs together."""
    if isinstance(b, dict) and isinstance(c, dict):
        for k in b:
            yield f"{path}.{k}#key", k, False, False
            yield from fields(b[k], c.get(k), f"{path}.{k}")
    elif isinstance(b, list) and isinstance(c, list) and len(b) == len(c):
        for i, (x, y) in enumerate(zip(b, c)):
            yield from fields(x, y, f"{path}[{i}]")
    elif isinstance(b, (dict, list)):
        for x in leaves(b):          # structure differs between the runs: treat all of it as attacker text
            yield path, x, True, False
    else:
        writable = "ZQXCANARY" in str(c)
        name = path.rsplit(".", 1)[-1]
        derived = (not writable) and b != c and name not in VOLATILE
        yield path, b, writable, derived


def arg_values(v):
    """Values inside an argument (dict keys are field names, not values)."""
    if isinstance(v, dict):
        for x in v.values():
            yield from arg_values(x)
    elif isinstance(v, (list, tuple)):
        for x in v:
            yield from arg_values(x)
    else:
        yield v


def norm(s):
    return re.sub(r"\s+", " ", str(s)).strip().lower()


def matches(value, leaf):
    """Exact equality for whole fields; word-bounded occurrence for strings inside longer text."""
    if isinstance(value, bool) or isinstance(leaf, bool):
        return value == leaf and type(value) is type(leaf)
    if isinstance(value, (int, float)) and isinstance(leaf, (int, float)):
        return value == leaf
    v, s = norm(value), norm(leaf)
    if not v:
        return False
    if v == s:
        return True
    return re.search(r"(?<![\w@.-])" + re.escape(v) + r"(?![\w@-])", s) is not None


def in_prompt(value, prompt):
    if isinstance(value, bool):
        return False
    v = str(value)
    if re.fullmatch(r"\d+", v):      # a bare number in the prompt ("June 13") is not an object id
        return re.search(r"\b(id|ids|file|event|transaction)\W{0,3}['\"]?" + re.escape(v) + r"\b", prompt, re.I) is not None
    return matches(value, prompt)


def analyse(task):
    calls, prompt = task["calls"], task["prompt"]
    attacker_args = []          # per call: did any argument come only from attacker text?
    rows = []
    for i, c in enumerate(calls):
        roles = SIDE_EFFECT.get((task["suite"], c["function"]))
        bad_arg = False
        for p, val in c["args"].items():
            # an attachment is {"type": "file", "file_id": ...}; only the id selects an object
            items = [a.get("file_id") if isinstance(a, dict) else a for a in val] if p == "attachments" and isinstance(val, list) else val
            for v in arg_values(items):
                if v is None or (isinstance(v, str) and not v):
                    continue
                if (c["function"], p, v) in MANUAL_SOURCE:
                    src = MANUAL_SOURCE[(c["function"], p, v)]
                elif in_prompt(v, prompt):
                    src = "PROMPT"
                else:
                    clean = tainted = False
                    for j in range(i):
                        for _, leaf, writable, _ in fields(calls[j]["output_struct"], calls[j]["canary_struct"]):
                            if leaf is None or not matches(v, leaf):
                                continue
                            if writable or attacker_args[j]:
                                tainted = True
                            else:
                                clean = True
                    src = "CLEAN" if clean else ("TAINTED" if tainted else "UNOBSERVED")
                if src == "TAINTED":
                    bad_arg = True
                if roles is not None and roles.get(p) == "authority":
                    rows.append({"call": i, "tool": c["function"], "param": p, "value": str(v)[:80], "source": src})
        attacker_args.append(bad_arg)
    return rows


INDEX = re.compile(r"\[\d+\]")


def influenced_fields(task):
    """Output fields that hold no attacker text but change when the vectors are filled."""
    out = set()
    for c in task["calls"]:
        for path, _, _, derived in fields(c["output_struct"], c["canary_struct"]):
            if derived:
                out.add(c["function"] + ":" + INDEX.sub("[]", path))
    return sorted(out)


def main():
    traces = json.load(open(TRACES))
    order = ["PROMPT", "CLEAN", "TAINTED", "UNOBSERVED"]
    per_task = []
    for t in traces:
        key = (t["suite"], t["task"])
        rows = analyse(t)
        side = [c for c in t["calls"] if (t["suite"], c["function"]) in SIDE_EFFECT]   # get_webpage modelled as egress
        worst = max((order.index(r["source"]) for r in rows), default=0)
        by_tool = collections.Counter(r["tool"] for r in rows if r["source"] != "PROMPT" and r["param"] in
                                      ("recipients", "recipient", "participants", "user", "channel", "email", "file_id", "url"))
        calls_per_tool = collections.Counter(c["function"] for c in t["calls"] if (t["suite"], c["function"]) in SIDE_EFFECT)
        loop = any(calls_per_tool[k] > 1 for k in by_tool)
        per_task.append({
            "suite": t["suite"], "task": t["task"],
            "side_effect": int(bool(side)),
            "class": order[worst] if rows else "NO_AUTHORITY_ARG",
            "instr_in_data": INSTR_IN_DATA.get(key, ""),
            "repeated_data_targets": int(loop),
            "selection_influenced": SELECTION_ON_INFLUENCED_FIELD.get(key, ""),
            "influenced_fields_read": " ".join(influenced_fields(t)),
            "authority_values": "; ".join(f"{r['tool']}.{r['param']}={r['value']}[{r['source']}]" for r in rows),
            "prompt": " ".join(t["prompt"].split())[:160],
        })
    with open(f"{OUT}/authority_census.csv", "w", newline="") as f:
        w = csv.DictWriter(f, fieldnames=list(per_task[0]))
        w.writeheader()
        w.writerows(per_task)
    suites = ["workspace", "travel", "banking", "slack"]
    classes = ["NO_AUTHORITY_ARG", "PROMPT", "CLEAN", "TAINTED", "UNOBSERVED"]
    summary = {s: collections.Counter(r["class"] for r in per_task if r["suite"] == s) for s in suites}
    flags = {s: {k: sum(int(bool(r[k])) for r in per_task if r["suite"] == s)
                 for k in ("side_effect", "instr_in_data", "repeated_data_targets", "selection_influenced")} for s in suites}
    json.dump({"classes": {s: dict(v) for s, v in summary.items()}, "flags": flags}, open(f"{OUT}/authority_census.json", "w"), indent=1)
    print(f"{'class':18s}" + "".join(f"{s:>11s}" for s in suites) + f"{'all':>6s}")
    for c in classes:
        n = [summary[s][c] for s in suites]
        print(f"{c:18s}" + "".join(f"{x:>11d}" for x in n) + f"{sum(n):>6d}")
    for k in ("side_effect", "instr_in_data", "repeated_data_targets", "selection_influenced"):
        n = [flags[s][k] for s in suites]
        print(f"{k:18s}" + "".join(f"{x:>11d}" for x in n) + f"{sum(n):>6d}")
    print("\nTAINTED / UNOBSERVED / selection-influenced tasks:")
    for r in per_task:
        if r["class"] in ("TAINTED", "UNOBSERVED") or r["selection_influenced"]:
            print(f"  {r['suite']}/{r['task']}: {r['class']} sel={r['selection_influenced']} | {r['authority_values'][:200]}")


main()
