"""Where do the authority values of τ²-bench's gold actions come from? (airline, retail; no model, no attack)

For every task, the gold actions (task.evaluation_criteria.actions) are replayed the way τ²-bench's own environment
evaluator replays them (get_environment + make_tool_call), and each tool output is recorded. For every call to a tool
that τ²-bench marks WRITE, every *authority* value (the account, order, reservation, payment instrument, item, flight,
passenger or shipping address that decides where the effect lands; ROLES below) is looked up:

  USER        in what the simulated user knows and may say: reason_for_call, known_info, task_instructions
  DB_READ     not there, but in an earlier tool output of the same gold action list (a database lookup)
  DB          in neither, but a value of the initial database (τ²-bench lists only some reads among its gold
              actions, so the agent's lookup is implied)
  NOWHERE     in none of these

A task's class is its worst authority value, USER < DB_READ < DB < NOWHERE (NO_WRITE if it has no write call).
τ²-bench has no attacker: every output comes from the company database. The census measures how much a rule that
accepts only user-given authority values would refuse, and so how much any argument-level defense depends on labelling
database fields as trusted.

  python -I eval/tau2_census/census_tau2.py results/v0_6_tau2_census     (needs the tau2 package, MIT, Sierra)
"""
import collections
import csv
import json
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "agentdojo_census"))
from match import leaves, matches, plain

from tau2.domains.airline.environment import get_environment as airline_env
from tau2.domains.airline.environment import get_tasks as airline_tasks
from tau2.domains.retail.environment import get_environment as retail_env
from tau2.domains.retail.environment import get_tasks as retail_tasks
from tau2.environment.toolkit import ToolType

A, C = "authority", "content"
ADDRESS = {"address1": A, "address2": A, "city": A, "state": A, "country": A, "zip": A}   # where goods are shipped
PASSENGER = {"first_name": A, "last_name": A, "dob": A}                                     # who travels
ROLES = {
    ("retail", "cancel_pending_order"): {"order_id": A, "reason": C},
    ("retail", "exchange_delivered_order_items"): {"order_id": A, "item_ids": A, "new_item_ids": A, "payment_method_id": A},
    ("retail", "modify_pending_order_address"): {"order_id": A, **ADDRESS},
    ("retail", "modify_pending_order_items"): {"order_id": A, "item_ids": A, "new_item_ids": A, "payment_method_id": A},
    ("retail", "modify_pending_order_payment"): {"order_id": A, "payment_method_id": A},
    ("retail", "modify_user_address"): {"user_id": A, **ADDRESS},
    ("retail", "return_delivered_order_items"): {"order_id": A, "item_ids": A, "payment_method_id": A},
    ("airline", "book_reservation"): {"user_id": A, "origin": C, "destination": C, "flight_type": C, "cabin": C,
                                      "flights": {"flight_number": A, "date": C}, "passengers": PASSENGER,
                                      "payment_methods": {"payment_id": A, "amount": C}, "total_baggages": C,
                                      "nonfree_baggages": C, "insurance": C},
    ("airline", "cancel_reservation"): {"reservation_id": A},
    ("airline", "send_certificate"): {"user_id": A, "amount": C},
    ("airline", "update_reservation_baggages"): {"reservation_id": A, "total_baggages": C, "nonfree_baggages": C,
                                                 "payment_id": A},
    ("airline", "update_reservation_flights"): {"reservation_id": A, "cabin": C, "flights": {"flight_number": A, "date": C},
                                                "payment_id": A},
    ("airline", "update_reservation_passengers"): {"reservation_id": A, "passengers": PASSENGER},
}
ORDER = ["USER", "DB_READ", "DB", "NOWHERE"]


def authority_values(role, value, path):
    """(path, leaf) for every leaf of value that the role marks as authority."""
    if isinstance(role, dict):
        items = value if isinstance(value, list) else [value]
        for i, item in enumerate(items):
            for k, sub in role.items():
                if isinstance(item, dict) and k in item:
                    yield from authority_values(sub, item[k], f"{path}[{i}].{k}")
    elif role == A:
        for leaf in (value if isinstance(value, list) else [value]):
            if leaf is not None and str(leaf) != "":
                yield path, leaf


def db_values(env):
    return {str(v).strip().lower() for v in leaves(plain(env.tools.db)) if v is not None}


def analyse(domain, task, env):
    db = db_values(env)
    ins = task.user_scenario.instructions
    user_text = " ".join(str(getattr(ins, k, "") or "") for k in ("reason_for_call", "known_info", "task_instructions"))
    outputs, rows = [], []
    for i, action in enumerate(task.evaluation_criteria.actions or []):
        write = env.tools.has_tool(action.name) and env.tools.tool_type(action.name) == ToolType.WRITE
        if write:
            roles = ROLES.get((domain, action.name))
            if roles is None:
                raise KeyError(f"no roles for write tool {domain}/{action.name}")
            for param, value in action.arguments.items():
                for path, v in authority_values(roles.get(param, C), value, param):
                    if matches(v, user_text):
                        src = "USER"
                    elif any(leaf is not None and matches(v, leaf) for out in outputs for leaf in leaves(out)):
                        src = "DB_READ"
                    elif str(v).strip().lower() in db:
                        src = "DB"
                    else:
                        src = "NOWHERE"
                    rows.append({"call": i, "tool": action.name, "param": path, "value": str(v)[:80], "source": src})
        try:
            out = env.make_tool_call(tool_name=action.name, requestor=action.requestor, **action.arguments)
            outputs.append(plain(out))
        except Exception as e:      # as in tau2's evaluator, a failing gold action is logged and the replay goes on
            outputs.append({"error": f"{type(e).__name__}: {e}"})
    return rows


def main():
    out_dir = sys.argv[1]
    os.makedirs(out_dir, exist_ok=True)
    per_task = []
    for domain, get_env, get_tasks in (("airline", airline_env, airline_tasks), ("retail", retail_env, retail_tasks)):
        for task in get_tasks(None):
            rows = analyse(domain, task, get_env())
            worst = max((ORDER.index(r["source"]) for r in rows), default=-1)
            per_task.append({
                "domain": domain, "task": task.id,
                "class": ORDER[worst] if rows else "NO_WRITE",
                "write_calls": len({r["call"] for r in rows}),
                "authority_values": "; ".join(f"{r['tool']}.{r['param']}={r['value']}[{r['source']}]" for r in rows),
            })
    with open(os.path.join(out_dir, "tau2_authority_census.csv"), "w", newline="") as f:
        w = csv.DictWriter(f, fieldnames=list(per_task[0]))
        w.writeheader()
        w.writerows(per_task)
    classes = ["NO_WRITE", *ORDER]
    summary = {d: collections.Counter(r["class"] for r in per_task if r["domain"] == d) for d in ("airline", "retail")}
    json.dump({d: dict(c) for d, c in summary.items()}, open(os.path.join(out_dir, "tau2_authority_census.json"), "w"),
              indent=1)
    print(f"{'class':12s}{'airline':>9s}{'retail':>9s}{'all':>6s}")
    values = collections.Counter(part.rsplit("[", 1)[-1].rstrip("]") for r in per_task
                                 for part in r["authority_values"].split("; ") if part)
    for c in classes:
        a, r = summary["airline"][c], summary["retail"][c]
        print(f"{c:12s}{a:>9d}{r:>9d}{a + r:>6d}")
    print("authority values by source:", dict(values))


main()
