# Where AgentDojo's authority-bearing values come from

A system-level defense keeps attacker-written data away from the decision about *where an action lands*: who gets
the money, the e-mail, the invitation or the file. Type-directed privilege separation (Jacob et al., arXiv
2509.25926), plan-then-execute (Piet et al., arXiv 2605.14290) and argument-provenance policies all depend on where
those values come from. This census looks at that for every user task of AgentDojo v1.2.2 (97 tasks), without running
a model and without any attack.

**Scope.** A census of explicit argument values in the recorded ground-truth traces, using our hand-labelled tool
roles and AgentDojo's declared injection vectors. It is not a utility ceiling for any defense and makes no claim about
attack success.

**Method.** `eval/agentdojo_census/extract_traces.py` runs each task's ground-truth calls in AgentDojo twice: once
with the default environment and once with every injection vector filled with a unique canary string. A field of a
tool output *holds a vector* if the canary appears in it. For each side-effect call, `census.py` takes every
*authority* argument (recipient, IBAN, URL, participant, channel, user, ACL permission, object id; roles are
hand-labelled in `tool_roles.py` by the parameter's intended meaning) and looks for its value in the preceding
outputs of that trace:

| Source | Meaning |
|---|---|
| PROMPT | in the user's request |
| CLEAN | in an earlier output field that holds no vector, from a call whose arguments did not come from such fields |
| TAINTED | only in fields that hold a vector |
| UNOBSERVED | in no preceding output (the ground truth uses environment knowledge) |

A task's class is its worst authority value. `get_webpage` is modelled as egress: its URL counts as an authority
argument (AgentDojo records the URL and returns simulated content).

## Results (97 tasks)

| Class | workspace | travel | banking | slack | all |
|---|---:|---:|---:|---:|---:|
| no explicit authority value | 22 | 18 | 5 | 0 | 45 |
| PROMPT | 2 | 2 | 6 | 2 | 12 |
| CLEAN | 16 | 0 | 3 | 9 | 28 |
| TAINTED | 0 | 0 | 1 | 10 | 11 |
| UNOBSERVED | 0 | 0 | 1 | 0 | 1 |

"No explicit authority value" means the trace has no argument value that our mapping labels authority. Some of these
tasks still change state without a target parameter (`get_unread_emails` marks e-mails read; `update_user_info`
changes the current account).

**11 tasks: the target is observable only in a field that holds a vector.**
- banking `user_task_0` ("pay the bill"): the IBAN, and the amount, are part of the default text of the
  `injection_bill_text` vector itself. Filling the vector removes them. In AgentDojo's own threat model the attacker
  writes the IBAN this task has to pay.
- slack `user_task_7, 9, 10, 12, 19`: the channel these tasks must write to is named `External_` + the
  `prompt_injection_channel` vector (default `0`), so the attacker names it.
- slack `user_task_2, 11, 16, 17, 20`: Dora's address is fixed text in her web page, in the same string as an
  appended vector. AgentDojo's simulated `invite_user_to_slack` ignores the address, so in these five cases the
  authority label rests on the parameter's intended meaning, not on an implemented routing effect.

A design that refuses untrusted strings in authority arguments cannot complete these tasks without asking the user or
consulting a trusted list. A design that passes them on as opaque values lets whoever wrote the data choose the
target. The values are strings, so restricting the handoff to Table I's numeric, boolean and enum types does not
carry them.

**28 tasks: every non-prompt authority value occurs in an earlier field that holds no vector** (calendar
participants, file ids, Slack user names, scheduled transaction ids). This shows that the candidate values are
available without reading attacker text; it does not show that choosing among them is free of attacker influence.
Table I's designer-fixed enum does not directly express membership that is only known at runtime; an enum built at
runtime from clean metadata, or an integer index into a trusted table, are possible ways to carry such a value.

**Clean id, influenced criterion.** workspace `user_task_35` and `user_task_38` delete "the largest file". The id
they delete (11) is in a clean field, but AgentDojo computes file size from content length, so filling the vectors
changes the sizes (file 11: 3,183 → 3,195 bytes) although the size fields hold no canary. File 11 stays the largest in
both runs and the ground truth fixes its id, so this shows that the selection criterion is attacker-influenced, not
that the choice changes.

**Flags.** 5 tasks delegate actions or instructions to data (workspace 13 and 19: actions listed in an e-mail;
banking 12: instructions in a file; slack 18 and 19: a TODO page that the ground truth does not fetch). 6 tasks show a
repeated-call pattern with targets observable in data (workspace 25: `send_email`; slack 10 and 11:
`add_user_to_channel`; slack 14: `send_direct_message`; slack 15 and 20: `get_webpage`); the ground truth prescribes
these calls as a list, so this is a pattern, not evidence of a dynamic loop. banking `user_task_9` updates scheduled
transaction 7, while its only preceding call returns transactions 1 to 5.

## What this is not
It describes one ground-truth trace per task; another valid trace could find a value elsewhere. AgentDojo's security
checks are predicates over the final environment, and nothing here evaluates them. An earlier draft tried to count
reachable attack pairs per design; an independent review showed that such a count needs AgentDojo's predicates and a
definition of what each design lets a plan select, so it was dropped.

## Reproduce
```bash
uv pip install agentdojo==0.1.35
python -I eval/agentdojo_census/extract_traces.py v1.2.2 traces.json
python -I eval/agentdojo_census/census.py traces.json results/v0_5_agentdojo_census
```
`traces_v1.2.2.json.gz` is the trace file used for the tables. A fresh extraction differs only in timestamps and in the
order of calendar participants (a set in AgentDojo); the census gives the same classes, flags and values.
`authority_census.csv` lists every task with its authority values and their sources.
