"""Run every AgentDojo user task's ground-truth calls (no LLM, no attack) and record the prompt, the calls,
each tool output (as the model would see it, and as structured data), and which output FIELDS are
attacker-writable: a second run fills every injection vector with a unique canary string."""
import json, sys
from pydantic import BaseModel
from agentdojo.task_suite.load_suites import get_suites
from agentdojo.functions_runtime import FunctionsRuntime
from agentdojo.agent_pipeline.tool_execution import tool_result_to_str

VERSION, OUT = sys.argv[1], sys.argv[2]

def plain(x):
    if isinstance(x, BaseModel):
        return plain(x.model_dump(mode="json"))
    if isinstance(x, dict):
        return {str(k): plain(v) for k, v in x.items()}
    if isinstance(x, (list, tuple)):
        return [plain(v) for v in x]
    if isinstance(x, (str, int, float, bool)) or x is None:
        return x
    return str(x)

def run_calls(suite, ut, injections):
    env = suite.load_and_inject_default_environment(injections)
    calls = ut.ground_truth(env.model_copy(deep=True))
    rt = FunctionsRuntime(suite.tools)
    rows = []
    for c in calls:
        res, err = rt.run_function(env, c.function, dict(c.args), raise_on_error=False)
        rows.append({"function": c.function, "args": dict(c.args), "output": tool_result_to_str(res),
                     "output_struct": plain(res), "error": err})
    return rows

out = []
for sname, suite in get_suites(VERSION).items():
    vecs = suite.get_injection_vector_defaults()
    canary = {v: f"ZQXCANARY{i:03d}" for i, v in enumerate(vecs)}
    for tid, ut in sorted(suite.user_tasks.items(), key=lambda kv: int(kv[0].split("_")[-1])):
        benign = run_calls(suite, ut, {})
        can = run_calls(suite, ut, canary)
        for b, c in zip(benign, can):
            b["exposed_vectors"] = sorted(v for v, tok in canary.items() if tok in (c["output"] or ""))
            b["canary_struct"] = c["output_struct"]
        out.append({"suite": sname, "task": tid, "prompt": ut.PROMPT, "calls": benign})
json.dump(out, open(OUT, "w"), indent=1, default=str)
print("tasks", len(out), "calls", sum(len(t["calls"]) for t in out),
      "errors", sum(1 for t in out for c in t["calls"] if c["error"]),
      "calls exposing a vector", sum(1 for t in out for c in t["calls"] if c["exposed_vectors"]))
