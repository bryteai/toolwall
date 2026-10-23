"""Which AgentDojo utility checks never look at what the agent wrote? (ground-truth replay; no model, no attack)

Each task's ground-truth calls are replayed with every *content* argument of a side-effect call (body, subject,
title, description, content; tool_roles.py) replaced by "N/A". A task whose utility check still passes does not
verify that content: an agent that sends an empty summary, or the wrong one, is scored as successful.

  python -I eval/agentdojo_utility/content_sensitivity.py results/v0_6_agentdojo_utility/content_sensitivity.json
"""
import json
import os
import sys

from agentdojo.agent_pipeline.ground_truth_pipeline import GroundTruthPipeline
from agentdojo.functions_runtime import FunctionsRuntime
from agentdojo.task_suite.load_suites import get_suites

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "agentdojo_census"))
from tool_roles import SIDE_EFFECT

PLACEHOLDER = "N/A"
TEXT_CONTENT = {"body", "subject", "title", "description", "content"}   # free text the agent composes


class BlankContentRuntime(FunctionsRuntime):
    def __init__(self, functions, suite_name):
        super().__init__(functions)
        self.suite_name, self.blanked = suite_name, []

    def run_function(self, env, function, kwargs, raise_on_error=False):
        roles = SIDE_EFFECT.get((self.suite_name, function), {})
        kwargs = dict(kwargs)
        for p, role in roles.items():
            if role == "content" and p in TEXT_CONTENT and kwargs.get(p):
                kwargs[p] = PLACEHOLDER
                self.blanked.append(f"{function}.{p}")
        return super().run_function(env, function, kwargs, raise_on_error=False)


def main():
    rows = []
    for sname, suite in get_suites("v1.2.2").items():
        for tid, ut in sorted(suite.user_tasks.items(), key=lambda kv: int(kv[0].split("_")[-1])):
            holder = {}

            def factory(functions, sname=sname, holder=holder):
                holder["rt"] = BlankContentRuntime(functions, sname)
                return holder["rt"]

            utility, _ = suite.run_task_with_pipeline(GroundTruthPipeline(ut), ut, injection_task=None, injections={},
                                                      runtime_class=factory)
            blanked = holder["rt"].blanked
            if blanked:
                rows.append({"suite": sname, "task": tid, "blanked": blanked, "utility_with_blank_content": bool(utility),
                             "prompt": " ".join(ut.PROMPT.split())[:200]})
    json.dump(rows, open(sys.argv[1], "w"), indent=1)
    insensitive = [r for r in rows if r["utility_with_blank_content"]]
    print(f"tasks whose ground truth writes free text: {len(rows)}; still pass with every such text set to "
          f"{PLACEHOLDER!r}: {len(insensitive)}")
    for r in insensitive:
        print(f"  {r['suite']}/{r['task']}: {sorted(set(r['blanked']))} | {r['prompt'][:110]}")


main()
