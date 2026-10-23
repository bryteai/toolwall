"""An authority policy enforced inside AgentDojo's FunctionsRuntime, for benign (no-attack) utility runs.

Before a side-effect call runs, every authority argument (the recipient, IBAN, URL, participant, channel or object id
that decides where the effect lands; ../agentdojo_census/tool_roles.py) must be observable in an allowed source:

  none          no check (the undefended baseline)
  prompt_only   the user's request
  provenance    the user's request, or an earlier tool-output field that holds no injection vector, produced by a
                call whose own arguments did not come only from such fields (the census's CLEAN)

A refused call does not run; the agent receives an error and may go on. Which output fields can hold attacker text is
read from a shadow copy of the task environment with every injection vector filled with a canary: each executed call
also runs there, and a leaf is attacker-writable if the shadow output holds a canary at the same place. The shadow
uses the benchmark's declared vectors, an oracle a deployed system does not have; prompt_only needs no such labels.
Free text the agent writes (a message body, a file's content) goes into the shadow marked as attacker text, so a value
the agent copies out of a vector field and reads back later stays TAINTED.
"""
import os
import sys

from agentdojo.functions_runtime import FunctionsRuntime

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "agentdojo_census"))
from match import CANARY, MANUAL_SOURCE, authority_items, fields, in_prompt, matches, plain, variants
from tool_roles import SIDE_EFFECT

POLICIES = ("none", "prompt_only", "provenance")
SOURCES = ["PROMPT", "CLEAN", "TAINTED", "UNOBSERVED"]
ALLOWED = {"none": None, "prompt_only": {"PROMPT"}, "provenance": {"PROMPT", "CLEAN"}}
TEXT_CONTENT = {"body", "subject", "title", "description", "content"}   # free text the agent composes


def canary_injections(suite):
    return {v: f"{CANARY}{i:03d}" for i, v in enumerate(suite.get_injection_vector_defaults())}


class PolicyRuntime(FunctionsRuntime):
    def __init__(self, functions, *, suite_name, prompt, shadow_env, policy):
        super().__init__(functions)
        if policy not in POLICIES:
            raise ValueError(f"unknown policy {policy!r}")
        self.suite_name, self.prompt, self.shadow_env, self.policy = suite_name, prompt, shadow_env, policy
        self.records = []      # per executed call: (benign output, shadow output, an argument came only from attacker text)
        self.decisions = []    # per authority value of a side-effect call: what the policy saw and did

    def source(self, function, param, value):
        """PROMPT, CLEAN, TAINTED or UNOBSERVED, as in the census; the best over the value's spellings (match.variants),
        which all name the same target."""
        return min((self._source(function, param, v) for v in variants(value)), key=SOURCES.index)

    def _source(self, function, param, value):
        if (function, param, value) in MANUAL_SOURCE:
            return MANUAL_SOURCE[(function, param, value)]
        if in_prompt(value, self.prompt):
            return "PROMPT"
        clean = tainted = False
        for out, shadow, bad_args in self.records:
            for _, leaf, writable, _ in fields(out, shadow):
                if leaf is None or not matches(value, leaf):
                    continue
                if writable or bad_args:
                    tainted = True
                else:
                    clean = True
        return "CLEAN" if clean else ("TAINTED" if tainted else "UNOBSERVED")

    def run_function(self, env, function, kwargs, raise_on_error=False):
        roles = SIDE_EFFECT.get((self.suite_name, function), {})
        bad_args, refused = False, []
        for param, val in (kwargs or {}).items():
            for v in authority_items(param, val):
                src = self.source(function, param, v)
                bad_args |= src == "TAINTED"
                if roles.get(param) == "authority":
                    ok = ALLOWED[self.policy] is None or src in ALLOWED[self.policy]
                    self.decisions.append({"tool": function, "param": param, "value": str(v)[:80], "source": src,
                                           "allowed": ok})
                    if not ok:
                        refused.append(param)
        if refused:
            names = ", ".join(sorted(set(refused)))
            return "", (f"PolicyViolation: the value of {names} is not from the user's request"
                        + ("" if self.policy == "prompt_only" else " or from trusted tool output")
                        + ". The call was not executed.")
        # A tool error goes back to the agent instead of ending the run: after a refusal the ground-truth replay calls
        # tools on state the refused call never created ("User Dora not found"), as an agent might.
        result, error = super().run_function(env, function, kwargs, raise_on_error=False)
        # slack/20: an agent posted a web page's text, with the address from its vector, to a channel and read the
        # channel back; unmarked, the address then counted as CLEAN.
        shadow_kwargs = {p: f"{CANARY}{v}" if roles.get(p) == "content" and p in TEXT_CONTENT and isinstance(v, str)
                         else v for p, v in (kwargs or {}).items()}
        shadow, _ = super().run_function(self.shadow_env, function, shadow_kwargs, raise_on_error=False)
        self.records.append((plain(result), plain(shadow), bad_args))
        return result, error


def make_runtime(suite, user_task, policy):
    """A runtime_class for TaskSuite.run_task_with_pipeline, holding the prompt and the shadow environment."""
    shadow_env = user_task.init_environment(suite.load_and_inject_default_environment(canary_injections(suite)))
    holder = {}

    def factory(functions):
        holder["runtime"] = PolicyRuntime(functions, suite_name=suite.name, prompt=user_task.PROMPT,
                                          shadow_env=shadow_env, policy=policy)
        return holder["runtime"]

    return factory, holder
