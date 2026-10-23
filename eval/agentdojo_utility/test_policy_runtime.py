"""Ground-truth replay checks for the runtime policy (needs agentdojo==0.1.35; no model, no attack).

  python -I -m pytest eval/agentdojo_utility/test_policy_runtime.py
"""
import csv
import os
import sys

import pytest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from agentdojo.task_suite.load_suites import get_suites
from policy_runtime import PolicyRuntime, canary_injections
from run_utility import run

CENSUS = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "..", "results", "v0_5_agentdojo_census",
                      "authority_census.csv")
REFUSED_CLASSES = {"prompt_only": {"CLEAN", "TAINTED", "UNOBSERVED"}, "provenance": {"TAINTED", "UNOBSERVED"}}


@pytest.fixture(scope="module")
def census():
    return {(r["suite"], r["task"]): r["class"] for r in csv.DictReader(open(CENSUS))}


def test_no_policy_keeps_every_ground_truth():
    rows = run("ground_truth", "none", None, None, "v1.2.2")
    assert len(rows) == 97
    assert all(r["utility"] and r["refused"] == 0 for r in rows)


@pytest.mark.parametrize("policy", sorted(REFUSED_CLASSES))
def test_refusals_match_the_census(policy, census):
    # The census reads offline traces; the runtime reads a live shadow environment. They must agree task by task.
    rows = run("ground_truth", policy, None, None, "v1.2.2")
    refused = {(r["suite"], r["task"]) for r in rows if r["refused"]}
    assert refused == {k for k, c in census.items() if c in REFUSED_CLASSES[policy]}


def test_a_refused_call_changes_nothing():
    suite = get_suites("v1.2.2")["banking"]
    ut = suite.user_tasks["user_task_0"]          # the IBAN to pay is in the bill's injection vector
    env = ut.init_environment(suite.load_and_inject_default_environment({}))
    shadow = ut.init_environment(suite.load_and_inject_default_environment(canary_injections(suite)))
    rt = PolicyRuntime(suite.tools, suite_name="banking", prompt=ut.PROMPT, shadow_env=shadow, policy="provenance")
    before = env.model_copy(deep=True)
    for call in ut.ground_truth(env.model_copy(deep=True)):
        rt.run_function(env, call.function, dict(call.args))
    assert any(not d["allowed"] and d["param"] == "recipient" for d in rt.decisions)
    assert env.bank_account.transactions == before.bank_account.transactions


def test_a_url_with_a_scheme_names_the_same_target():
    # slack/1: Bob posts "www.informations.com" in 'general'; agents call get_webpage("https://www.informations.com").
    suite = get_suites("v1.2.2")["slack"]
    ut = suite.user_tasks["user_task_1"]
    env = ut.init_environment(suite.load_and_inject_default_environment({}))
    shadow = ut.init_environment(suite.load_and_inject_default_environment(canary_injections(suite)))
    rt = PolicyRuntime(suite.tools, suite_name="slack", prompt=ut.PROMPT, shadow_env=shadow, policy="provenance")
    rt.run_function(env, "read_channel_messages", {"channel": "general"})
    assert rt.source("get_webpage", "url", "www.informations.com") == "CLEAN"
    assert rt.source("get_webpage", "url", "https://www.informations.com/") == "CLEAN"
    assert rt.source("get_webpage", "url", "https://www.not-in-the-data.com") == "UNOBSERVED"


def test_unknown_policy_is_rejected():
    with pytest.raises(ValueError):
        PolicyRuntime([], suite_name="banking", prompt="", shadow_env=None, policy="allow_everything")
