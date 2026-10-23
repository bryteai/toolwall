"""Benign utility of AgentDojo v1.2.2 user tasks under an authority policy: no injection task, no attack.

  python -I eval/agentdojo_utility/run_utility.py ground_truth provenance out.json
  python -I eval/agentdojo_utility/run_utility.py openai:gpt-4o-mini-2024-07-18 prompt_only out.json --suite banking

`ground_truth` replays each task's prescribed calls through the policy, so its utility is what the policy leaves of a
perfect agent. `openai:<model>`, `deepseek:<model>` (DeepSeek's OpenAI-compatible API) and `anthropic:<model>` run
AgentDojo's default pipeline (default system message, temperature 0) with that model and count its tokens. Utility is
AgentDojo's own check.
"""
import argparse
import collections
import json
import os
import sys

from agentdojo.agent_pipeline.agent_pipeline import AgentPipeline, PipelineConfig
from agentdojo.agent_pipeline.ground_truth_pipeline import GroundTruthPipeline
from agentdojo.agent_pipeline.llms.openai_llm import OpenAILLM
from agentdojo.task_suite.load_suites import get_suites

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from policy_runtime import POLICIES, make_runtime

USAGE = collections.Counter()


def openai_llm(model_name, base_url=None, api_key=None, developer_as_system=False):
    import openai
    client = openai.OpenAI(base_url=base_url, api_key=api_key)
    create = client.chat.completions.create

    def counted(*args, **kwargs):
        if developer_as_system:     # AgentDojo sends the system message as role "developer"; DeepSeek knows "system"
            kwargs["messages"] = [{**m, "role": "system"} if m.get("role") == "developer" else m
                                  for m in kwargs["messages"]]
        response = create(*args, **kwargs)
        USAGE["requests"] += 1
        if response.usage is not None:
            USAGE["prompt_tokens"] += response.usage.prompt_tokens
            USAGE["completion_tokens"] += response.usage.completion_tokens
        return response

    client.chat.completions.create = counted
    return OpenAILLM(client, model_name)


def anthropic_llm(model_name):
    import anthropic
    from agentdojo.agent_pipeline.llms import anthropic_llm as module
    request = module.chat_completion_request

    async def counted(*args, **kwargs):
        message = await request(*args, **kwargs)
        USAGE["requests"] += 1
        USAGE["prompt_tokens"] += message.usage.input_tokens
        USAGE["completion_tokens"] += message.usage.output_tokens
        return message

    module.chat_completion_request = counted
    return module.AnthropicLLM(anthropic.AsyncAnthropic(), model_name)


def model_pipeline(spec):
    provider, _, name = spec.partition(":")
    if provider == "openai":
        llm = openai_llm(name)
    elif provider == "deepseek":
        llm = openai_llm(name, base_url="https://api.deepseek.com", api_key=os.environ["DEEPSEEK_API_KEY"],
                         developer_as_system=True)
    elif provider == "anthropic":
        llm = anthropic_llm(name)
    else:
        raise ValueError(f"unknown pipeline {spec!r}: use ground_truth, openai:, deepseek: or anthropic:<model>")
    pipeline = AgentPipeline.from_config(PipelineConfig(llm=llm, model_id=None, defense=None, system_message_name=None,
                                                        system_message=None))
    pipeline.name = spec
    return pipeline


def run(pipeline_name, policy, suites, tasks, version):
    model = None if pipeline_name == "ground_truth" else model_pipeline(pipeline_name)
    rows = []
    for sname, suite in get_suites(version).items():
        if suites and sname not in suites:
            continue
        for tid, ut in sorted(suite.user_tasks.items(), key=lambda kv: int(kv[0].split("_")[-1])):
            if tasks and tid not in tasks:
                continue
            factory, holder = make_runtime(suite, ut, policy)
            pipeline = GroundTruthPipeline(ut) if model is None else model
            before = USAGE.copy()
            utility, _ = suite.run_task_with_pipeline(pipeline, ut, injection_task=None, injections={},
                                                      runtime_class=factory)
            decisions = holder["runtime"].decisions
            rows.append({"suite": sname, "task": tid, "pipeline": pipeline_name, "policy": policy, "version": version,
                         "utility": bool(utility), "refused": sum(not d["allowed"] for d in decisions),
                         "decisions": decisions, "usage": dict(USAGE - before)})
    return rows


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("pipeline")
    ap.add_argument("policy", choices=POLICIES)
    ap.add_argument("out")
    ap.add_argument("--suite", action="append")
    ap.add_argument("--task", action="append")
    ap.add_argument("--version", default="v1.2.2")
    a = ap.parse_args()
    rows = run(a.pipeline, a.policy, a.suite, a.task, a.version)
    json.dump(rows, open(a.out, "w"), indent=1)
    by = collections.defaultdict(lambda: [0, 0, 0])
    for r in rows:
        by[r["suite"]][0] += r["utility"]
        by[r["suite"]][1] += 1
        by[r["suite"]][2] += r["refused"] > 0
    for s, (u, n, ref) in by.items():
        print(f"{s:10s} utility {u:3d}/{n:<3d} tasks with a refused call {ref}")
    print(f"{'all':10s} utility {sum(v[0] for v in by.values()):3d}/{sum(v[1] for v in by.values()):<3d}"
          f" tasks with a refused call {sum(v[2] for v in by.values())}")
    if USAGE:
        print("usage", dict(USAGE))


if __name__ == "__main__":
    main()
