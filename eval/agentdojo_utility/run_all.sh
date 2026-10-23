#!/bin/bash
# Reproduce results/v0_6_agentdojo_utility: benign AgentDojo v1.2.2 runs, no injection task, no attack.
#   uv venv ~/venvs/agentdojo-0.1.35 --python 3.12
#   VIRTUAL_ENV=~/venvs/agentdojo-0.1.35 uv pip install agentdojo==0.1.35 anthropic==0.52.0 pytest
#   DEEPSEEK_API_KEY=... eval/agentdojo_utility/run_all.sh
# anthropic==0.52.0: AgentDojo 0.1.35's AnthropicLLM fails with the 2.x SDK ("Cannot instantiate typing.Union").
set -u
cd "$(dirname "$0")/../.."
PY=${PY:-~/venvs/agentdojo-0.1.35/bin/python}
OUT=results/v0_6_agentdojo_utility/raw
mkdir -p "$OUT"

run() {  # pipeline tag policy repeat
  f=$OUT/$2__$3__r$4.json
  [ -s "$f" ] && return
  $PY -I eval/agentdojo_utility/run_utility.py "$1" "$3" "$f.tmp" > "$OUT/$2__$3__r$4.log" 2>&1 && mv "$f.tmp" "$f"
}

$PY -I -m pytest -q eval/agentdojo_utility/test_policy_runtime.py -p no:cacheprovider || exit 1
for pol in none prompt_only provenance; do run ground_truth ground-truth $pol 1; done
for rep in 1 2 3; do
  for model in deepseek-chat deepseek-reasoner; do
    for pol in none prompt_only provenance; do run "deepseek:$model" "$model" $pol $rep & done
  done
  wait
done
for pol in none provenance; do run deepseek:deepseek-v4-pro deepseek-v4-pro $pol 1 & done   # one repeat (balance)
wait
$PY -I eval/agentdojo_utility/content_sensitivity.py results/v0_6_agentdojo_utility/content_sensitivity.json
python3 -I eval/agentdojo_utility/report.py results/v0_6_agentdojo_utility
