---
base_model: Qwen/Qwen2.5-7B-Instruct
library_name: peft
license: apache-2.0
---

# `toolwall-judge-v0.1` (in-repo adapter artifacts)

The full model card --- training data, dev-set evaluation, in-house
200-case bench numbers, dev-saturation disclosure, MinHash overlap
audit, and the published-vs-spec base-model substitution
(`Qwen/Qwen2.5-7B-Instruct` Apache-2.0 in place of the gated
`meta-llama/Llama-3.1-8B-Instruct`) --- lives at:

- `training/MODEL_CARD.md` in this repository
- `https://huggingface.co/bryteai/toolwall-judge-v0.1` (mirror)

This directory holds only the LoRA adapter weights + tokenizer
artefacts the runtime loads via
`toolwall.detect.judge._resolve_adapter_source` when
`TOOLWALL_JUDGE_LOCAL_PATH` is set or when the default
`models/judge-v0.1/` path is present.

For reproduction, citation, and the full results table, read the
model card and `results/v0.1.md`.
