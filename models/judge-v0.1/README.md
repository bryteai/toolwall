---
base_model: Qwen/Qwen2.5-7B-Instruct
library_name: peft
license: apache-2.0
---

# `toolwall-judge-v0.1` (in-repo adapter artifacts)

> **Superseded by `toolwall-judge-v0.2` (October 2026).** On held-out external data this
> v0.1 adapter blocked 98.0 % of random Wikipedia pages (392/400) and 66.5 % of benign
> InjecAgent tool responses (701/1,054); its in-house numbers were in-distribution.
> See `results/external_v0_2/` and the v0.2.0 entry in `CHANGELOG.md`. It is kept only
> for reproducibility and loads only when `TOOLWALL_JUDGE_LOCAL_PATH` points at it.

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
