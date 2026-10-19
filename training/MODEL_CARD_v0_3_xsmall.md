---
license: apache-2.0
base_model: microsoft/deberta-v3-xsmall
language:
- en
pipeline_tag: text-classification
library_name: transformers
tags:
- prompt-injection
- indirect-prompt-injection
- ai-agents
- security
---

# toolwall-judge-v0.3-xsmall

The faster variant of [`bryteai/toolwall-judge-v0.3`](https://huggingface.co/bryteai/toolwall-judge-v0.3): same training data, windowing and threshold, on [`microsoft/deberta-v3-xsmall`](https://huggingface.co/microsoft/deberta-v3-xsmall) (MIT), 71M parameters. Read the v0.3 card for the data, protocol, comparison with other guards and limitations; this card lists only what differs.

| | |
|---|---|
| Weights | `model.safetensors`, sha256 `aa1705ca447955ce8e90bd74c29355cbc1e1073f73e9248110d2c181dd8fb138` |
| Training | 3 epochs, learning rate 6e-5, batch 16, bf16, seed 20261020, one A10G, 22 minutes |
| Use | `TOOLWALL_JUDGE=v0.3-xsmall` with `pip install "toolwall-guard[judge]"` |

**Why it ships.** A rule written in our notes before the small models' results were seen: a fast variant ships only if, on dev data, TPR ≥ 0.97 at FPR ≤ 1 %, at least 75/80 attacks are caught with 1,000 benign characters before them, and at most 2/80 benign inputs are flagged. xsmall: dev AUROC 0.9997, TPR 0.991 at FPR 0.009, 80/80, 0/80. DeBERTa-v3-small also passed; the rule did not say how to choose between two passing models, and we took the smaller one.

**Final tests** (one run). LLMail-Inject and LongPIBench were run with a task (the user's request; LongPIBench's system prompt), BIPIA without one. toolwall's default, no task, was not run on LLMail-Inject for this variant.

| Set | Detection | False alarms |
|---|---|---|
| LLMail-Inject | 0.807 [0.781, 0.830] (807/1,000) | 0.004 [0.001, 0.012] (3/703) |
| BIPIA test | 0.807 [0.736, 0.862] (121/150) | 0.020 [0.007, 0.057] (3/150) |
| LongPIBench, system prompt as task | 1.000 (1,200/1,200) | **1.000** (400/400): unusable this way |

**CPU latency** (rules + judge, AMD Ryzen 5 4500U, 6 cores, median of 10): 500 characters 0.10 s; 2,000 0.66 s; 8,000 3.5 s; 32,000 13 s. About 2.5 times faster than v0.3.
