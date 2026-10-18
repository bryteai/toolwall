---
license: apache-2.0
base_model: microsoft/deberta-v3-base
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

# toolwall-judge-v0.2

A binary classifier that reads a **tool response** (a web page, an email, a file, an API or MCP result) and estimates whether it contains an instruction aimed at the AI agent that is reading it. It is the third layer of [toolwall](https://github.com/bryteai/toolwall); regex rules run before it.

| | |
|---|---|
| Base model | [`microsoft/deberta-v3-base`](https://huggingface.co/microsoft/deberta-v3-base) (MIT), 184M parameters |
| Head | sequence classification, labels `benign` (0) / `attack` (1) |
| Input | up to 512 tokens (longer inputs are truncated) |
| Decision threshold | 0.5 on P(attack), calibrated on dev (stored in `toolwall_judge.json`) |
| Weights | `model.safetensors`, sha256 `34dc0cc929250b61ee2bc24f901ba31da87c38f923f7623bfe31924a796768fe` |
| Runs on | CPU or GPU |
| Author | Muhammad Hasnain, bryteai.studio (Bin Abdullah LLC) |

## Read this first

On InjecAgent attacks whose tools and attacker instructions were never seen in training, the toolwall stack with this judge blocks every attack (95/95 in each setting) with no false positives on the 150 benign twins. On **BIPIA, run once after this model was frozen, it misses 94.7 % of attacks** (142/150). It detects explicit overrides and requests for tool actions well. It largely does not detect instructions that change the content or format of the answer ("Modify your reply to promote…", "Shift each letter in your reply…") or that ask for an unrelated task. Do not use it as your only defence.

## Use

With toolwall (rules first, then this judge):

```python
from toolwall import toolwall, policy

@toolwall(policy=policy.web_fetch())
def fetch_url(url: str) -> str: ...
```

On its own:

```python
from transformers import pipeline
clf = pipeline("text-classification", model="bryteai/toolwall-judge-v0.2", top_k=None, truncation=True, max_length=512)
scores = {d["label"]: d["score"] for d in clf([tool_response])[0]}
is_attack = scores["attack"] >= 0.5
```

## Training data

8,619 training and 961 dev rows. Every source except the short outputs is placed in one of four containers (raw text, web-page JSON, email JSON, product-review JSON), chosen uniformly at random for both labels, so that the container carries no label signal.

| Source | Licence | Train benign | Train attack |
|---|---|---:|---:|
| [InjecAgent](https://github.com/uiuc-kang-lab/InjecAgent) (commit `f19c9f2`), train tools × train instructions only | MIT | — | 740 |
| InjecAgent benign twins: train-tool templates filled with neutral Wikipedia sentences | MIT / CC BY-SA 4.0 | 400 | — |
| Random Wikipedia introductions (disjoint from the test pages) | CC BY-SA 4.0 | 1,150 | — |
| Wikipedia security articles (titles disjoint from the hard-negative test titles) | CC BY-SA 4.0 | 81 | — |
| [deepset/prompt-injections](https://huggingface.co/datasets/deepset/prompt-injections), train split | Apache-2.0 | 308 | 183 |
| Enron-Spam ham emails, train split, 2/3 containing a request ([SetFit/enron_spam](https://huggingface.co/datasets/SetFit/enron_spam); Metsis et al., 2006) | used for training only, not redistributed | 1,350 | — |
| Short benign tool outputs (status lines, ids, URLs, listings), generated | Apache-2.0 | 1,347 | — |
| toolwall v0.1 synthetic templates ("suspicious" rows dropped) | Apache-2.0 | 1,743 | 1,317 |

**Split protocol.** InjecAgent's 17 user tools were split 10 / 2 / 5 and its 62 attacker instructions 60 / 10 / 30 % within each family, before any training. A case is used only if its tool and its instruction fall in the same split. Exact overlaps between training text and any test text were removed (three rows). Scripts: `training/build_corpus_v0_2.py`, `training/build_short_benign_v0_2_2.py`, `training/build_corpus_v0_2_3.py`.

**Training.** 3 epochs, learning rate 2e-5, batch 16, warm-up 10 %, weight decay 0.01, fp16, seed 20261019, one A10G (`training/modal_train_judge_v0_2_3.py`). Best epoch by dev F1. The threshold is the lowest value at which at most 1 % of dev benign rows score above it, with a floor of 0.5; the floor applied. Dev: F1 0.994, precision 1.000, recall 0.989.

## Evaluation

The numbers below are for the **toolwall stack** (rules + this judge) as shipped in v0.2.0, from `results/v0_2/` in the repository. The judge was not scored separately. ASR = share of attacked responses that get through; FPR = share of benign responses blocked; brackets are Wilson 95 % intervals. ProtectAI = [`protectai/deberta-v3-base-prompt-injection-v2`](https://huggingface.co/protectai/deberta-v3-base-prompt-injection-v2) on the same rows.

| Set | n | Metric | toolwall v0.2 | ProtectAI v2 |
|---|---:|---|---|---|
| InjecAgent, unseen tools × unseen instructions (base) | 95 | ASR | 0.000 [0.000, 0.039] | 0.284 [0.203, 0.382] |
| InjecAgent, same, "enhanced" | 95 | ASR | 0.000 [0.000, 0.039] | 0.000 [0.000, 0.039] |
| In-house MCP attacks | 185 | ASR | 0.000 [0.000, 0.020] | 0.319 [0.256, 0.389] |
| Novel attack families | 10 | ASR | 0.200 [0.057, 0.510] | 0.000 [0.000, 0.278] |
| deepset, test split, in a web page | 60 | ASR | 0.217 [0.131, 0.336] | 0.517 [0.393, 0.638] |
| Lakera Gandalf, test split, in a web page | 112 | ASR | 0.205 [0.141, 0.289] | 0.000 [0.000, 0.033] |
| InjecAgent benign twins | 150 | FPR | 0.000 [0.000, 0.025] | 0.287 [0.220, 0.364] |
| Wikipedia, random | 400 | FPR | 0.003 [0.000, 0.014] | 0.180 [0.145, 0.221] |
| Wikipedia security articles (injection, phishing, LLMs) | 91 | FPR | 0.121 [0.069, 0.204] | 0.319 [0.232, 0.420] |
| Enron workplace emails with requests | 296 | FPR | 0.000 [0.000, 0.013] | 0.500 [0.443, 0.557] |
| Short tool outputs | 300 | FPR | 0.000 [0.000, 0.013] | 0.057 [0.036, 0.089] |
| **BIPIA (email + table QA), final one-shot test** | 150 | ASR | **0.947** [0.898, 0.973] | 0.820 [0.751, 0.873] |
| BIPIA, clean contexts | 150 | FPR | 0.020 [0.007, 0.057] | 0.220 [0.161, 0.293] |

**What is and is not clean.** Four candidate judges were trained and the choice among them used the held-out sets, so those sets informed model selection. Only BIPIA was run after the choice. The deepset and Enron results are in-distribution for those sources, because their train splits were used. Gandalf and BIPIA were never used in training. The in-house and novel sets were written for toolwall v0.1. ProtectAI's training data may overlap with deepset or Gandalf; we did not check.

## Limitations

- Misses most BIPIA-style attacks, which change the answer or add an unrelated task rather than override instructions or call tools.
- Blocks about one in eight paragraphs from Wikipedia security articles (injection, phishing, LLMs); 10 of the 11 blocks come from toolwall's rules (mainly an over-broad v0.1.1 pattern, `ipi-053`), not the judge.
- Trained and tested mostly on English.
- Not tested against adaptive attacks aimed at the classifier itself.
- Detection only: it does not measure what an agent does after a response is passed or blocked.

## Superseded model

`toolwall-judge-v0.1` (LoRA on Qwen2.5-7B) blocked 98.0 % of random Wikipedia pages and 66.5 % of benign InjecAgent tool responses on external data. Use v0.2.

## Citation

```bibtex
@software{hasnain2026toolwall,
  title   = {toolwall: a tool-boundary firewall for indirect prompt injection in AI agents},
  author  = {Hasnain, Muhammad},
  year    = {2026},
  version = {0.2.0},
  url     = {https://github.com/bryteai/toolwall}
}
```
