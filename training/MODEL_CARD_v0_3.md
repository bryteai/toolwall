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

# toolwall-judge-v0.3

A binary classifier that reads a **tool response** (a web page, an email, a file, an API or MCP result) and estimates whether it contains an instruction aimed at the AI agent that reads it. It is the last layer of [toolwall](https://github.com/bryteai/toolwall); regex rules run before it.

v0.3 fixes the main weakness of v0.2: v0.2 read only the first 512 tokens and learned that long text is benign, so about 1,000 benign characters around an attack hid it. v0.3 scores the whole response in overlapping windows and was trained on attacks hidden inside long benign documents.

| | |
|---|---|
| Base model | [`microsoft/deberta-v3-base`](https://huggingface.co/microsoft/deberta-v3-base) (MIT), 184M parameters |
| Head | sequence classification, labels `benign` (0) / `attack` (1) |
| Input | any length: windows of 512 tokens with a stride of 256; the score is the highest window score |
| Optional task | the user's request, as `[CLS] task [SEP] window [SEP]` (at most 64 tokens). **Default: no task.** See "Task" below |
| Decision threshold | 0.5 on P(attack), the lowest value with at most 1 % false alarms on dev (stored in `toolwall_judge.json`) |
| Weights | `model.safetensors`, sha256 `b4df0319a7e0e0db0599bfe87dfabe3a29736b299377df7f4c32d3e5c3807d72` |
| Faster variant | [`bryteai/toolwall-judge-v0.3-xsmall`](https://huggingface.co/bryteai/toolwall-judge-v0.3-xsmall), about 2.5 times faster on CPU |
| Author | Muhammad Hasnain, bryteai.studio (Bin Abdullah LLC) |

## Read this first

All numbers below come from one run on test sets that were frozen before training and never used to choose the model. Detection = share of attacked responses blocked; false alarms = share of benign responses blocked; Wilson 95 % intervals.

- **LLMail-Inject** (500 attacks written by people that got past Microsoft's defended email assistant): the toolwall stack with this judge blocks **82.2 %** of attacked inputs with **0 of 703** benign inputs blocked. The best other open guard we ran, PIGuard, blocks 44.9 % with 3.7 % false alarms.
- **BIPIA** test split: **78.0 %** detection with 1 false alarm in 150 (v0.2: 5.3 %). PIGuard is better here: 94.7 %.
- **LongPIBench** (long papers, résumés, emails and code with one attack inside): **this judge fails, like every guard we ran.** Only the "combined" attack is caught reliably. For naive and authority-spoof attacks, guards flag attacked and clean documents at similar rates, and toolwall blocks 31.0 % of clean documents (most of those false alarms come from toolwall's rules, not this judge).

Do not use it as your only defence. It has not been tested against attacks crafted against it.

## Use

With toolwall (rules first, then this judge; `pip install "toolwall-guard[judge]"`):

```python
from toolwall import toolwall, policy

@toolwall(policy=policy.web_fetch())
def fetch_url(url: str) -> str: ...
```

The windowing must match training, so use toolwall's wrapper rather than a plain `pipeline`:

```python
from toolwall.detect import judge
hit = judge.score(tool_response)              # None = below threshold, else a Detection
if hit:
    print(hit.score, hit.span, hit.evidence["p_attack"])   # span = characters of the most suspicious window
```

`TOOLWALL_JUDGE=v0.3-xsmall` selects the faster variant; `TOOLWALL_JUDGE=v0.2` the previous judge.

## Task

Training rows carried the user's request 76 % of the time (median 12 tokens, for example "Summarize the latest emails for me."). The task did **not** improve any final test: on LLMail-Inject detection was 80.9 % with the task and 82.2 % without, both with 0 false alarms. With LongPIBench's system prompts as the task (51–111 tokens, written as "You are a careful, impartial peer reviewer…"), the judge flagged **97.5 % of clean documents**. Pass a short user request or nothing; never the agent's system prompt. toolwall's decorator and proxy pass no task.

## Training data

21,880 training and 2,630 dev rows (`training/build_corpus_v0_3.py`). Every row has a character span for its attack, so each 512-token window is labelled attack only if it holds at least 60 % of the attack (or 300 characters); windows with a smaller part of it are left out. Formats (plain text, web-page JSON, MCP content block, JSON mail list, Markdown, HTML) are drawn at random for both labels.

| Rows | Train benign | Train attack |
|---|---:|---:|
| **Paired dilution**: an attack inserted at a random place in a benign host of 200–8,000 characters, and the same host without it. Hosts: Wikipedia introductions and security articles (from the v0.2 corpus), Enron-Spam ham emails (train split), deepset benign prompts. Half of the hosts also carry a harmless instruction or a paragraph about prompt injection in both versions | 6,000 | 5,933 |
| [BIPIA](https://github.com/microsoft/BIPIA) **train** contexts and train attacks (email, table, code) | 900 | 1,800 |
| [InjecAgent](https://github.com/uiuc-kang-lab/InjecAgent), train tools × train attacker instructions (v0.2's split), base and enhanced, plus benign twins | 400 | 740 |
| Short harmless instructions that fit the task ("Please reply by Friday"), generated with DeepSeek | 1,653 | — |
| Short paragraphs that discuss prompt injection, generated with DeepSeek | 337 | — |
| Short attacks, generated with DeepSeek | — | 1,057 |
| toolwall v0.1 synthetic templates | 1,743 | 1,317 |

Attack strings were split between train and dev by source family (BIPIA attack category, InjecAgent instruction, generator call), and exact overlaps were removed from dev. No text from LLMail-Inject, LongPIBench or the BIPIA test split was read. Enron text is used for training only and is not redistributed. The generated texts are in the repository (`training/_gen_v0_3/`).

**Training.** 2 epochs, learning rate 2e-5, batch 16, warm-up 6 %, weight decay 0.01, bf16, seed 20261020, one A10G, 29 minutes (`training/modal_train_judge_v0_3.py`). The epoch was chosen by dev TPR − FPR.

**Dev** (same sources as training, so optimistic): AUROC 0.9997; TPR 0.990 at FPR 0.002; 0 of 243 harmless instructions flagged. Dilution probe (80 InjecAgent attacks and 80 benign twins): 79/80 attacks caught with 1,000 benign characters before or after (v0.2: 5/80 and 37/80), 0 false alarms.

## Evaluation

**Protocol.** The LLMail-Inject test file was frozen (sha256 `2fd96422…a594`, commit `4842057`) and the LongPIBench version pinned (code `c7b8011`, data `cdfdfdb`) before training. The rule for picking the shipped models was written in our notes (not a public commit) before the smaller models' results were seen. Every guard was then run once on all final tests (protocol commit `377a3b2`, 19 October 2026). Hugging Face guards were scored with their first 512 tokens and with LongPIBench's chunked protocol (any 512-token chunk ≥ 0.5). The chunked numbers are shown: they detect more for every guard, with more false alarms; both are in the repository. Per-row decisions: `results/v0_3_final/` in the repository.

| Guard | LLMail-Inject detection (n = 1,000) | LLMail-Inject false alarms (n = 703) | BIPIA detection (150) | BIPIA false alarms (150) | LongPIBench detection (1,200) | LongPIBench false alarms (400) |
|---|---|---|---|---|---|---|
| **toolwall v0.3** (rules + this judge, no task) | **0.822** [0.797, 0.844] | **0.000** [0.000, 0.005] | 0.780 [0.707, 0.839] | 0.007 | 0.632 | 0.310 |
| toolwall v0.3 with task (LLMail: the user's request; LongPIBench: the system prompt) | 0.809 [0.783, 0.832] | 0.000 | 0.780 | 0.007 | 0.980 | **0.975** ⚠ |
| toolwall v0.3-xsmall, with task | 0.807 [0.781, 0.830] | 0.004 | 0.807 | 0.020 | 1.000 | **1.000** ⚠ |
| toolwall v0.2 | 0.819 [0.794, 0.842] | 0.000 | 0.053 | 0.020 | 0.557 | 0.335 |
| PIGuard (chunked) | 0.449 [0.418, 0.480] | 0.037 | **0.947** | 0.007 | 0.729 | 0.583 |
| ProtectAI v2 (chunked) | 0.249 | 0.006 | 0.200 | 0.247 | 0.199 | 0.185 |
| Prompt Guard 2 86M (chunked) | 0.215 | 0.004 | 0.013 | 0.007 | 0.340 | 0.058 |
| Prompt Guard 2 22M (chunked) | 0.089 | 0.000 | 0.100 | 0.000 | 0.390 | 0.265 |
| deepset | 1.000 | 1.000 | 1.000 | 1.000 | 1.000 | 1.000 |

**LLMail-Inject.** Each attack appears once as a single email and once inside a bundle of 5, 10 or 20 emails. v0.3 is better than v0.2 on bundles (424 vs 356 of 500) and worse on single emails (398 vs 463). The judge alone (without rules) fires on 675 of 1,000 attacked inputs and 0 of 703 benign ones. These attacks were adaptive against Microsoft's defences, not against toolwall.

**BIPIA.** v0.3 was trained on BIPIA's train split, so this test is closer to its training data than the other two. This test split had already been run once, for the v0.2 report.

**LongPIBench.** By attack type, the judge alone (no task) flags 7 % of clean documents, 34 % with a naive attack, 12 % with an authority-spoof attack and 100 % with the combined attack. Of the 124 clean documents toolwall blocks, 95 are blocked by rules alone, 76 of them by one persuasion pattern (`pap-persuasive`).

**CPU latency** (rules + judge, AMD Ryzen 5 4500U laptop, 6 cores, PyTorch, median of 10): 500 characters 0.27 s; 2,000 characters 1.6 s; 8,000 characters 8.7 s; 32,000 characters 32 s. The xsmall variant: 0.10 s, 0.66 s, 3.5 s and 13 s. Use a GPU or the xsmall variant for long outputs; `TOOLWALL_JUDGE_MAX_CHARS` caps how much text is scored (default 200,000 characters, head and tail halves beyond that).

## Limitations

- Fails on long documents with naive or authority-spoof attacks (LongPIBench).
- Breaks when given a system prompt as the task; the default is no task.
- Misses about one in five LLMail-Inject attacks, more often in single emails than v0.2.
- Not tested against adaptive attacks aimed at this classifier.
- Slow on CPU for long outputs.
- Tested almost only on English (about half of the generated training texts are in six other languages).
- Detection only: it does not measure what an agent does after a response is passed or blocked.

## Data and licences

LLMail-Inject: Abdelnabi et al., 2025, MIT, © Microsoft. LongPIBench: Liu, Jia, Gong and Jia, EMNLP Findings 2026, MIT. BIPIA: Yi et al., KDD 2025, MIT. InjecAgent: Zhan et al., ACL Findings 2024, MIT. deepset/prompt-injections: Apache-2.0. Wikipedia: CC BY-SA 4.0. Enron-Spam (Metsis et al., 2006): training only.

## Citation

```bibtex
@software{hasnain2026toolwall,
  title   = {toolwall: a tool-boundary firewall for indirect prompt injection in AI agents},
  author  = {Hasnain, Muhammad},
  year    = {2026},
  version = {0.3.0},
  url     = {https://github.com/bryteai/toolwall}
}
```
