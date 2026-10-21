# Utility cost of DataFilter on clean SEP data

One run, 21 October 2026, protocol commit `eae1a6f` (`eval/modal_datafilter_sep_clean_v0_4.py`).

**What was measured.** DataFilter (Wang, Chen, Wagner; SaTML 2026; arXiv 2510.19207) is a Llama-3.1-8B fine-tune
that rewrites untrusted data to remove injected instructions, given the user's instruction. Its paper reports security
and task utility; this run measures the cost its benign users pay: on clean data, how often and how much does it
change the text? Model `JoyYizhu/DataFilter`, revision `f1841ddf786325a1e00c4b56bd00f100a7f711d7`, with DataFilter's own
prompt format (system prompt, `{instruction} <|end_of_instruction|> {data}`, greedy, max 1,024 tokens, stop at
`<|end_of_data|>`), reproduced verbatim in the script.

**Data.** The same 9,160 clean SEP rows as `results/v0_4_sep_clean` (benign fields only; no injected text):
task = SEP's clean instruction, text = SEP's clean data.

| | Rows | Share [Wilson 95 %] |
|---|---:|---:|
| Output differs from input (whitespace-normalized) | 191 of 9,160 | 2.09 % [1.81, 2.40] |
| … of which similarity < 0.9 (real edits, not punctuation) | 163 | 1.78 % |
| … of which similarity < 0.5 (most of the text removed) | 107 | 1.17 % |
| … of which output empty (all data removed) | 80 | 0.87 % |

By SEP task type: analytical 30 of 3,230 (0.93 %), creative and generative 139 of 2,940 (4.73 %), information
processing 22 of 2,990 (0.74 %). Subtasks with the most changes (of 30 each): Function Implementation 14, Contextual
Customization 13, Follow-up Reminder 12, Alternative Endings Creation 10, Prompt Variability Generation 10, Email
Drafting 9.

**For comparison, detectors on the same rows** (`results/v0_4_sep_clean`): toolwall v0.3 blocks 1.12 %, PIGuard
0.86 %, ProtectAI v2 2.18 %, Prompt Guard 2 86M 0.09 %. A detector's cost is a blocked task; a filter's cost is a task
run on edited data, which can be silent.

**Reading.** The rows DataFilter edits are the same kind the detectors block: data that is itself an instruction
meant to be processed ("Create a function that…", "Explain the importance of…"), where the user's instruction asks the
model to implement, translate or rewrite that text. Three of the most-changed rows had their data removed entirely.
This is the SEP question ("should it be executed or processed?") seen from the filter side: without the role of the
text, both detectors and filters treat processable instructions as injections. Role separation (StruQ, SecAlign,
SecPO) resolves it by structure; `docs/boundary.md` is toolwall's version of that.

**Limits.** One run, greedy decoding; benign data only, so this says nothing about DataFilter's security; SEP texts
are short and synthetic; "changed" is a text comparison, not a judgment of whether the downstream task still succeeds
(a removed sentence can be harmless or fatal). The threshold choices (0.9, 0.5) were made after seeing the data and
are reported for description only; the headline number is the 2.09 %.

Per-row outputs for every changed row: `datafilter.json`; summary: `SUMMARY.json`.
