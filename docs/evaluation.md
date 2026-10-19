# Evaluation

Full method and numbers: the [v0.3 report](report_v0_3.md) and the
[README](../README.md#results-v03). Raw per-row decisions: `results/v0_3_final/`.
The v0.2 results are in [results_v0_2.md](results_v0_2.md).

## In short (v0.3, final tests run once)
- **LLMail-Inject** (500 human-written attacks that got past Microsoft's defences): 82.2 % of
  attacked inputs blocked, 0 of 703 benign inputs blocked. Best other open guard: 44.9 %.
- **BIPIA**: 78.0 % detected, 1 false alarm in 150 (v0.2: 5.3 %). PIGuard is better: 94.7 %.
- **LongPIBench** (long documents): every guard fails. toolwall blocks 31 % of clean documents,
  mostly through one regex rule, and barely detects naive and authority-spoof attacks.
- **Task input**: no gain; with a system prompt as the task, 97.5 % of clean documents are
  blocked. Off by default.
- **CPU latency**: 0.27 s for 500 characters, 8.7 s for 8,000 (xsmall: 0.10 s and 3.5 s).

## Reproduce
See the README's *Reproduce* section. The LLMail-Inject test file's SHA-256 is in
`bench/build_artifacts/final_v0_3/MANIFEST.json`.
