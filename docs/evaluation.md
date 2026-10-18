# Evaluation

Full method and numbers: the [README](../README.md#results-v02) and the
[technical report](../paper/toolwall-v0.2-report.pdf). Raw per-row decisions: `results/v0_2/`.

## In short
- **Held-out InjecAgent** (tools and attacker instructions never seen in training): all 95
  attacks blocked in both settings; no false positives on 150 benign twins, 296 workplace
  emails with requests, or 300 short tool outputs.
- **BIPIA**, run once after the judge was frozen: 8 of 150 attacks caught. Instructions that
  change the content or format of the answer are mostly missed.
- **Hard negatives**: 12.1 % of paragraphs from Wikipedia security articles are blocked, mostly
  by rule `ipi-053`.
- **Formatting sensitivity**: one BIPIA-style email scores 0.0 as compact JSON and 0.995 when
  indented.

## Reproduce
See the README's *Reproduce* section; every test file has a SHA-256 in
`bench/build_artifacts/TEST_MANIFEST_v0_2.json`.
