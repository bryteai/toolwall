# `results/`

Every number in the top-level README comes from **`v0_3_final/`** (v0.3 release) or, for the
v0.2 tables in `docs/results_v0_2.md`, from **`v0_2/`**. The other folders are kept so that the
path to them can be checked.

| Folder | Judge | Rules | What it is |
|---|---|---|---|
| `v0_3_final/` | v0.3 (`b4df0319…7d72`), v0.3-xsmall (`aa1705ca…b138`), v0.2 | v0.2.0 | **v0.3 final tests, run once**: LLMail-Inject, LongPIBench, BIPIA; 9 guard settings. `eval/modal_final_v0_3.py`, summarised by `eval/report_final_v0_3.py` (`tables.md`, `summary.json`); CPU latency in `latency_*.json` |
| `v0_3_dev/` | four v0.3 backbones | — | Dev and dilution-probe results used to choose the v0.3 models |
| `v0_2/` | v0.2 (frozen, sha256 `34dc0cc9…68fe`) | v0.2.0 (v0.1.1 rules + structured-payload fix) | **Release run.** All held-out sets and BIPIA. `eval/modal_eval_v0_2.py`, summarised by `eval/report_v0_2.py` |
| `v0_2_rc1/` | v0.2 (same) | v0.1.1 rules as merged | Same run before the dampener fix. Rules alone missed every InjecAgent attack here |
| `v0_2_rc0_bipia/` | v0.2 (same) | v0.1.0 rules | The first BIPIA run, before v0.1.1 was merged. `eval/run_final_bipia_v0_2.py` |
| `heldout_v0_2/`, `heldout_v0_2_1/`, `heldout_v0_2_2/`, `heldout_v0_2_3/` | the four judge candidates | v0.1.0 rules | Used to choose the judge (candidate 4 = the shipped one). These sets are therefore not untouched |
| `external_v0_2/` | v0.1 (LoRA, Qwen2.5-7B) | v0.1.0 rules | The external evaluation that showed the v0.1 judge does not generalise |
| `v0.1.*`, `leaderboard.json`, `*_predictions.jsonl`, `promptguard_*`, `novel_attacks_*`, `train_test_similarity.json` | v0.1 | v0.1.0 | v0.1 results on the in-house set. Superseded; kept for the record |

Decision files contain only ids, set names, labels and decisions — no text. Enron-Spam
texts are not redistributed; `bench/build_artifacts/heldout_v0_2/enron_requests_ids.json`
lists the message ids.
