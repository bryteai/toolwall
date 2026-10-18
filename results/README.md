# `results/`

Every number in the top-level README comes from **`v0_2/`**. The other folders are kept so
that the path to it can be checked.

| Folder | Judge | Rules | What it is |
|---|---|---|---|
| `v0_2/` | v0.2 (frozen, sha256 `34dc0cc9…68fe`) | v0.2.0 (v0.1.1 rules + structured-payload fix) | **Release run.** All held-out sets and BIPIA. `eval/modal_eval_v0_2.py`, summarised by `eval/report_v0_2.py` |
| `v0_2_rc1/` | v0.2 (same) | v0.1.1 rules as merged | Same run before the dampener fix. Rules alone missed every InjecAgent attack here |
| `v0_2_rc0_bipia/` | v0.2 (same) | v0.1.0 rules | The first BIPIA run, before v0.1.1 was merged. `eval/run_final_bipia_v0_2.py` |
| `heldout_v0_2/`, `heldout_v0_2_1/`, `heldout_v0_2_2/`, `heldout_v0_2_3/` | the four judge candidates | v0.1.0 rules | Used to choose the judge (candidate 4 = the shipped one). These sets are therefore not untouched |
| `external_v0_2/` | v0.1 (LoRA, Qwen2.5-7B) | v0.1.0 rules | The external evaluation that showed the v0.1 judge does not generalise |
| `v0.1.*`, `leaderboard.json`, `*_predictions.jsonl`, `promptguard_*`, `novel_attacks_*`, `train_test_similarity.json` | v0.1 | v0.1.0 | v0.1 results on the in-house set. Superseded; kept for the record |

Decision files contain only ids, set names, labels and decisions — no text. Enron-Spam
texts are not redistributed; `bench/build_artifacts/heldout_v0_2/enron_requests_ids.json`
lists the message ids.
