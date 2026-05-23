"""HarmBench-style evaluation harness for ``toolwall-bench-v0.1``.

Three stages, one orchestrator:

* :mod:`eval.generate_attacks` --- materializes the bench split into a
  flat JSONL of (id, attack_kind, tool_response, expected_block).
* :mod:`eval.run_firewall` --- runs each defense (no-defense, prompt
  sandwich, spotlight, toolwall rule-only, toolwall full) against
  every case and emits per-case decisions.
* :mod:`eval.score` --- aggregates per-defense ASR + utility into a
  comparison CSV + markdown table.

The orchestrator :mod:`eval.run_pipeline` chains the three stages and
writes ``results/v0.1.csv`` + ``results/v0.1.md``. One command,
reproducible, no cherry-picking.
"""

from __future__ import annotations

__all__: list[str] = []
