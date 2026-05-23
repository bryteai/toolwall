"""Judge-model training utilities for ``toolwall-judge-v0.1``.

The training pipeline runs on Modal (single A10G) and produces a LoRA
adapter that the production firewall loads lazily via
:mod:`toolwall.detect.judge`. All training assets in this package are
DISJOINT from the published bench test split --- see
:mod:`training.build_corpus` for the disjointness assertion that
runs at corpus-build time.
"""

from __future__ import annotations

__all__: list[str] = []
