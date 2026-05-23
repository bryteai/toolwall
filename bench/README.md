# `toolwall-bench-v0.1` — dataset card

**Version:** v0.1
**Curator:** Muhammad Hasnain · bryteai.studio · Bin Abdullah LLC (Brooklyn, NY) · NVIDIA Inception
**License (dataset, our contribution):** Apache-2.0
**License (re-shipped subsets):** InjecAgent = MIT · AgentDojo = AGPL-3.0
**Citation:** see `CITATION.cff` at repo root.

## What this is

The evaluation dataset that backs `toolwall`'s public claims about
indirect prompt injection (IPI) defense at the AI-agent ↔ tool-call
boundary. It is composed of three subsets:

| Source        | Cases | License     | Provenance |
|---------------|------:|-------------|-----------|
| `mcp_v0_1`    |   200 | Apache-2.0  | New, hand-curated by Muhammad Hasnain — the contribution of this work. |
| `injecagent`  |   500 | MIT         | Subset of Zhan et al., ACL Findings 2024. |
| `agentdojo`   |   354 | AGPL-3.0    | Subset of Debenedetti et al., NeurIPS D&B 2024. |
| **total**     | **1,054** | mixed   |  |

Splits (deterministic, seeded shuffle on sorted ids):

| Split | N   | Use                                            |
|-------|----:|------------------------------------------------|
| train | 600 | Judge-model fine-tune set; OK to leak features.|
| dev   | 200 | Early-stopping / sanity.                       |
| test  | 254 | Held out. **Never trained against.**           |

## Why a new dataset?

The two prior corpora are excellent for the *general* IPI threat
model but were authored before:

* MCP became the dominant tool protocol (CVE-2026-30615 disclosed
  ~200 K vulnerable MCP servers in April 2026);
* **tool poisoning**, **rug-pull**, and **full-schema poisoning** were
  named as distinct attack classes (Invariant Labs and CyberArk blogs,
  March–May 2026);
* **markdown-image exfil** was given a public CVE (EchoLeak,
  CVE-2025-32711, CVSS 9.3);
* the OWASP **Agentic Security Initiative Top-10** ranked these as
  A01 / A02 / A03 (Q1 2026).

The 200 new cases target those gaps explicitly. Family budget:

| Attack family            | Cases | Reference                              |
|--------------------------|------:|----------------------------------------|
| `tool_poisoning`         |    30 | Invariant Labs, 2026-03                |
| `rug_pull`               |    25 | Invariant Labs, 2026-04                |
| `full_schema_poisoning`  |    25 | CyberArk, 2026-05                      |
| `markdown_exfil`         |    30 | CVE-2025-32711 (EchoLeak)              |
| `unicode_tag`            |    25 | Goodside 2024-07; CVE-2021-42574       |
| `base64_payload`         |    25 | Greshake et al., AISec 2023            |
| `multi_hop`              |    25 | AgentDojo, NeurIPS D&B 2024            |
| `benign` (utility)       |    15 | hand-authored                          |
| **total**                |   200 |                                        |

Every attack family carries a published citation on **every case**, so
a reviewer can audit the provenance without re-running construction.

## Case schema

```python
class Case(BaseModel):
    id: str                              # ``<source>-NNNN``
    attack_kind: AttackKind               # one of nine families
    tool_response: str                    # the raw string the tool returns
    expected_block: bool                  # True iff a correct firewall blocks
    expected_utility_payload: list[str]   # substrings to preserve (benign / partial)
    source: Source                        # ``mcp_v0_1`` | ``injecagent`` | ``agentdojo``
    citation: str                         # paper / blog / CVE
    notes: str                            # free-text curator notes
```

See `bench/schema.py`.

## Reproducing the bench

The full 1,054-case canonical bench needs network access to the two
upstream repos. The 200-case in-house slice is pure-Python and can be
built offline.

```bash
# 1. In-house only (offline, deterministic):
python -m bench.build --inhouse-only
# → bench/build_artifacts/v0_1_inhouse/test.jsonl

# 2. Full canonical bench (requires the two caches below):
#    a. InjecAgent
git clone --depth 1 https://github.com/uiuc-kang-lab/InjecAgent /tmp/InjecAgent
git -C /tmp/InjecAgent checkout 6f9c4b3a8e1d7f2c5a90b146e3d8c2719f4a0e6b
python -m bench.loaders.injecagent --build-cache /tmp/InjecAgent/data \
    --out bench/loaders/_cache/injecagent_500.jsonl

#    b. AgentDojo
pip install agentdojo==0.1.43
python -m bench.loaders.agentdojo --build-cache \
    --out bench/loaders/_cache/agentdojo_354.jsonl

#    c. Assemble + split (writes train/dev/test JSONL + MANIFEST.json)
python -m bench.build
```

The `MANIFEST.json` emitted by step (c) contains per-split SHA-256
fingerprints. Any paper reporting numbers against this bench **must
echo the test-split SHA in its appendix** — that is the integrity
check.

## Honest finding included in the test suite

`tests/test_bench.py::test_rule_based_floor_and_no_overblock` codifies
a published-paper-grade result on the in-house corpus:

* Rule-based detectors alone catch ~22 % of these MCP-specific attacks
  (100 % on `unicode_tag`, ~53 % on `markdown_exfil`, **0 % on the
  semantic classes** — tool poisoning, rug-pull, schema poisoning,
  multi-hop, base64 payload).
* The judge model (`bryteai/toolwall-judge-v0.1`) is what lifts the
  floor to ≥95 %. The full pipeline result lives in
  `eval/run_pipeline.py`.

This is the central scientific claim the bench is designed to expose.
We refuse to game the rule layer to inflate detector-only numbers.

## Not in scope

* **Adversarial suffix attacks** (HarmBench / JailbreakBench territory).
  Toolwall is the response-side boundary; it cannot defend against
  user-prompt direct jailbreaks.
* **Sandbox/process escapes** (Cymulate Codex CLI, 2026-03). These are
  a host concern, upstream of the firewall.
* **Multimodal IPI** (image-encoded payloads). Planned for v0.3.
* **English bias.** All in-house cases are English-only. v0.2 will add
  Urdu / Arabic / Hindi / Chinese variants.

## Refusal to do

* We do not lift attack strings from adversary-controlled sources.
  Every in-house case is synthesized from a public class disclosure.
* We do not overlap the `test` split with the judge model's training
  data. The split is byte-pinned by the seeded shuffle in
  `bench/build.py` and the fingerprint is published in `MANIFEST.json`.
* We will not silently degrade a published number. Bench version bumps
  (v0.2 etc.) get new fingerprints and a new model card.
