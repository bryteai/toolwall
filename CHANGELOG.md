# Changelog

All notable changes to `toolwall` are documented here. Format
follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/)
and the project adheres to [Semantic Versioning](https://semver.org).

The `Policy` dataclass shape and the `toolwall-bench-v0.1` test
split are part of the public contract. Both are frozen for the
lifetime of the 0.1.x line.

---

## [v0.2.0] — 2026-10-19

### Why this release exists
An external, held-out evaluation showed that the v0.1 judge (LoRA on
Qwen2.5-7B, trained only on synthetic templates) does not generalise: on
benign Wikipedia pages it blocked 98.0 % (392/400), and on benign InjecAgent
tool responses 66.5 % (701/1,054). The v0.1 headline (ASR 0.097 on the
in-house split) was in-distribution and is not representative. Full numbers:
`results/external_v0_2/`.

### Changed
- New default judge `toolwall-judge-v0.2`: a DeBERTa-v3-base classifier
  (runs on CPU), trained with a split-by-tool and split-by-instruction
  protocol on InjecAgent plus Wikipedia benign pages, with the decision
  threshold calibrated on a dev split (`training/build_corpus_v0_2.py`,
  `training/modal_train_judge_v0_2.py`). The v0.1 LoRA judge is still
  loadable via `TOOLWALL_JUDGE_LOCAL_PATH`.
- Evaluation compares detectors with detectors. Prompt-level defences
  (prompt sandwich, spotlighting) were removed from the comparison table:
  they do not block anything by design, so an "ASR 1.0" row was misleading.
- PyPI distribution renamed to `toolwall-guard` (the name `toolwall` on
  PyPI belongs to an unrelated project). The import name stays `toolwall`.

### Fixed (accuracy of claims)
- InjecAgent loader cited a commit and a Hugging Face mirror that do not
  exist; now pinned to the real commit `f19c9f2c79a4` (2024-07-02, MIT).
- Corrected source dates in `bench/schema.py` (Invariant Labs, 1 Apr 2025;
  CyberArk, 30 May 2025; Unicode-tag smuggling, Jan 2024).
- Removed claims that could not be verified (a NIST quotation, an
  over-broad description of CVE-2026-30615, an unsourced CVE count) and
  corrected MCPTox figures and the OWASP Agentic Top 10 mapping.
- Removed install instructions and badges for packages that were never
  published (npm, PyPI under the old name, `create-toolwall-worker`).
- Added the missing `toolwall` CLI (`toolwall check`), declared in v0.1
  but absent.

---

## [v0.1.0]

Initial public release.

### Added

- **Core library (Python + TypeScript)** with identical
  three-layer shape: policy → detect → enforce.
- **`Policy` dataclass (frozen, 9 fields):** `url_allowlist`,
  `url_denylist`, `egress_denylist`, `path_scope`, `redact`,
  `response_max_bytes`, `response_ipi_threshold`,
  `calls_per_min`, `cost_cents_max`. The shape is the v0.1
  contract — adding a 10th field is a v0.2 decision.
- **`@toolwall(policy=…)` decorator** for sync + async callables.
  Returns sanitized response or raises `toolwall.Blocked`.
- **Five built-in policy presets:** `web_fetch`, `file_read`,
  `mcp`, `db_read`, `email`.
- **Three detectors:**
  - `patterns` (regex corpus, every entry cited in
    `attack_corpus.csv`)
  - `unicode_tags` (U+E0000 block + zero-width + base64 heuristic)
  - `markdown_exfil` (markdown image/link sinks to non-allowlisted
    hosts)
  - `judge` (LoRA fine-tune on `Qwen/Qwen2.5-7B-Instruct`,
    Apache-2.0; substituted for gated Llama-3.1-8B-Instruct —
    see `training/MODEL_CARD.md` for the rationale and the
    bench numbers). Adapter weights ship via Hugging Face
    (`bryteai/toolwall-judge-v0.1`) and are downloaded lazily by
    `toolwall.detect.judge`. The local path `models/judge-v0.1/`
    is the trainer's write target and is honored by an env
    override (`TOOLWALL_JUDGE_LOCAL_PATH`). Rule layers run
    independently when the adapter is absent.
- **Five framework adapters** (each ≤80 lines, single `wrap()`
  entry):
  - `toolwall.adapters.claude_sdk`
  - `toolwall.adapters.crewai`
  - `toolwall.adapters.langgraph`
  - `toolwall.adapters.openai_agents`
  - `toolwall.adapters.mcp`
- **TypeScript port `@bryteai/toolwall-core`** with feature
  parity, Zod-based `Policy` schema, MCP middleware, Vercel AI
  SDK adapter. Bundle <30 KB minified.
- **`create-toolwall-worker` CLI** scaffolds a Cloudflare Workers
  MCP server with OAuth 2.1 + KV audit log + Durable Object
  sessions, pre-wired with `policy.mcp()`.
- **`toolwall-bench-v0.1` dataset.** 1,054 cases total: 500
  imported from InjecAgent (ACL 2024), 354 from AgentDojo
  (NeurIPS 2024 D&B), 200 new MCP-specific cases curated for
  this release. 3-way split (train 600 / dev 200 / test 254),
  test split SHA256-pinned at release tag time.
- **`eval/` pipeline (HarmBench-style)** with one-command
  reproducibility: `python -m eval.run_pipeline --inhouse-only`.
  Baselines: no-defense, prompt-sandwich, Spotlighting,
  GPT-4o-judge-inline.
- **`fence.bryteai.studio` demo** — Next.js + React + Tailwind,
  static export to Cloudflare Pages. Side-by-side
  attacked-vs-defended terminals across five attack scenarios.
- **Deterministic Playwright recorder** (`eval/recorder`) for the
  60-second portrait + 5-minute landscape demo cuts. Uses the
  own-the-in-page-clock pattern: patch `requestAnimationFrame` /
  `cancelAnimationFrame` / `performance.now` / `Date.now` only —
  never `setTimeout`/`setInterval`/`queueMicrotask`.
- **arXiv preprint draft** (`paper/toolwall-arxiv.tex`), 8-page
  ACL/NeurIPS-style with self-contained inline bibliography so
  arXiv's first-submission pipeline does not require BibTeX.
- **Public leaderboard format** (`results/leaderboard.json`)
  with five measured entries, per-family ASR for toolwall rows,
  separated `targets` vs measurements, and an anti-overfit
  submission protocol that opens at v0.2.
- **Governance:** `LICENSE` (Apache-2.0), `SECURITY.md` (90-day
  coordinated disclosure), `CITATION.cff`, `THREAT_MODEL.md`,
  `AUTHORS.md`, `CONTRIBUTING.md`, `CODE_OF_CONDUCT.md`,
  `ROADMAP.md`, `.github/workflows/{ci,release,codeql,scorecard}.yml`.

### Measured

In-house 200-case test split (185 attack + 15 benign):

| Defense              | ASR ↓      | Utility ↑   | LoC ↓ |
|----------------------|------------|-------------|-------|
| `no_defense`         | 1.0000     | 1.0000      | 0     |
| `prompt_sandwich`    | 1.0000     | 1.0000      | 30    |
| `spotlight`          | 1.0000     | 1.0000      | 50    |
| `toolwall_rule_only` | 0.7784     | 1.0000      | **4** |
| `toolwall`           | **0.0973** | **0.9333**  | 4     |

The rules+judge row is computed by `eval/merge_judge_predictions.py`
from a one-shot GPU-host scoring run on the 200-case test split
(`results/judge_predictions.jsonl`). Per-family ASR for `toolwall`:
base64 0.20 · full-schema 0.00 · markdown-exfil 0.10 · multi-hop 0.28 ·
rug-pull 0.12 · tool-poisoning 0.00 · unicode-tag 0.00. The judge
incurs a one-case benign block (utility 14/15 = 0.9333) — disclosed
not optimised away.

We publish what we hit. No number on the leaderboard has been
adjusted after the fact.

### Targeted (not measured)

The v0.1 launch targets — held separately so no one mistakes
them for measurements:

- InjecAgent ASR ≤ 2 %
- AgentDojo ASR ≤ 3 %
- Utility ≥ 97 %
- LoC ≤ 4

These will move from `targets` to `entries` only after the judge
revision lands and the full 854 imported cases run.

### Known limitations

- **Judge base model substituted.** The internal target was
  `meta-llama/Llama-3.1-8B-Instruct`. Llama-3.1 weights are gated
  behind a Meta license that was not approved at training time.
  `Qwen/Qwen2.5-7B-Instruct` (Apache-2.0) was used instead, which
  keeps the model card redistributable and lets the LoRA adapter
  ship in this repo without licence friction. See
  `training/MODEL_CARD.md` for the full rationale and per-class
  metrics on the 400-pair dev split.
- **Judge dev split is saturated** (1.0/1.0/1.0). The 400-record
  dev split was drawn from the same template generators as the
  3 600 training records, so the LoRA learned the template
  distribution itself. The dev numbers are an in-distribution
  sanity check, not a generalization claim. The metric we report
  in the README and the leaderboard is **judge-enabled ASR on the
  bench test split**, which is enforced disjoint from training
  (corpus fingerprint `68550159…ff71bd8`). A v0.2 release will
  swap the synthetic-template dev for a ~500-record
  human-curated held-out split. See `training/MODEL_CARD.md` §5.3.
- **English-language corpus.** All in-house cases are English.
  Multilingual IPI is a v0.3 line item.
- **No multi-modal IPI yet.** Image / PDF / DOM-aware detection
  parked for v0.3.
- **Solo curation.** Every in-house case was authored by the
  project lead. Public attack-case PRs are explicitly welcomed
  to widen coverage (`CONTRIBUTING.md`).
- **Latency overhead unmeasured in production.** Hot path is
  Python; the Rust core (v0.4) is the cure if needed.

### Security

- Disclosure address: `security@bryteai.studio`. 90-day
  coordinated window per `SECURITY.md`.
- DCO sign-off required for non-trivial contributions; see
  `CONTRIBUTING.md`.
