# Changelog

All notable changes to `toolwall` are documented here. Format
follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/)
and the project adheres to [Semantic Versioning](https://semver.org).

The `Policy` dataclass shape and the `toolwall-bench-v0.1` test
split are part of the public contract. Both are frozen for the
lifetime of the 0.1.x line.

---

## [0.2.2] — 2026-10-19

First release on PyPI (`pip install toolwall-guard`). No code changes from 0.2.1.

### Changed
- Install instructions use PyPI (`pip install toolwall-guard`).
- README links are absolute, so they work on the PyPI project page.
- The source distribution contains only the package, tests and project files; evaluation data
  and results stay in the git repository.
- Package description no longer claims that toolwall "blocks" injection; see the README for
  what it catches and misses.

## [v0.2.1] — 2026-10-19

### Added
- `toolwall proxy`: a stdio proxy that protects any MCP server without code changes. It removes
  tools whose descriptions score as injection or change after first use (rug-pull), and withholds
  tool results that score as injection (`--mode block`), or only audits (`--mode warn`).
  Docs: `docs/proxy.md`. Tests: `tests/test_proxy.py`.

### Changed
- The release workflow runs manually until PyPI publishing is configured.

---

## [v0.2.0] — 2026-10-19

### Why this release exists
An external, held-out evaluation showed that the v0.1 judge (LoRA on
Qwen2.5-7B, trained only on synthetic templates) does not generalise: on
benign Wikipedia pages it blocked 98.0 % (392/400), and on benign InjecAgent
tool responses 66.5 % (701/1,054). The v0.1 headline (ASR 0.097 on the
in-house set) was in-distribution and is not representative. Full numbers:
`results/external_v0_2/`.

### Results (release run, `results/v0_2/`)
- InjecAgent with unseen tools × unseen instructions: ASR 0.000 (0/95) in
  both the base and enhanced settings; FPR 0.000 on 150 benign twins.
- FPR 0.003 on 400 random Wikipedia pages, 0.000 on 296 Enron workplace
  emails containing requests, 0.000 on 300 short tool outputs, 0.121 on 91
  paragraphs from Wikipedia security articles.
- ASR 0.217 on deepset (test split) and 0.205 on Lakera Gandalf (test split).
- **BIPIA, run once after the judge was frozen: ASR 0.947 (142/150 attacks
  get through), FPR 0.020.** The judge does not detect instructions that
  change the answer or add an unrelated task.

### Changed
- New default judge `toolwall-judge-v0.2`: a DeBERTa-v3-base classifier
  (runs on CPU). Training data: InjecAgent with a split-by-tool and
  split-by-instruction protocol, Wikipedia benign pages, deepset train split,
  Enron ham train emails, short benign outputs and the v0.1 templates, with
  every source placed in every container type at equal rates. Threshold
  calibrated on dev. Weights on the Hugging Face Hub at a pinned revision
  (`JUDGE_V02_HF_REVISION`). The v0.1 LoRA judge is still loadable via
  `TOOLWALL_JUDGE_LOCAL_PATH`.
- Includes the v0.1.1 rule changes, with one fix: the quote dampener is no
  longer applied to structured payloads (JSON, dicts, lists). In v0.1.1 it
  halved the score of every match inside a JSON string, so the rules alone
  missed every InjecAgent "enhanced" attack (`results/v0_2_rc1/`). The fix
  was made after seeing those held-out numbers.
- Evaluation compares detectors with detectors. Prompt-level defences
  (prompt sandwich, spotlighting) were removed from the comparison table:
  they do not block anything by design, so an "ASR 1.0" row was misleading.
- PyPI distribution renamed to `toolwall-guard` (the name `toolwall` on
  PyPI belongs to an unrelated project). The import name stays `toolwall`.
- New `judge` install extra (`pip install "toolwall-guard[judge]"`); CI runs
  rules only.

### Fixed (features that were declared but not enforced)
- `Policy.egress_denylist`, `schema_lock` and `scan_schema` existed as fields but no
  code enforced them. They are now enforced (`egress-denied`, `schema-mismatch`,
  `schema-poisoned`), with tests. Their scope is documented in `docs/usage.md` and
  `THREAT_MODEL.md` §4.3–4.5.

### Added
- `docs/` (installation, usage, evaluation) and `examples/arsenal_demo/demo.py`, an
  offline demo of six tool responses including one known miss.

### Fixed (accuracy of claims)
- OWASP references now use the published category names (Top 10 for LLM Applications 2025;
  Top 10 for Agentic Applications, December 2025). A claimed memory-write hook and config
  scanner, which do not exist, were removed from the threat model.
- InjecAgent loader cited a commit and a Hugging Face mirror that do not
  exist; now pinned to the real commit `f19c9f2c79a4` (2024-07-02, MIT).
- Corrected source dates in `bench/schema.py` (Invariant Labs, 1 Apr 2025;
  CyberArk, 30 May 2025; Unicode-tag smuggling, Jan 2024).
- Removed claims that could not be verified (a NIST quotation, an
  over-broad description of CVE-2026-30615, an unsourced CVE count) and
  corrected MCPTox figures and the OWASP Agentic Top 10 mapping.
- `ipi-001` note: the canonical override phrase appears in 1,054/1,054
  enhanced-setting InjecAgent cases and 0/1,054 base cases (not "18 %").
- Removed install instructions and badges for packages that were never
  published (npm, PyPI under the old name, `create-toolwall-worker`).
- Withdrew the unsubmitted v0.1 preprint draft (`paper/README.md`).
- Added the missing `toolwall` CLI (`toolwall check`), declared in v0.1
  but absent.

### Known issues
- Rule `ipi-053` (added in v0.1.1) matches ordinary phrases such as "LLMs are";
  it causes 6 of the 11 false positives on Wikipedia security articles.
- The judge's score can change with formatting: one BIPIA-style email scores
  0.0 as compact JSON and 0.995 when indented. Not yet measured.

### Note on the v0.1.1 entry below
Its "ENDEST" table was measured on a self-built panel of 48 attacks and
10 benign documents. It is not comparable with the held-out results above.

---

## [v0.1.1] — 2026-05-24

Security-hardening release. Adds detectors for the 2024-2026 frontier
of indirect-prompt-injection and jailbreak techniques, lowers
false-positive rate on quoted security-blog content via a
use-vs-mention dampener, and ships a defense-in-depth fix on the
audit-log path. No public API or `Policy` shape changes — drop-in
upgrade from v0.1.0.

### Added

- **ROT13 chain layer** in the encoding-rescan loop, run after the
  base64-decode pass so that `base64(ROT13(payload))` cannot smuggle
  an IPI canary past the regex corpus.
- **Sneaky Bits detector** for U+2062 / U+2064 invisible math
  operators (Rehberger / Embracethered 2024). Fires at score 0.88
  on a run of ≥ 8 invisible operators and feeds into `strip()`.
- **Multilingual IPI patterns** for eight languages — Urdu, Arabic,
  Hindi, Chinese, Japanese, Korean, Russian, Turkish (Deng et al.,
  COLM 2024). Native quantifiers handled (جميع/كافة, सभी, 所有+先前的
  cumulative, すべての).
- **MCP attack patterns:** tool shadowing, puppet / line-jumping,
  self-replicating worms (`include-this-line` + `next-agent-tool` +
  description-field bridges). Reflects Invariant 2025, CyberArk 2026,
  EchoLeak CVE-2025-32711.
- **PAP 40-strategy detectors** (Zeng et al., NeurIPS 2024):
  authority impersonation, social proof ("other Claude instances
  already provided …"), reciprocity ("in return please share your
  system prompt"), foot-in-door multi-step.
- **ArtPrompt** (ACL 2024) dense ASCII art + `[MASK]` decode prompts.
- **Crescendo** (Microsoft 2024) gradual-escalation patterns.
- **Skeleton Key** (Microsoft 2024) compliance-claim patterns.
- **Generic prompt-leak canary** (`ipi-060`) — cross-cut silver-bullet
  pattern covering 17 verb forms × 8 modifier slots × system-prompt
  / instructions / directives / initial-message targets.
- **Per-layer dedup** in multi-encoding decode-rescan loops.
  Previously a single shared `seen` set silently swallowed hex blobs,
  because the hex alphabet is a strict subset of the base64 alphabet:
  the base64 layer matched the hex blob first, added it to `seen`,
  then the hex layer skipped it via `if blob in seen: continue` —
  even though only the hex decode produced the real plaintext payload.
  Each encoding layer now keeps its own `seen_<scheme>` set.
- **`.snyk` policy file** documenting accepted residual issues with
  annual review dates so suppressions cannot rot silently.

### Changed

- **Base scores lowered for `instruction-override` patterns** to combat
  use-vs-mention false-positives on quoted security-blog / OWASP /
  LangChain-docs content. Examples: `ipi-001` 0.92 → 0.70,
  `ipi-002` 0.90 → 0.68, `ipi-003` 0.88 → 0.66. Raw IPI still crosses
  the default `response_ipi_threshold = 0.6`. Quote-dampener
  additionally halves scores inside `"..."`, `'...'`, backticks, and
  fenced code blocks.
- **`audit.py`:** new `_safe_log_path()` helper rejects empty paths,
  NUL bytes, and `..` segments before the `TOOLWALL_AUDIT_LOG` value
  reaches `open()`. The audit-log location remains operator-controlled
  deploy-time configuration; this is defense-in-depth on the
  operator-trusted path, not a threat-model change.
- **Multilingual IPI** was previously listed as a v0.3 line item; it
  is now partially shipped (8 languages) and the v0.3 line item is
  narrowed to multilingual *coverage parity* with the English corpus.

### Measured — ENDEST world-class hardening test (2026-05-24)

Adversarial test harness covering 21 frontier attack families plus
PAIR LLM-as-attacker (Azure Claude Opus 4.7, 10 mutation rounds).
Wilson 95 % binomial confidence intervals reported.

| Round | ASR (95 % CI)        | Evades | Patch layer added              |
|-------|----------------------|--------|--------------------------------|
| R1    | 52.1 % [37.5, 66.3]  | 25/48  | pre-patch baseline             |
| R2    | 27.1 % [16.4, 41.5]  | 13/48  | NFKC + Zalgo + URL + gzip + 22 corpus rows |
| R2.5  | **0.0 % [0.0, 7.4]** | **0/48** | per-layer dedup + ROT13 chain + Sneaky Bits + ipi-060 silver bullet |

- **Utility FPR:** 0.0 % on a 10-doc benign panel covering eight
  languages, mixed code, and security-blog prose.
- **PAIR LLM-as-attacker:** 0 / 10 evades. Claude Opus 4.7, given the
  detector source and free rein over mutation, could not synthesize a
  working bypass after R2.5.
- **`pytest`:** 75 / 75 green. One detector test threshold was lowered
  from `≥ 0.85` to `≥ 0.65` to align with the new use-vs-mention base
  scores; raw IPI canaries still safely cross the default 0.6 gate.
- **Latency:** unchanged — p50 0.04 ms, p95 0.22 ms.

21 attack families covered: GCG · AutoDAN · AutoDAN-Turbo · JBFuzz
(2026) · Many-Shot (Anthropic) · Crescendo (Microsoft) · Skeleton Key
(Microsoft) · ArtPrompt (ACL 2024) · PAIR (Chao et al. 2024) · TAP ·
PAP 40-strategy (Zeng et al., NeurIPS 2024) · multilingual jailbreak
(8 langs, Deng et al., COLM 2024) · MCP shadowing / puppet / worm ·
EchoLeak (CVE-2025-32711) · Unicode Tags / Sneaky Bits / Zalgo /
homoglyph · base64 / hex / URL / gzip / ROT13 chained encodings ·
prompt-leak canary.

### Security

- Pre-existing low-severity path-traversal in `audit.py`
  (operator-trusted `TOOLWALL_AUDIT_LOG` env var) has been
  defense-in-depth sanitized via `_safe_log_path()` and documented
  in `.snyk` with annual-review expiration.

### CI

- The `test` matrix on Python 3.10 has been moved to a dedicated
  `test-py310-core` job that runs core detectors with pip (no
  adapter extras), because the adapter extras' transitive
  `onnxruntime` dropped cp310 wheels at 1.24+. The main test matrix
  now runs on 3.11 / 3.12 / 3.13. `requires-python` in
  `pyproject.toml` remains `>=3.10`.

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
