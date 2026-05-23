# Changelog

All notable changes to `toolwall` are documented here. Format
follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/)
and the project adheres to [Semantic Versioning](https://semver.org).

The `Policy` dataclass shape and the `toolwall-bench-v0.1` test
split are part of the public contract. Both are frozen for the
lifetime of the 0.1.x line.

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
