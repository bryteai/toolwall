# Roadmap

`toolwall` is shipping v0.1.0 deliberately small. The bar for v0.1
was: four-line API, three-layer defense, one frozen benchmark,
one frozen judge revision, one honest leaderboard. Everything
else is parked here.

This document is the **scope contract**: nothing on this list
should land in `main` until the version that owns it. If you have
a strong opinion about an item, open an issue against that
milestone — not against v0.1.

The pace is intentionally slow. Security libraries that ship
new fields every Friday lose the property that makes them
trustable. Versions ship when their gate criteria are met, not on
a calendar.

---

## v0.1.0 — Public release

The minimum honest first release. Tracked in [`CHANGELOG.md`](CHANGELOG.md).

- [x] Three-layer architecture (policy → detect → enforce)
- [x] Frozen 9-field `Policy` dataclass
- [x] Python `toolwall` + TypeScript `@bryteai/toolwall-core`
- [x] Adapters: Claude SDK, CrewAI, LangGraph, OpenAI Agents, MCP
- [x] `toolwall-bench-v0.1` — 1,054 cases, 3-way split, SHA256-pinned test
- [x] In-house 200-case rule-only floor measured + published
- [x] `eval/run_pipeline.py` end-to-end, one command
- [x] `fence.bryteai.studio` demo (static export)
- [x] Deterministic Playwright recorder for socials
- [x] arXiv preprint draft
- [x] `AUTHORS.md`, `CONTRIBUTING.md`, `SECURITY.md`, `CITATION.cff`
- [x] LoRA judge fine-tune on `Qwen/Qwen2.5-7B-Instruct`

---

## v0.2.0 — Public leaderboard

The whole point of v0.2 is one thing: let other people submit
scores against the held-out test split, and let CI re-run the
harness to keep submissions honest.

**Gate criteria for shipping v0.2:**

- Public leaderboard surface at `fence.bryteai.studio/leaderboard`
- Submission protocol opens (`results/leaderboard.json`'s
  `submission_protocol` block goes live)
- CI re-runs every PR-submitted entry against the pinned test split
- Anti-overfit audit: `judge_revision` provenance must be
  declarable; any entry with `asr < 0.05` requires the audit log
- Per-family ASR shown on every leaderboard row
- Per-attack confidence intervals (Wilson) on every published number
- At least two third-party defenses (e.g., paid-platform open
  variants, static-side scanners) registered as baselines
- Judge-layer scoring extended to cover the OOD novel-families
  probe published in v0.1

**Out of scope for v0.2:** new `Policy` fields, new attack families
beyond the v0.1 set, adapter additions. v0.2 is purely about the
leaderboard and the OOD coverage backfill.

---

## v0.3.0 — Multi-modal IPI + browser scenarios

Once leaderboard is stable, the attack surface widens.

- Image inputs with hidden text (steganographic + OCR-visible)
- PDF inputs with hidden text layers and embedded JS
- Browser-Use / browser-agent scenarios (vision-language IPI)
- New attack families added to a `toolwall-bench-v0.2` (additive,
  v0.1 cases stay frozen)
- Optional vision detector module (OCR + pattern matchers)
- HTML/DOM-aware markdown-exfil detection (currently we look at
  the text; v0.3 looks at the rendered DOM)
- Multilingual IPI coverage (Urdu / Arabic / CJK / RTL handling)

---

## v0.4.0 — Rust core

Performance becomes the bottleneck once response-side defenses
run inline for every tool call.

- Rust crate `toolwall-core` (no underscore) for the hot path
  (pattern + Unicode-tag detectors)
- Python bindings via `pyo3` / Maturin
- TypeScript bindings via Wasm (esbuild output)
- Maintain feature parity with the Python/TS layers; do not
  fragment behaviour
- Target: <100 µs added latency per tool response on the
  in-house corpus at p95

---

## v0.5.0 — Production telemetry

Closes the gap between "library on your laptop" and "library in
production."

- OpenTelemetry-native audit log
- Per-tool `Detection` rate dashboards
- Configurable sample-and-store for replay
- Privacy-preserving exfil reporter (counts, not contents) so
  enterprises can ship telemetry without leaking the very PII
  toolwall is supposed to protect
- Optional pluggable judge backends (OpenAI / Anthropic / local
  vLLM) behind the same `Judge` ABC

---

## v1.0.0 — Hosted toolwall (only if there is demand)

API-key gated managed offering at `fence.bryteai.studio/api`. This
is the *commercial* surface. The opensource Apache-2.0 core
remains the source of truth — the hosted product is a deployment
convenience, never a feature gate.

- Hosted detector inference (judge model behind an API)
- Hosted audit log retention
- Hosted leaderboard private submissions for enterprises that
  cannot publish their results
- SOC 2 readiness for the hosted plane only

If commercial pull is not real, this milestone is cut. The
opensource library is sufficient on its own.

---

## Explicit non-goals (will not appear on any future roadmap)

- A "toolwall agent framework." We are a *library*; the
  agent framework belongs to the user.
- A jailbreak-prompt filter. That is HarmBench / JailbreakBench
  territory and a different layer of the stack.
- A model-side guardrail. We are downstream of the model — we
  do not align the model.
- A network firewall. The host's job.
- An IAM / auth layer for tools. Assumed to be correct
  upstream.

If you would like to build any of those, please do, and a link
from this file is gladly offered.
