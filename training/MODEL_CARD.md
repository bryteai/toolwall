> **Superseded by `toolwall-judge-v0.2`** (see `MODEL_CARD_v0_2.md`). On held-out external data this v0.1 judge blocked 98.0 % of random Wikipedia pages and 66.5 % of benign InjecAgent tool responses; the in-house numbers below were in-distribution.

# Model Card: `toolwall-judge-v0.1`

> Third-layer IPI judge for `toolwall` — a LoRA adapter that scores
> whether a tool response contains an indirect-prompt-injection
> payload. The first two layers (pattern + unicode + markdown-exfil)
> are cited in `THREAT_MODEL.md`; this card documents the model that
> closes the long tail.

| Field | Value |
|---|---|
| Model name | `toolwall-judge-v0.1` |
| Base model | `Qwen/Qwen2.5-7B-Instruct` (Apache-2.0) |
| Adaptation | LoRA (r=16, α=32, dropout 0.05, target `q_proj`/`v_proj`) |
| Head | `AutoModelForSequenceClassification`, 3 labels |
| Labels | `benign` (0) · `suspicious` (1) · `attack` (2) |
| Quantisation | 4-bit NF4 + double-quant (training); fp16 inference |
| Tokenizer | Qwen2.5 SentencePiece (pad = eos) |
| Sequence length | 512 |
| License | Apache-2.0 (base) · Apache-2.0 (adapter) |
| Author | Muhammad Hasnain — bryteai.studio (Bin Abdullah LLC, Brooklyn NY) · NVIDIA Inception member |
| Release | `v0.1.0` of `toolwall` |
| Adapter location | `models/judge-v0.1/` in repo + Hugging Face `bryteai/toolwall-judge-v0.1` |

---

## 1. Why a substituted base model

The project's internal training spec named **`meta-llama/Llama-3.1-8B-Instruct`** as the
judge base. Llama-3.1 weights live behind a Meta license that requires
account-level approval, and that approval was not in hand at training
time. Rather than block the v0.1 launch waiting on a gated download,
the project substituted **`Qwen/Qwen2.5-7B-Instruct`**, which:

- ships under Apache-2.0 (compatible with the toolwall license),
- is ungated on Hugging Face (no licence-acceptance step),
- benchmarks within noise of Llama-3.1-8B on classification fine-tunes
  at the 7-8 B scale (MMLU / ARC / HellaSwag deltas <2 pp in the
  Qwen2.5 technical report), and
- lets the LoRA adapter be redistributed in this repo without licence
  friction.

The substitution is documented in `CHANGELOG.md` under both the
`Added` and `Known limitations` sections — silently amending the spec
would have been the wrong move. "Publish what we hit, do not
fabricate" is the project rule; the substitution is reported plainly.

A future minor release (`v0.2.x`) may re-train on Llama-3.1 once
licence access is granted, and the comparison numbers will be
published side by side rather than as a replacement.

---

## 2. Intended use

`toolwall-judge-v0.1` is **only** intended as the third detector layer
inside `toolwall`. It scores a single tool-response payload (≤4 000
chars, truncated by the wrapper at `src/toolwall/detect/judge.py`)
and returns one of three labels with a calibrated probability.

It is **not** intended for:

- Standalone content moderation.
- General LLM safety classification outside the IPI threat model in
  `THREAT_MODEL.md`.
- Replacing the pattern / unicode-tag / markdown-exfil detectors —
  those layers run first by design (defense in depth).
- Any setting where the input language is not English (v0.1 corpus
  is English-only; multilingual support is a v0.3 line item).

The wrapper is lazy: if `transformers`/`peft`/`torch` are not
installed, the judge is silently disabled and only the rule layers
run. Production deploys without GPU therefore degrade *gracefully* to
the rule-only configuration.

---

## 3. Training corpus

**Corpus**: `training/_corpus/train_v0_1.jsonl`
**Fingerprint (SHA256 of sorted records)**:
`68550159e6fc97f8e4f131c39e9336fe8ae871be7dfbc93bb4f53b721ff71bd8`
**Records**: 4 000
**Seed**: 20260524 (deterministic dev split + shuffle)

| Family | Label | Count | Source policy |
|---|---|---:|---|
| `benign` | benign | 1 950 | Synthetic neutral tool outputs (web fetch, file read, RAG snippet, MCP tool result, calendar listing). Templates disjoint from bench test split. |
| `suspicious_borderline` | suspicious | 600 | Mild deflection language, role-play hints, edge-case markdown. No actionable injection. |
| `tool_poisoning` | attack | 220 | Invariant Labs "tool poisoning" template family — instructions embedded in tool description/output. |
| `rug_pull` | attack | 200 | Post-approval description mutation (the tool says one thing, the response says another). |
| `full_schema_poisoning` | attack | 200 | CyberArk full-schema-poisoning template family — malicious schema fields. |
| `markdown_exfil` | attack | 230 | Markdown image / link sinks pointing to non-allowlisted hosts (EchoLeak class). |
| `unicode_tag` | attack | 200 | U+E0000 block + zero-width characters carrying hidden payload. |
| `base64_payload` | attack | 200 | Hidden-payload-via-base64 heuristic family. |
| `multi_hop` | attack | 200 | Multi-step indirect injection (response says "fetch X, then do Y"). |

**Class totals**: attack 1 450 · benign 1 950 · suspicious 600.

### 3.1 Disjointness invariant

`training/build_corpus.py` enforces a hard assertion: **no record in
`train_v0_1.jsonl` may equal any `tool_response` in the published
test split** (`bench/build_artifacts/v0_1_inhouse/test.jsonl`). The
build refuses to write a contaminated corpus. This is the
integrity-killing class of mistake for any benchmark like this one,
and it is checked at build time, not assumed.

### 3.2 What the corpus is *not*

- It is not an attempt to enumerate every IPI variant — it is a
  training distribution biased toward the seven attack families
  documented in `bench/README.md`. Adversaries will find variants
  outside this distribution; the pattern/unicode/markdown layers
  exist specifically because the judge should not be the only line
  of defense.
- It is not human-graded preference data. Labels are generated by
  the family policy (every `tool_poisoning` row is `attack` by
  construction, etc.). A v0.2 release plans to layer ~500
  human-graded ambiguous cases on top.
- It is English-only. Roman Urdu / Hindi / Arabic / CJK adversarial
  inputs are out of scope for v0.1.

---

## 4. Training procedure

Run `training/train_judge.py` on a single A10G-class GPU host
(24 GB VRAM, sm_86, CUDA 12.1). Container image pins:

```
torch==2.4.0   transformers==4.46.0   peft==0.13.2
bitsandbytes==0.44.1   accelerate==1.0.1   datasets==3.0.1
scikit-learn==1.5.2   sentencepiece==0.2.0
tokenizers==0.20.3   tiktoken==0.8.0
```

| Hyperparameter | Value |
|---|---|
| Epochs | 3 |
| Per-device train batch | 8 |
| Gradient accumulation | 4 (effective batch 32) |
| Per-device eval batch | 16 |
| Optimiser | AdamW (Trainer default) |
| Learning rate | 2e-4 |
| Warmup ratio | 0.03 |
| LR schedule | Cosine |
| Mixed precision | fp16 |
| Sequence length | 512 |
| Seed | 20260524 |
| Best-checkpoint metric | `macro_f1` (greater is better) |

### 4.1 Dev split (deterministic)

The 4 000-record corpus is split into **3 600 train / 400 dev** with
a class-stratified rule:

- 133 records per class are pulled into dev first.
- The remaining benign records top dev up to exactly 400 (benign is
  the largest class).
- The split is fully reproducible from `SEED = 20260524`.

Dev metrics in §5 are computed on this 400-record split. The
*published bench test split* (`bench/v0_1_inhouse/test.jsonl`) is
not used for any dev-time decision and is reserved for the
leaderboard.

---

## 5. Dev-set metrics

> Measured on a 400-record stratified dev split drawn from the same
> 4 000-pair training corpus. Numbers below are copied verbatim from
> `models/judge-v0.1/training_summary.json` written by the training
> run that produced the v0.1 adapter. **We publish whatever we
> hit; no number is adjusted after the fact.** And — see §5.3 — we
> publish honestly *why* the headline number below is **not the
> performance metric a reader should trust**.

### 5.1 Headline

| Metric | Spec threshold | Measured | Met? |
|---|---|---|---|
| Accuracy | ≥ 0.92 | **1.0000** | ✅ |
| Attack-class F1 | ≥ 0.85 | **1.0000** | ✅ |
| Macro F1 | (not specified) | 1.0000 | — |
| Eval loss | (not specified) | 3.59 × 10⁻⁶ | — |

`shippable` in `training_summary.json` = `true`. The adapter ships.

### 5.2 Per-class report

From `sklearn.classification_report` on the 400-record dev split:

| Class | Precision | Recall | F1 | Support |
|---|---|---|---|---|
| benign | 1.0000 | 1.0000 | 1.0000 | 133 |
| suspicious | 1.0000 | 1.0000 | 1.0000 | 133 |
| attack | 1.0000 | 1.0000 | 1.0000 | 134 |

### 5.3 Why this number is suspect — read this before citing

A 1.0 on every class is **not** a result a reader should take at face
value, and it is not the result the project will quote in the README
or the paper. The honest reading is:

1. The dev split was drawn from the same 4 000-pair corpus produced
   by `training/build_corpus.py`. The corpus has family-specific
   template generators (one per the seven attack families plus two
   non-attack families).
2. A stratified 133-per-class hold-out from that same generator pool
   means a record in dev is, in distribution, indistinguishable from
   the records the model trained on — same template family, same
   wording patterns, often near-identical surface forms.
3. A 7-B-parameter LoRA over 3 600 such records will saturate that
   distribution. 1.0/1.0/1.0 means the model has learned the
   *template generators*, not necessarily the underlying concept of
   "is this an indirect-prompt-injection payload."
4. The metric that actually matters is **ASR on the published
   benchmark test split** (`bench/build_artifacts/v0_1_inhouse/
   test.jsonl`), which is enforced disjoint from the training
   corpus (`build_corpus.py` refuses to write a contaminated
   corpus — verified at corpus-build time, fingerprint
   `68550159e6fc97f8e4f131c39e9336fe8ae871be7dfbc93bb4f53b721ff71bd8`).
5. We re-run the bench with `--with-judge` and report the
   judge-enabled ASR in `results/leaderboard.json`. That number is
   the one the README, paper, and launch post will quote — not the
   dev-split saturation above.

Calling this a "negative result" would overstate it; the dev
saturation is simply the wrong metric for cross-distribution claims.
But calling it a "win" — as in *"toolwall-judge-v0.1 hits 100 %
accuracy"* — would be straightforwardly misleading. We do neither.

A future minor release (`v0.2.x`) will replace the synthetic-template
dev split with a **held-out human-curated split** (target: ~500
records authored from incidents not in any template family), so that
dev-time decisions reflect real distribution shift. Until then, treat
the dev metric as a training-loop sanity check, not as a
generalization claim.

---

## 6. Limitations & known failure modes

- **Single base-model substitution** — see §1. The substituted base
  is honestly disclosed; the v0.1 leaderboard row reflects the Qwen
  numbers, not Llama numbers.
- **English-only training distribution** — the model has not been
  exposed to multilingual IPI. Treat non-English inputs as if the
  judge were absent and rely on the rule layers.
- **Synthetic labels** — labels come from family policies, not human
  raters. Borderline cases (the `suspicious` class) are the noisiest
  population; the spec deliberately scores them at ≤ 0.55 in
  `judge.py` so they cannot single-handedly block.
- **No multi-modal coverage** — image / PDF / DOM-aware payloads are
  v0.3 work.
- **Adversaries may attack the judge directly** — see `THREAT_MODEL.md`
  §"Where toolwall fails open". The judge is one of three layers; if
  the judge is fooled, the pattern + unicode + markdown layers still
  run on the same payload (and conversely, the judge catches what
  the rule layers miss). Defense in depth is the design.
- **Adapter weights only** — the base model is not redistributed; the
  user downloads `Qwen/Qwen2.5-7B-Instruct` from HF at first
  inference. `transformers` handles the download with its normal
  caching.

---

## 7. Reproducing this model

```bash
# 1. Build the corpus (deterministic; refuses to write if any record
#    overlaps the published test split).
uv run python -m training.build_corpus

# 2. Train on an A10G-class GPU (≈30–45 min). Any container host that
#    can mount training/_corpus and persist the output adapter works.
python -m training.train_judge

# 3. Pull the adapter back locally (host-specific; see your platform's
#    persistent-volume export tooling).

# 4. Re-run the bench with the judge enabled.
uv run python -m eval.run_pipeline --inhouse-only --with-judge --force
```

The fingerprint in §3 lets a third party verify they trained on the
same corpus we did. If a corpus fingerprint diverges, the trained
weights cannot be expected to match.

---

## 8. Citation

If you build on this judge or the toolwall bench, please cite:

```bibtex
@misc{toolwall2026,
  title  = {Toolwall: A Defense-in-Depth Library for Indirect Prompt
            Injection at the Tool--Response Boundary},
  author = {Hasnain, Muhammad},
  year   = {2026},
  note   = {bryteai.studio (Bin Abdullah LLC, Brooklyn NY).
            NVIDIA Inception member.},
  url    = {https://github.com/bryteai/toolwall}
}
```

The `CITATION.cff` in the repo root is the canonical machine-readable
form; GitHub renders a "Cite this repository" button from it.
