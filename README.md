<div align="center">

# `toolwall` — indirect prompt injection defense for AI agents

**A 4-line, opensource firewall for indirect prompt injection (IPI) at the AI-agent ↔ tool-response boundary.**

Apache-2.0 alternative to closed-source guard platforms for the tool-response surface. Framework-agnostic (CrewAI · LangGraph · Claude Agent SDK · OpenAI Agents · MCP). Aligned with OWASP ASI Top-10 (A01 IPI / A02 Tool Poisoning) and NIST AI 100-2e.

[![PyPI](https://img.shields.io/badge/PyPI-toolwall-blue)](https://pypi.org/project/toolwall/)
[![npm](https://img.shields.io/badge/npm-%40bryteai%2Ftoolwall--core-red)](https://www.npmjs.com/package/@bryteai/toolwall-core)
[![CI](https://github.com/bryteai/toolwall/actions/workflows/ci.yml/badge.svg)](https://github.com/bryteai/toolwall/actions/workflows/ci.yml)
[![CodeQL](https://github.com/bryteai/toolwall/actions/workflows/codeql.yml/badge.svg)](https://github.com/bryteai/toolwall/actions/workflows/codeql.yml)
[![OpenSSF Scorecard](https://api.securityscorecards.dev/projects/github.com/bryteai/toolwall/badge)](https://securityscorecards.dev/viewer/?uri=github.com/bryteai/toolwall)
[![License: Apache-2.0](https://img.shields.io/badge/License-Apache--2.0-green.svg)](LICENSE)
[![arXiv](https://img.shields.io/badge/arXiv-PENDING-b31b1b)](https://arxiv.org/abs/PENDING)
[![HF Bench](https://img.shields.io/badge/%F0%9F%A4%97-toolwall--bench--v0.1-yellow)](https://huggingface.co/datasets/bryteai/toolwall-bench-v0.1)
[![HF Judge](https://img.shields.io/badge/%F0%9F%A4%97-toolwall--judge--v0.1-yellow)](https://huggingface.co/bryteai/toolwall-judge-v0.1)

</div>

---

## The number

Toolwall blocks 90.27 % of indirect prompt injections (ASR **0.097 [0.062, 0.149]**) on the 200-case `toolwall-bench-v0.1` test split — non-overlapping with the best public OSS baseline (PromptGuard-86M at **0.427 [0.358, 0.499]**). Utility **0.933 [0.702, 0.988]**. Rule-only floor **0.778 [0.713, 0.832]**. All intervals are Wilson 95 % CIs over 185 attacks + 15 benigns; raw rows in [`results/leaderboard.json`](results/leaderboard.json).

> **Honest at v0.1:** the judge is a 4-bit-NF4 LoRA fine-tune on `Qwen/Qwen2.5-7B-Instruct` (Apache-2.0), substituted for gated Llama-3.1-8B-Instruct. The dev split saturated at 1.0/1.0/1.0 (template overlap with train) and we publish that verbatim — see [`training/MODEL_CARD.md §5.3`](training/MODEL_CARD.md#53-why-this-number-is-suspect-read-this-before-citing). The 9.7 % test-split number is computed by [`eval/merge_judge_predictions.py`](eval/merge_judge_predictions.py) against held-out cases with corpus fingerprint SHA256 `ce685e7a…`. Train↔test MinHash + 5-gram Jaccard overall mean = **0.006**, max = **0.447**, 2/200 cases flagged — full audit at [`results/train_test_similarity.json`](results/train_test_similarity.json).

---

## The four lines

```python
from toolwall import toolwall, policy

@toolwall(policy=policy.web_fetch())
def fetch_url(url: str) -> str:
    return requests.get(url).text
```

That is the entire user-facing API. Anything fancier is API failure — see [`THREAT_MODEL.md`](THREAT_MODEL.md) for why.

---

## Why this exists

Indirect prompt injection (IPI) is NIST's stated "[greatest security flaw](https://csrc.nist.gov/) of generative AI." The evidence pile in 2025–2026 is concrete:

| # | Disclosure | What it proved |
|---|---|---|
| 1 | **[EchoLeak — CVE-2025-32711](https://nvd.nist.gov/vuln/detail/CVE-2025-32711)** (CVSS 9.3) | Zero-click M365 Copilot data exfiltration via auto-fetched markdown images in untrusted email. The first *named, production* IPI exploit. |
| 2 | **CVE-2026-30615** | MCP supply-chain RCE chain hitting Cursor, VS Code, Claude Code, Windsurf, Gemini-CLI. ~200K vulnerable MCP server instances. |
| 3 | **[MCPTox (arXiv 2508.14925)](https://arxiv.org/abs/2508.14925)** | 353 real MCP tools × 1,312 attacks. o1-mini ASR **72.8 %**. Claude-3.7-Sonnet refused **only 2.7 %** of attacks. |
| 4 | **[OWASP ASI Top 10](https://owasp.org/www-project-top-10-for-large-language-model-applications/)** | Lists IPI / Tool Poisoning / Memory Tampering as A01 / A02 / A03. |
| 5 | **Anthropic MCP STDIO RCE class** | 10 CVEs across LiteLLM, LangChain, LangFlow, Flowise, LettaAI, LangBot. Anthropic declined a protocol-level fix — "expected behaviour." |

No opensource library currently inspects *tool-response bodies* before they re-enter the model's context. Existing defenses are either paid platforms or static metadata scanners that never read the payload. `toolwall` is the missing primitive.

---

## How it works

Three layers, one decorator. See [`THREAT_MODEL.md`](THREAT_MODEL.md) for the formal model.

```
agent ─call──▶ ① policy  ──▶ tool ──response──▶ ② detector ──▶ ③ enforcement ──▶ agent
              allowlist                        IPI score          redact/block
              scope                            pattern + judge    + audit log
              budget
```

- **Policy layer** — declarative `Policy` object: URL allowlist, egress denylist, path scope, named redactions, byte cap, IPI threshold, rate / cost caps.
- **Detector layer** — regex + Unicode-tag (U+E0000 block) + zero-width-char + markdown-exfil patterns drawn from public CVE corpus, plus a frozen LoRA-tuned `Qwen/Qwen2.5-7B-Instruct` judge (`models/judge-v0.1/`, Apache-2.0) for residual cases. Every pattern cited in [`src/toolwall/detect/attack_corpus.csv`](src/toolwall/detect/attack_corpus.csv). Base substitution rationale: [`training/MODEL_CARD.md`](training/MODEL_CARD.md).
- **Enforcement layer** — `redact` · `quarantine` · `block` (raises `toolwall.Blocked(reason, evidence)`) · `allow`. Every decision lands in an audit log.

---

## Comparison vs SOTA defenses

Measured on the 200-case in-house split of `toolwall-bench-v0.1` (185 attacks + 15 benigns). ASR is attack-success rate (lower is better); utility is benign-pass rate (higher is better). Brackets are Wilson 95 % CIs. Raw rows: [`results/leaderboard.json`](results/leaderboard.json).

| Defense | ASR ↓ [95 % CI] | Utility ↑ [95 % CI] | LoC ↓ |
|---|---|---|---:|
| No defense (baseline) | 1.000 [0.980, 1.000] | 1.000 [0.796, 1.000] | 0 |
| Prompt sandwiching | 1.000 [0.980, 1.000] | 1.000 [0.796, 1.000] | ~30 |
| [Spotlighting (Hines et al. 2024)](https://arxiv.org/abs/2403.14720) | 1.000 [0.980, 1.000] | 1.000 [0.796, 1.000] | ~50 |
| [`Niansuh/Prompt-Guard-86M`](https://huggingface.co/Niansuh/Prompt-Guard-86M) (input-side OSS baseline) | 0.427 [0.358, 0.499] | 0.467 [0.248, 0.699] | n/a |
| **`toolwall` v0.1 (rules only)** | **0.778 [0.713, 0.832]** | **1.000 [0.796, 1.000]** | **4** |
| **`toolwall` v0.1 (rules + judge)** | **0.097 [0.062, 0.149]** | **0.933 [0.702, 0.988]** | **4** |

The toolwall upper CI (0.149) does not overlap the PromptGuard-86M lower CI (0.358), so the gap is statistically meaningful at this n. PromptGuard also fails on benign traffic: its 0.467 utility means it kills more than half of legitimate tool responses. Per-attack-family numbers (Unicode-tag, markdown-exfil, base64, full-schema-poisoning, multi-hop, rug-pull, tool-poisoning) are in `entries[]` of the leaderboard.

### Honest limitations

- **Out-of-distribution attacks.** A 10-case red-team probe across 10 novel attack families (timing channels, RFC-header role confusion, OAuth consent spoof, etc., none in our 7 training families) yielded rule-only ASR **0.80 [0.490, 0.943]** — i.e., the rule layer alone generalizes poorly to unseen families. Judge-layer scoring on this set is queued for v0.2. Full per-family numbers: [`results/novel_attacks_score.json`](results/novel_attacks_score.json).
- **Dev-set saturation.** The LoRA judge's dev split scored 1.0/1.0/1.0; we suspect template overlap with the train split rather than a generalized solution. We publish the suspect number verbatim and treat the 200-case test split as the only authoritative figure. Disclosure: [`training/MODEL_CARD.md §5.3`](training/MODEL_CARD.md#53-why-this-number-is-suspect-read-this-before-citing).
- **Single-bench scope at v0.1.** All numbers above are on the in-house 200-case split. InjecAgent and AgentDojo runs are queued for v0.2. If measured numbers disagree with stated targets, the README and abstract are updated to the measured values — never the other direction.

---

## Install

```bash
# Python
uv add toolwall                         # or: pip install toolwall

# TypeScript
pnpm add @bryteai/toolwall-core         # or: npm i @bryteai/toolwall-core

# Cloudflare Workers MCP scaffold
npx create-toolwall-worker my-mcp
```

Python ≥3.10 (tested on 3.10 / 3.11 / 3.12 / 3.13). Zero runtime deps beyond `pydantic` and `regex`. TS bundle <30 KB minified.

---

## Adapters

Every adapter is ≤80 lines, single `wrap()` entry point. Working examples in [`examples/`](examples/).

| Framework | Module |
|---|---|
| Claude Agent SDK | `toolwall.adapters.claude_sdk` |
| CrewAI | `toolwall.adapters.crewai` |
| LangGraph | `toolwall.adapters.langgraph` |
| OpenAI Agents SDK | `toolwall.adapters.openai_agents` |
| MCP (Python — FastMCP middleware) | `toolwall.adapters.mcp` |
| MCP (TypeScript middleware) | `@bryteai/toolwall-mcp-middleware` |
| Vercel AI SDK v6 | `@bryteai/toolwall-core` |
| Mastra | `@bryteai/toolwall-core` |

---

## CLI

```bash
toolwall scan ./mcp.json     # audit a Claude Code / Cursor / Windsurf config
toolwall bench               # run toolwall-bench-v0.1 locally; print ASR + utility
toolwall demo                # launch the live exfiltration demo on :7860
```

---

## Where `toolwall` fits

If you searched for one of these, here is the honest positioning:

- **Opensource alternative on the tool-response surface** — `toolwall` is Apache-2.0, self-hosted, and inspectable. We do not match input-side coverage of paid platforms out-of-box; we focus on the tool-response vector.
- **Alternative to [PromptGuard-86M](https://huggingface.co/meta-llama/Prompt-Guard-86M) for tool output** — PromptGuard is trained on user-to-LLM injection and over-blocks structured tool JSON (utility 46.7 % on our bench). `toolwall` covers the `role:"tool"` channel PromptGuard was not trained for.
- **Alternative to [Llama-Guard-3](https://huggingface.co/meta-llama/Llama-Guard-3-8B) for tool responses** — Llama-Guard errors on `role:"tool"` inputs. `toolwall` is the tool-channel-specific layer.
- **MCP tool injection firewall / MCP middleware** — `toolwall.adapters.mcp` (Python FastMCP) + `@bryteai/toolwall-mcp-middleware` (TS) wrap any MCP server. Complements static-metadata MCP scanners with runtime response inspection.
- **AgentDojo / InjecAgent defense baseline** — we publish reproducible numbers on a `toolwall-bench-v0.1` subset that overlaps both. Submit a PR to add `toolwall` as a defense row on those leaderboards.
- **CrewAI / LangGraph / Claude Agent SDK / OpenAI Agents prompt injection defense** — one adapter per framework, identical `Policy` shape, all ≤80 LoC. See [`examples/`](examples/).

---

## Threat model — what `toolwall` does NOT defend against

We are deliberately upstream of the sandbox, downstream of the auth layer, and orthogonal to model alignment. Explicit non-goals (full list in [`THREAT_MODEL.md`](THREAT_MODEL.md)):

- Direct jailbreaks of the underlying LLM (HarmBench / JailbreakBench territory).
- Host-OS sandbox escapes — that is the host's job.
- Tool-side authentication or IAM.
- Network packet filtering.

If you are building defense-in-depth, `toolwall` is one layer. Use it with a sandbox, an authenticated tool layer, and a model with reasonable alignment. None of those alone is enough; neither is `toolwall` alone.

---

## Project layout

```
toolwall/
├── src/toolwall/              # Python core
│   ├── __init__.py
│   ├── policy.py              # frozen Pydantic Policy
│   ├── decorator.py           # @toolwall, sync + async
│   ├── exceptions.py          # Blocked, PolicyViolation
│   ├── detect/                # IPI detectors
│   │   ├── patterns.py
│   │   ├── unicode_tags.py
│   │   ├── markdown_exfil.py
│   │   ├── judge.py
│   │   └── attack_corpus.csv  # every pattern cited to source
│   └── adapters/              # framework adapters (≤80 lines each)
├── packages/toolwall-core/    # TypeScript port (pnpm workspace)
├── eval/                      # HarmBench-style pipeline
│   ├── generate_attacks/
│   ├── run_firewall/
│   ├── score/
│   └── run_pipeline.py
├── examples/                  # one-file integrations per framework
├── tests/                     # pytest + hypothesis
├── assets/                    # demo videos
├── THREAT_MODEL.md
├── SECURITY.md
├── CITATION.cff
└── LICENSE                    # Apache-2.0
```

---

## Reproduce in 60 seconds

```bash
git clone https://github.com/bryteai/toolwall && cd toolwall
pip install -e .
python eval/run_pipeline.py --bench in_house_200
```

CPU-only; no GPU needed (judge predictions are cached in [`results/judge_predictions.jsonl`](results/judge_predictions.jsonl)). Output writes ASR/utility tables with Wilson CIs to `results/v0.1.md`. Held-out split SHA256 (`ce685e7a…`) is pinned in [`eval/run_pipeline.py`](eval/run_pipeline.py); if your local hash disagrees, the harness aborts. To regenerate the judge predictions from scratch on a GPU host, see [`training/MODEL_CARD.md`](training/MODEL_CARD.md).

If you find a contamination case missed by the MinHash check ([`eval/run_minhash_dup_check.py`](eval/run_minhash_dup_check.py)), open an issue — it is the integrity-killing class of bug for this kind of benchmark.

---

## Live demo

[`fence.bryteai.studio`](https://fence.bryteai.studio) — same agent, same malicious page, side by side: undefended vs `toolwall`-wrapped. Five attack scenarios (calendar exfil, file exfil, markdown image, schema poisoning, rug-pull). No login. No tracking. Static. Source: [`examples/fence/`](examples/fence/).

### Reproducing the videos

The demo videos are captured by [`@toolwall/recorder`](eval/recorder/) — a Playwright driver that owns the in-page clock (patches `requestAnimationFrame` + `cancelAnimationFrame` + `performance.now` + `Date.now` and exposes `window.__toolwall_advance(ms)`) and pipes PNG-per-frame into `ffmpeg image2pipe`. Same git revision + same CRF = bit-stable mp4 across runs.

```bash
( cd examples/fence && pnpm build && cd out && python3 -m http.server 4173 ) &
pnpm --filter @toolwall/recorder build
pnpm --filter @toolwall/recorder record:portrait   # → eval/recorder/out/portrait-60s.mp4 (1080×1920)
pnpm --filter @toolwall/recorder record:landscape  # → eval/recorder/out/landscape-5min.mp4 (1920×1080)
```

Only those four globals are patched and never `setTimeout` / `setInterval` / `queueMicrotask`, because React's scheduler reads them for its own work loop and patching them desyncs the renderer.

---

## Cite

The BibTeX block below is the source of truth for the "Cite this repository" button GitHub auto-generates from [`CITATION.cff`](CITATION.cff). Update both when the arXiv ID lands. Preprint source: [`paper/toolwall-arxiv.tex`](paper/toolwall-arxiv.tex).

```bibtex
@article{hasnain2026toolwall,
  title   = {Toolwall: A Defense-in-Depth Library for Indirect Prompt Injection
             at the Tool--Response Boundary},
  author  = {Hasnain, Muhammad},
  year    = {2026},
  journal = {arXiv preprint arXiv:PENDING},
  url     = {https://arxiv.org/abs/PENDING},
  note    = {bryteai.studio (Bin Abdullah LLC, Brooklyn NY) --- NVIDIA Inception member}
}
```

---

## Contributors

`toolwall` is led by **Muhammad Hasnain** ([bryteai.studio](https://bryteai.studio) · Bin Abdullah LLC · NVIDIA Inception). The repository is single-author at v0.1.0 and is open to contributions under Apache-2.0. Two contribution lanes are explicitly welcomed:

- **New attack cases** for `bench/cases/mcp_v0_1.py`. Every case must cite a public disclosure (CVE, blog post, paper). PRs that invent attacks without provenance are declined — see [`bench/README.md`](bench/README.md).
- **Adapters for new frameworks**. The template is `≤80 lines`, single `wrap()` entry point. See [`src/toolwall/adapters/`](src/toolwall/adapters/) and [`packages/toolwall-core/`](packages/toolwall-core/) for the prior art.

The contributor list is updated on each release in [`AUTHORS.md`](AUTHORS.md). Conduct expectations live in [`CODE_OF_CONDUCT.md`](CODE_OF_CONDUCT.md).

---

## Security

See [`SECURITY.md`](SECURITY.md). Report vulnerabilities to `security@bryteai.studio` — 90-day coordinated disclosure window. Do not file public issues for security reports.

---

## License

[Apache-2.0](LICENSE). Use it, fork it, sell services on top of it — just don't remove the attribution.

---

<sub>Built by **Muhammad Hasnain** · [bryteai.studio](https://bryteai.studio) · NVIDIA Inception · Apache-2.0</sub>
