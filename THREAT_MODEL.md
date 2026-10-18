# Threat Model — `toolwall` v0.1

**Status:** authoritative for v0.1.x. Updated only by accompanying CVE / advisory.
**Audience:** security engineers, agent framework authors, academic reviewers.
**Frame:** STRIDE-adjacent, expressed in the agent-tool-call vocabulary.

This document is deliberately blunt about what `toolwall` does *not* defend against. If a reader cannot point to the section that admits a limitation, the document is failing.

---

## 1. System under defense

A program where:

1. An LLM (the **model**) is invoked in a loop and emits tool calls.
2. Tool calls are dispatched to **tools** — opaque functions whose return value is serialized back into the model's context window for the next turn.
3. Tool outputs may be sourced from anywhere: a web page, a RAG index, an email body, an API payload, a file body, an MCP server.

`toolwall` is a library that sits between step 2 and step 3, inspects the request and the response, and applies a declarative `Policy` before the response re-enters the model's context.

`toolwall` does **not** modify the model, the system prompt, the orchestrator, the sandbox, or the network.

---

## 2. Attacker (Adversary `A`)

### 2.1 Capabilities the adversary has

| # | Capability | Realism (2026) |
|---|---|---|
| A1 | Controls the **content** of any tool response (web page body, RAG document body, email body, JSON value, file body, MCP tool output). | Standard — EchoLeak (CVE-2025-32711), AgentDojo, InjecAgent, MCPTox all exploit this. |
| A2 | Controls the **schema / description** of a tool registered to the agent (rug-pull post-approval, full-schema poisoning). | Invariant Labs (April 2025), CyberArk (May 2025). |
| A3 | Knows the **system prompt and tool roster** of the target agent. | Worst-case assumption. Often true via Reddit / GitHub leaks. |
| A4 | Can target **the model directly** with prompt-engineering payloads in tool output (i.e., the response itself is the jailbreak). | Standard IPI. |
| A5 | Can **chain** multiple tool calls — e.g., trick the agent into POSTing exfiltrated content via a second tool. | Standard chained-attack pattern. |
| A6 | Can **persist** payloads across sessions (memory poisoning) where the agent has memory. | OWASP Top 10 for Agentic Applications (Dec 2025), ASI06 Memory & Context Poisoning. |
| A7 | Can **time-shift** the attack — payload delivered today, exploited weeks later when the document is re-retrieved. | Stored IPI; common in RAG. |

### 2.2 Capabilities the adversary does NOT have

| # | Limitation | Why we exclude it |
|---|---|---|
| ~A1 | Cannot modify the model weights. | Different layer (alignment / training-time). |
| ~A2 | Cannot modify the system prompt or orchestrator source code. | If they can, the host is already compromised; `toolwall` is moot. |
| ~A3 | Cannot tamper with `toolwall`'s own audit log on disk. | Host-OS responsibility. `toolwall` only writes to its log, never reads it back to drive enforcement. |
| ~A4 | Cannot tamper with `Policy` objects in memory. | If they have arbitrary read-write on the agent process, every defense fails — this is the floor. |
| ~A5 | Cannot bypass the network firewall. | Orthogonal layer. We are application-level. |

If `A` actually has a capability listed under §2.2, **`toolwall` does not pretend to help.** That is a Stanford-class non-goal, listed in §6.

---

## 3. Defender (`toolwall`)

### 3.1 Defender position
- Sits between every tool invocation and the model context window.
- Sees:
  - Raw tool **arguments** before dispatch (request layer).
  - Raw tool **output** before serialization (response layer).
- Owns: `Policy` (declarative), detectors (pattern + judge), enforcement (allow / redact / block / quarantine), audit log.

### 3.2 Defender does NOT have
- Visibility into the model's internal activations.
- Authority over the system prompt.
- Ability to retrain the model.
- Ability to harden the underlying OS sandbox.
- Ability to authenticate the tool — that is upstream.

---

## 4. In-scope attacks (each one cites a real artifact)

For each attack class: definition, concrete real-world case, the `toolwall` mechanism that addresses it, and a sober statement of where the mechanism fails open.

### 4.1 Indirect Prompt Injection in tool output (IPI-Direct)
- **Definition.** Tool returns content containing instructions that the model interprets as commands.
- **Real case.** *EchoLeak* — CVE-2025-32711, CVSS 9.3. M365 Copilot was driven to fetch a markdown image whose URL embedded the user's recent calendar data. Zero-click. (Source: Microsoft MSRC, June 2025.)
- **Mechanism.** Detector layer: regex + Unicode-tag detector + judge model. Enforcement: `block` if score ≥ threshold; otherwise `redact` the matched span.
- **Where it fails open.** Detector is finite; a sufficiently novel paraphrase the judge has not seen will pass. We do not claim 0 % ASR; we claim a measurable, reproducible reduction.

### 4.2 Hidden-Unicode / zero-width / homoglyph payloads (IPI-Stealth)
- **Definition.** Instructions encoded in Unicode tag block (U+E0000–U+E007F), zero-width joiners, RTL overrides, or visually identical homoglyphs so a human review misses them.
- **Real case.** Documented in the Unicode tag attack on Bing Chat (2024) and re-popularized in the ATTESTMCP attack corpus (2026).
- **Mechanism.** `toolwall.detect.unicode_tags` strips the entire U+E0000 block from any tool output; zero-width chars are normalized; suspicious mixed-script tokens flagged.
- **Where it fails open.** Stripping the U+E0000 block can break legitimate text that uses tag characters (rare, but exists in some emoji flags). We default to strip-with-audit, not strip-silently; the audit log records the offending span.

### 4.3 Tool Poisoning / rug-pull (IPI-Schema)
- **Definition.** A previously approved tool changes its description, parameters, or default values after approval, smuggling new behavior the agent operator never reviewed.
- **Real case.** Invariant Labs, "Tool Poisoning Attacks against MCP" (2025-04). Real demo against Claude Desktop.
- **Mechanism.** `Policy.schema_lock=True` pins the SHA-256 of the wrapped tool's schema text (name, docstring, signature, `description` attribute) at wrap time. A call made after that text has changed raises `Blocked("schema-mismatch")`.
- **Where it fails open.** The lock sees the wrapped Python function only. A description changed elsewhere — for example inside an MCP SDK's own registry, or on a remote MCP server the agent talks to — is not seen.

### 4.4 Full-Schema Poisoning (IPI-FSP)
- **Definition.** Malicious instructions embedded in *non-description* schema fields (e.g., `parameters.properties.<field>.description`, `examples`, `default`, `$ref` titles) that the model nonetheless reads when reasoning about the tool.
- **Real case.** CyberArk Labs, "Poison Everywhere" (May 2025).
- **Mechanism.** With `Policy.scan_schema=True` (on in the `policy.mcp()` profile) the detectors also score the wrapped tool's schema text; a score at or above `response_ipi_threshold` raises `Blocked("schema-poisoned")`. Nested JSON-schema fields of a remote tool are not seen.
- **Where it fails open.** Some legitimate tool descriptions read like instructions ("If the user asks about X, return Y."). False-positive rate is non-zero. The block is written to the audit log with the score for operator review.

### 4.5 Exfiltration via tool side effects (Exfil-Sink)
- **Definition.** Agent is tricked into POSTing data, fetching a markdown image with embedded data in the URL, encoding secrets into a search query, or writing to a file path the attacker controls.
- **Real case.** EchoLeak (CVE-2025-32711, markdown image sink), and the configuration-based sandbox escapes in coding agents reported by Cymulate Research Labs (April 2026), where a configuration file written from inside the sandbox is executed outside it.
- **Mechanism.** Request side: `Policy.url_allowlist` / `url_denylist` and `Policy.path_scope` on arguments; `Policy.egress_denylist` on writes (a `method`/`http_method`/`verb` argument of POST, PUT, PATCH or DELETE). Response side: the markdown-exfiltration detector flags image and link sinks in tool output.
- **Where it fails open.** A legitimately allowlisted host can still be a sink (e.g., a paste service inside the org). The allowlist is only as good as the operator's discipline.

### 4.6 Capability escalation via argument smuggling (Exfil-Args)
- **Definition.** Adversary causes the agent to call a low-privilege tool with arguments that smuggle a high-privilege operation. Canonical example: a `git diff` tool that shells out, given an argument containing `; rm -rf /`.
- **Real case.** Anthropic MCP STDIO RCE class disclosure (2026-04) and 10 downstream CVEs across LiteLLM, LangChain, LangFlow, Flowise, LettaAI, LangBot.
- **Mechanism.** `Policy.arg_validators` — per-tool regex / type / length constraints on arguments. `Policy.shell_metachar_block=True` rejects shell metacharacters in any string argument by default.
- **Where it fails open.** We do not patch the underlying tool; we reject obvious shell-injection shapes. A tool that does `eval(arg)` is still RCE — that is the tool's bug, not ours. We document this and refuse to be marketed as a fix for it.

### 4.7 Resource abuse (Loop / Cost / Token)
- **Definition.** Adversary causes the agent to enter a loop, burn tokens, or run up cost.
- **Real case.** Runaway loops and unbounded cost are a known failure of autonomous agents; OWASP lists Unbounded Consumption as LLM10 (2025).
- **Mechanism.** `Policy.calls_per_min`, `Policy.cost_cents_max`, `Policy.response_max_bytes`.
- **Where it fails open.** Cost cap requires accurate token accounting, which we approximate from response bytes. A pathological response (lots of long tokens) can underspend our byte estimate.

### 4.8 Memory poisoning (Stored-IPI)
- **Definition.** Adversary stores a payload in the agent's memory (vector store, summary, scratchpad) and triggers it later in a different session.
- **Real case.** OWASP Top 10 for Agentic Applications (Dec 2025), ASI06 Memory & Context Poisoning.
- **Mechanism.** `toolwall` applies the same detector layer to memory writes if the host registers the memory write as a "tool" (most do not).
- **Where it fails open.** If the host writes memory *without* going through a tool boundary, `toolwall` never sees it. We document this loudly. A dedicated memory-write hook is not implemented yet; a host can route memory writes through a `@toolwall`-wrapped function today.

---

## 5. Architecture: what each layer actually defends

```
                                attacker controls ↓ ↓ ↓
                                                       
   ┌───────────────────────────────────────────────┐
   │ TOOL                                          │
   └──────────────────┬────────────────────────────┘
                      │ raw output  (this is the attack surface)
   ┌──────────────────▼────────────────────────────┐
   │ ② DETECTOR — pattern + judge                  │  defends 4.1, 4.2, 4.4
   └──────────────────┬────────────────────────────┘
                      │ scored output
   ┌──────────────────▼────────────────────────────┐
   │ ③ ENFORCEMENT — allow/redact/block/quarantine │  defends 4.5, 4.6, 4.7
   └──────────────────┬────────────────────────────┘
                      │ safe output
   ┌──────────────────▼────────────────────────────┐
   │ MODEL CONTEXT                                 │
   └───────────────────────────────────────────────┘

   ┌───────────────────────────────────────────────┐
   │ ① POLICY (declared at registration time)      │  defends 4.3, 4.5, 4.6, 4.7
   │   schema_lock · url_allowlist · egress denyl. │
   │   path_scope · arg_validators · rate · cost   │
   └───────────────────────────────────────────────┘
```

Three layers. No single layer is a defense by itself.

---

## 6. Explicit non-goals (do not soften these)

If a non-goal looks embarrassing, that is the strongest reason to write it.

| Non-goal | Why we exclude it |
|---|---|
| **Defending the model against direct jailbreaks** | Different attack vector. Tools you want for this: HarmBench, JailbreakBench, NeMo Guardrails system-prompt-side, Llama-Guard. |
| **OS-level sandbox escapes** | Tools you want: gVisor, Firecracker, Bubblewrap, seccomp filters. `toolwall` runs *inside* the application; if the sandbox is broken, application-level defense is too late. |
| **Tool authentication / IAM** | We assume the tool is correctly authenticated upstream. If it is not, `toolwall` is irrelevant. |
| **Network-layer firewalling** | Tools you want: Cloudflare, AWS SG, iptables. We see semantic tool calls, not packets. |
| **Detecting *every* IPI variant** | Detection is statistical. We publish ASR; we do not claim 0 %. A claim of 0 % would be dishonest. |
| **Defending agents whose host process is already compromised** | If `A` has code execution in the host, they can monkey-patch `toolwall` itself. We do not pretend to defend against in-process tampering. |
| **Replacing security review of tools** | The list of allowed tools is the operator's responsibility; we enforce the policy they wrote, we do not write it for them. |
| **Defending against social-engineering against the human operator** | Agent says "please paste your password" — `toolwall` does not save you. |

---

## 7. Where `toolwall` fails open (the section reviewers will look for first)

This section is more important than the rest of the doc combined.

1. **Novel paraphrases.** The v0.2 judge was trained on 8,619 rows and misses most BIPIA attacks (see README). A skilled adversary can craft a payload that none of our patterns and nothing in the judge's training data resembles. We will see this in the wild. We expect ASR > 0 forever. Treat any vendor claiming 0 % as a vendor lying to you.
2. **Allowlisted but compromised hosts.** If your allowlist includes `paste.example.com` and an attacker controls a path on `paste.example.com`, the allowlist is the loaded gun pointing at you. Allowlist tighter than "domain"; allowlist by exact path or signed handle wherever feasible.
3. **Schema-lock scope.** `schema_lock=True` checks the wrapped Python function before each call. It does not see tool descriptions held by an MCP client or a remote server.
4. **Judge-as-attack-surface.** The judge model is itself an LLM and is itself injection-vulnerable. We mitigate by (a) running pattern detectors *before* the judge, (b) using a classifier that outputs only a probability, never text, (c) capping judge input at 512 tokens. We do not claim immunity.
5. **Adapter coverage gaps.** If you wrap `fetch_url` but the agent also has `read_file` and you forgot to wrap it, `read_file` is unprotected. A config scanner is planned; until then, wrapping every tool is operator discipline.
6. **Time-of-check / time-of-use.** Argument inspection happens before dispatch. If the tool re-reads the argument from a mutable source (e.g., a database row the attacker can race), TOCTOU applies. We document this and recommend tools dereference arguments once and trust them as values.
7. **Memory layer.** As stated in §4.8, memory writes routed around the tool boundary are invisible to us.
8. **Multi-agent crosstalk.** If two agents communicate via a shared queue, the queue is a tool from each agent's perspective — but only if it is registered as one. Un-registered side channels are out of scope.
9. **Long-tail of legitimate text that looks like an attack.** False positives are real. We surface the evidence; we do not silently drop. If you want fail-closed, set `Policy.on_low_confidence="block"`. The default is `"redact"` to preserve utility.
10. **The judge model itself can be exfiltrated.** It is on Hugging Face. Adversaries will fine-tune their own evader against it. We rotate the judge revision on a 90-day cadence and bake the revision SHA into `toolwall/detect/judge.py`. There is no defense against an adversary who keeps up.

---

## 8. Compliance with stated frameworks

- **OWASP Top 10 for Large Language Model Applications (2025).** Addresses LLM01 Prompt Injection (in-scope, response-side), LLM02 Sensitive Information Disclosure (egress denylist + redaction), LLM06 Excessive Agency (capability-based policy), LLM10 Unbounded Consumption (rate, size and cost limits).
- **OWASP Top 10 for Agentic Applications (December 2025).** Relevant to ASI01 Agent Goal Hijack (indirect prompt injection in tool output), ASI02 Tool Misuse & Exploitation (argument and egress policy), ASI04 Agentic Supply Chain Vulnerabilities (tool-schema poisoning and rug-pull, partial) and ASI06 Memory & Context Poisoning (partial, see §4.8). Does not address ASI03 Identity & Privilege Abuse or ASI07 Insecure Inter-Agent Communication.
- **NIST AI 100-2e (Adversarial Machine Learning, 2025).** Covers the IPI taxonomy.

We do **not** claim certification under any of these. We claim coverage of specific items, naming the items.

---

## 9. Threat-model review log

Each material change to `toolwall`'s defended surface updates this file and bumps the major version of the threat model.

| Version | Reviewer | Change |
|---|---|---|
| 0.1.0 | Muhammad Hasnain (author) | Initial document for v0.1.x. |

Reviewers, please file issues with tag `threat-model` at https://github.com/bryteai/toolwall/issues.

---

*If you read this far and the document failed to answer "what cannot `toolwall` do?", file an issue — that is a documentation bug.*
