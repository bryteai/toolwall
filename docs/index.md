# toolwall documentation

toolwall checks the output of an AI agent's tools (web pages, emails, files, API and MCP
results) for indirect prompt injection before the text reaches the model. It combines a
declarative policy, fast rule-based detectors and a small fine-tuned classifier.

| Page | Contents |
|---|---|
| [Installation](installation.md) | Requirements, supported platforms, extras, offline use, environment variables |
| [Usage](usage.md) | The decorator, policy presets and every policy field, decisions and exceptions, the audit log, the CLI, framework adapters, the demo |
| [MCP proxy](proxy.md) | Protect any stdio MCP server from Claude Desktop, Claude Code or Cursor without code |
| [Evaluation](evaluation.md) | What was measured, the results, and the known failure modes |

## Features
- **One decorator** around any sync or async tool: `@toolwall(policy=...)`.
- **Policy layer** (before and after the call): URL allowlist and denylist, outbound-write
  denylist, filesystem scope, shell-metacharacter block, per-argument regex, size, rate and
  cost limits, named redaction of e-mail addresses, API keys, phone numbers and more.
- **Detectors** on every response:
  - instruction-override, exfiltration and role-smuggling patterns (each cited to a public source);
  - hidden Unicode (tag characters, zero-width, bidirectional controls);
  - markdown-image exfiltration sinks;
  - decode-and-rescan for base64, hex, URL encoding, gzip and ROT13;
  - the judge, `toolwall-judge-v0.2` (DeBERTa-v3-base, 184M parameters, CPU).
- **MCP protection**: tool-schema lock (rug-pull) and schema scanning (full-schema poisoning).
- **Audit log**: one JSON record per decision.
- **Adapters** for the Claude Agent SDK, CrewAI, LangGraph, OpenAI Agents SDK and MCP (Python).
- **CLI**: `toolwall check` scores a saved response; exit code 2 means blocked.

## Status
Research prototype, version 0.2.0. It detects many explicit injections and misses most
instructions that change the content of the answer (see [Evaluation](evaluation.md)).
Use it as one layer, not the only one.

## License and changes
- Code: Apache-2.0 ([LICENSE](../LICENSE)). Judge weights: Apache-2.0, base model MIT.
- Changes: [CHANGELOG.md](../CHANGELOG.md). Security reports: [SECURITY.md](../SECURITY.md).
- Threat model and non-goals: [THREAT_MODEL.md](../THREAT_MODEL.md).
