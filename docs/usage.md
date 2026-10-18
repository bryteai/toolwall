# Usage

## 1. Wrap a tool
```python
from toolwall import Blocked, policy, toolwall

@toolwall(policy=policy.web_fetch(url_allowlist=("docs.python.org",)))
def fetch_url(url: str) -> str:
    return requests.get(url, timeout=10).text

try:
    page = fetch_url("https://docs.python.org/3/")
except Blocked as exc:
    print(exc.reason, exc.evidence)        # e.g. "ipi-detected" {"score": 0.99, "threshold": 0.6}
```
Sync and async functions are both supported. Every call runs, in order:
1. **Schema checks** (if enabled): `schema_lock`, `scan_schema`.
2. **Request checks** on the arguments: URL allow/deny lists, outbound-write denylist,
   path scope, shell metacharacters, per-argument regex.
3. **Budgets**: calls per minute, cost.
4. The tool itself.
5. **Response checks**: size cap, named redactions, then the detectors (rules, then the judge).
6. One **audit** record.

## 2. Policy presets
| Preset | For | What it turns on |
|---|---|---|
| `policy.web_fetch(url_allowlist=(), response_max_bytes=500_000, response_ipi_threshold=0.6)` | fetching pages | outbound writes denied, redacts EMAIL / API_KEY / PHONE_E164, shell metacharacters blocked |
| `policy.file_read(path_scope=...)` | reading files | path must stay inside `path_scope`, no outbound writes, redacts EMAIL / API_KEY / SSN_US |
| `policy.mcp(url_allowlist=())` | MCP tools | as `web_fetch`, plus `schema_lock` and `scan_schema` |
| `policy.shell(arg_validators={...})` | shell-like tools | metacharacters blocked, per-argument regex |
| `policy.passthrough()` | staging | audit only, nothing enforced — not for production |

Every preset accepts any `Policy` field as a keyword override.

## 3. Every `Policy` field
| Field | Type, default | Effect |
|---|---|---|
| `url_allowlist` | tuple of host globs, `()` | URL arguments must match one entry (empty = no allowlist) |
| `url_denylist` | tuple, `()` | URL arguments matching an entry are refused; denies win |
| `egress_denylist` | tuple, `("*",)` | when the tool has a `method`, `http_method` or `verb` argument of POST/PUT/PATCH/DELETE, URL arguments to matching hosts are refused |
| `path_scope` | str or None | path arguments must resolve inside this directory |
| `redact` | tuple of names, `()` | replace matches in the response: `EMAIL`, `API_KEY`, `PHONE_E164`, `SSN_US`, `IBAN`, `CREDIT_CARD` |
| `response_max_bytes` | int, 1,000,000 | larger responses raise `BudgetExceeded("response-too-large")` |
| `response_ipi_threshold` | float 0–1, 0.6 | detector score at or above this blocks the response |
| `calls_per_min` | int, 60 | sliding-window rate limit per wrapped function |
| `cost_cents_max` | int or None | soft cap on cumulative cost in the same window |
| `schema_lock` | bool, False | block if the tool's name, docstring, signature or `description` changed since it was wrapped |
| `scan_schema` | bool, False | score the tool's own schema text with the detectors |
| `shell_metachar_block` | bool, True | refuse string arguments containing shell metacharacters |
| `arg_validators` | dict name → regex | the argument must fully match its regex |
| `on_low_confidence` | `"redact"` / `"block"` / `"allow"`, `"redact"` | behaviour for scores in 0.3 ≤ score < threshold. `"redact"` records the decision as redact and returns the PII-redacted text; it does **not** remove the suspicious span. Use `"block"` to refuse instead |

## 4. Decisions and exceptions
All refusals raise `toolwall.Blocked` (or a subclass) with a stable `reason` slug and an
`evidence` dict. The agent should treat a `Blocked` as "this tool returned nothing usable".

| `reason` | Raised by | Class |
|---|---|---|
| `ipi-detected` | response score ≥ threshold | `Blocked` |
| `ipi-low-confidence-block` | uncertain band with `on_low_confidence="block"` | `Blocked` |
| `schema-mismatch` / `schema-poisoned` | `schema_lock` / `scan_schema` | `Blocked` |
| `url-not-allowlisted`, `url-denylisted`, `egress-denied`, `path-out-of-scope`, `shell-metachar-in-arg`, `arg-validator-failed` | request checks | `PolicyViolation` |
| `rate-limit`, `cost-budget`, `response-too-large` | budgets | `BudgetExceeded` |

## 5. The audit log
One JSON line per decision, appended to `$TOOLWALL_AUDIT_LOG` (default `./.toolwall-audit.log`):
`ts`, `decision` (`allow` / `redact` / `block`), `tool` (module.function), `reason`, and a
size-truncated `evidence` object (score, redaction names, bytes). Tool output text is not logged.

## 6. Command line
```bash
toolwall check response.json            # rules only
toolwall check --judge response.json    # rules + judge
cat page.txt | toolwall check -         # read from stdin
toolwall check --threshold 0.8 page.txt
```
| Option | Meaning |
|---|---|
| `path` | file to score, or `-` for stdin |
| `--judge` | also run the classifier (needs the `judge` extra) |
| `--threshold` | block threshold, default 0.6 |

Output is JSON (`blocked`, `score`, `threshold`, `detections`). Exit code 0 = allowed, 2 = blocked.

## 6b. MCP proxy
See [proxy.md](proxy.md): `toolwall proxy [--judge] [--threshold] [--mode block|warn] -- <server command>`.

## 7. Framework adapters
Each adapter exposes one function, `wrap(..., policy=...)`:

| Adapter | Wraps | Example |
|---|---|---|
| `toolwall.adapters.claude_sdk` | a Claude Agent SDK tool | `examples/claude_sdk/quickstart.py` |
| `toolwall.adapters.crewai` | a CrewAI tool | `examples/crewai/quickstart.py` |
| `toolwall.adapters.langgraph` | a LangGraph tool | `examples/langgraph/quickstart.py` |
| `toolwall.adapters.openai_agents` | an OpenAI Agents SDK tool | `examples/openai_agents/quickstart.py` |
| `toolwall.adapters.mcp` | every tool registered on a FastMCP server | `examples/mcp/quickstart.py` |

## 8. Demo
`python examples/arsenal_demo/demo.py` runs six tool responses through toolwall (five handled
correctly, one known miss) and `--try "<text>"` scores your own payload.
