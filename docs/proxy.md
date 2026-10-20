# `toolwall proxy` — protect any MCP server without changing code

`toolwall proxy` sits between an MCP client (Claude Desktop, Claude Code, Cursor, or any client
that launches stdio servers) and an MCP server. The client starts the proxy; the proxy starts
the real server and relays every message, checking two of them:

| Message | Check | In `block` mode |
|---|---|---|
| `tools/list` result | Each tool's name, description and input schema are scored (poisoned descriptions) and pinned by SHA-256 when first seen (rug-pull) | The tool is removed from the list |
| `tools/call` result | The text content is scored for indirect prompt injection | The result is replaced by an error telling the model the output was withheld |

`--mode warn` changes nothing and only writes audit records. Every decision is appended to
`$TOOLWALL_AUDIT_LOG` (default `./.toolwall-audit.log`, relative to the directory the client
starts the proxy in — set the variable to an absolute path).

## Install
```bash
pip install "toolwall-guard[judge]"     # puts the `toolwall` command on your PATH
```

## Use it
Put `toolwall proxy [options] --` in front of the server command you already use.

**Claude Code**
```bash
claude mcp add fetch -- toolwall proxy --judge -- uvx mcp-server-fetch
```

**Claude Desktop / Cursor** (`claude_desktop_config.json` / `.cursor/mcp.json`)
```json
{
  "mcpServers": {
    "fetch": {
      "command": "toolwall",
      "args": ["proxy", "--judge", "--", "uvx", "mcp-server-fetch"],
      "env": { "TOOLWALL_AUDIT_LOG": "/home/you/.toolwall-audit.log" }
    }
  }
}
```
If the client cannot find `toolwall`, use the full path printed by `which toolwall`.

## Options
| Option | Meaning |
|---|---|
| `--judge` | also run the classifier (first use downloads about 750 MB; CPU is fine) |
| `--threshold` | block threshold, default 0.6 |
| `--mode block` / `--mode warn` | enforce (default) or only audit |
| `--untrusted-delimiters llama3` | remove Llama 3 control tokens from every string in tool results (both modes), for models that read tool output in a separate untrusted role, such as Meta-SecAlign or SecPO; see [boundary.md](boundary.md) |
| `--` | everything after it is the server command |

## What it does not do
- It covers **stdio** servers. Remote (HTTP) MCP servers are not proxied yet.
- It checks what the server returns, not what the client sends.
- A tool removed for a changed description stays removed until the client restarts the proxy.
- Detection has the limits described in [Evaluation](evaluation.md): explicit overrides and
  requests for tool actions are caught well; instructions that only change the answer are often
  missed.

## Tested
`tests/test_proxy.py` runs the proxy against a fake server (poisoned description removed,
injected output withheld, rug-pull removed, warn mode unchanged). It was also run by hand in
front of the reference `mcp-server-fetch`: a normal page passed (score 0.0) and a local page
containing an injected instruction was withheld (score 1.0).
