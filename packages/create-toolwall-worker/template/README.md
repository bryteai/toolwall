# __PROJECT_NAME__

Cloudflare Workers MCP server scaffolded by
[`create-toolwall-worker`](https://github.com/bryteai/toolwall) with the
toolwall firewall pre-wired.

## What you get

- Streamable HTTP transport (not SSE — that lane is dead)
- OAuth 2.1 PKCE (KV-backed token store)
- `@bryteai/toolwall-core` wrapping every tool handler
- KV audit log of every tool call (90-day retention by default)
- Durable Object session state — one `McpSession` per `Mcp-Session-Id`

## Setup

```bash
pnpm install
wrangler kv namespace create AUDIT
wrangler kv namespace create OAUTH
# paste the IDs into wrangler.toml
wrangler secret put OAUTH_CLIENT_SECRET
wrangler deploy
```

## Add your own tools

Open `src/mcp.ts` and append to `EXAMPLE_TOOLS`. Every handler is
automatically wrapped with `toolwall()` using the `mcpPolicy()` profile
(IPI block threshold 0.55, response size cap 200 KB, redaction of
email / API keys / bearer tokens / private-IP URLs).

To tighten or loosen the policy, edit `POLICY` in `src/mcp.ts`.

## Audit log

Every tool call writes one row to KV under
`<iso-timestamp>:<session-id>:<uuid>`. Inspect with:

```bash
wrangler kv key list --binding=AUDIT --prefix="2026-"
```

Each entry is JSON: `{ ts, session, tool, decision, score?, detections?, reason? }`.

## License

Apache-2.0.
