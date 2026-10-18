/**
 * `__PROJECT_NAME__` — Cloudflare Workers MCP server (Streamable HTTP)
 * with toolwall firewall pre-wired.
 *
 * Routes:
 *   GET  /.well-known/oauth-authorization-server  RFC 8414 metadata
 *   GET  /authorize                               OAuth 2.1 PKCE start
 *   POST /token                                   OAuth 2.1 token exchange
 *   POST /mcp                                     Streamable HTTP endpoint
 *
 * The Durable Object `McpSession` is the per-session state holder
 * (one DO per `Mcp-Session-Id` header).
 */

import * as oauth from "./oauth.js";
import { EXAMPLE_TOOLS, wireTools } from "./mcp.js";
import { Blocked } from "@bryteai/toolwall-core";

export interface Env {
  readonly AUDIT: KVNamespace;
  readonly OAUTH: KVNamespace;
  readonly MCP_SESSION: DurableObjectNamespace;
  readonly OAUTH_ISSUER: string;
  readonly OAUTH_CLIENT_ID: string;
  readonly OAUTH_CLIENT_SECRET: string;
  readonly OAUTH_REDIRECT_URIS: string;
}

interface JsonRpcRequest {
  readonly jsonrpc: "2.0";
  readonly id: string | number;
  readonly method: string;
  readonly params?: Record<string, unknown>;
}

interface JsonRpcResponse {
  readonly jsonrpc: "2.0";
  readonly id: string | number;
  readonly result?: unknown;
  readonly error?: { code: number; message: string; data?: unknown };
}

export default {
  async fetch(req: Request, env: Env): Promise<Response> {
    const url = new URL(req.url);
    if (
      req.method === "GET" &&
      url.pathname === "/.well-known/oauth-authorization-server"
    ) {
      return oauth.metadata(env);
    }
    if (req.method === "GET" && url.pathname === "/authorize") {
      return oauth.authorize(req, env);
    }
    if (req.method === "POST" && url.pathname === "/token") {
      return oauth.token(req, env);
    }
    if (req.method === "POST" && url.pathname === "/mcp") {
      return handleMcp(req, env);
    }
    return new Response("not found", { status: 404 });
  },
} satisfies ExportedHandler<Env>;

async function handleMcp(req: Request, env: Env): Promise<Response> {
  const principal = await oauth.verifyBearer(req, env);
  if (!principal) {
    return new Response(
      JSON.stringify({ error: "invalid_token" }),
      {
        status: 401,
        headers: {
          "content-type": "application/json",
          "www-authenticate": `Bearer realm="${env.OAUTH_ISSUER}"`,
        },
      },
    );
  }

  const sessionId =
    req.headers.get("mcp-session-id") ?? crypto.randomUUID();
  const id = env.MCP_SESSION.idFromName(sessionId);
  const stub = env.MCP_SESSION.get(id);
  const forwarded = new Request(req, {
    headers: new Headers({
      ...Object.fromEntries(req.headers),
      "mcp-session-id": sessionId,
      "x-toolwall-subject": principal.sub,
    }),
  });
  return stub.fetch(forwarded);
}

export class McpSession {
  private readonly env: Env;

  constructor(_state: DurableObjectState, env: Env) {
    this.env = env;
  }

  async fetch(req: Request): Promise<Response> {
    const sessionId = req.headers.get("mcp-session-id") ?? "anon";
    const body = (await req.json()) as JsonRpcRequest;
    const tools = wireTools(EXAMPLE_TOOLS, this.env.AUDIT, sessionId);

    if (body.method === "initialize") {
      return jsonRpc({
        jsonrpc: "2.0",
        id: body.id,
        result: {
          protocolVersion: "2025-06-18",
          capabilities: { tools: {} },
          serverInfo: { name: "__PROJECT_NAME__", version: "0.0.1" },
        },
      }, sessionId);
    }
    if (body.method === "tools/list") {
      return jsonRpc({
        jsonrpc: "2.0",
        id: body.id,
        result: {
          tools: tools.map((t) => ({
            name: t.name,
            description: t.description,
            inputSchema: { type: "object" },
          })),
        },
      }, sessionId);
    }
    if (body.method === "tools/call") {
      const params = body.params as { name?: string; arguments?: unknown };
      const tool = tools.find((t) => t.name === params.name);
      if (!tool) {
        return jsonRpc({
          jsonrpc: "2.0",
          id: body.id,
          error: { code: -32601, message: `unknown tool: ${params.name}` },
        }, sessionId);
      }
      try {
        const out = await tool.handler(params.arguments ?? {});
        return jsonRpc({
          jsonrpc: "2.0",
          id: body.id,
          result: { content: [{ type: "text", text: out }] },
        }, sessionId);
      } catch (err) {
        if (err instanceof Blocked) {
          return jsonRpc({
            jsonrpc: "2.0",
            id: body.id,
            error: {
              code: -32000,
              message: "toolwall_blocked",
              data: { reason: err.reason, evidence: err.evidence },
            },
          }, sessionId);
        }
        throw err;
      }
    }
    return jsonRpc({
      jsonrpc: "2.0",
      id: body.id,
      error: { code: -32601, message: `method not found: ${body.method}` },
    }, sessionId);
  }
}

function jsonRpc(payload: JsonRpcResponse, sessionId: string): Response {
  return new Response(JSON.stringify(payload), {
    headers: {
      "content-type": "application/json",
      "mcp-session-id": sessionId,
    },
  });
}
