/**
 * MCP server wired up with @bryteai/toolwall-core.
 *
 * - Streamable HTTP transport (not SSE)
 * - Every tool handler passes through `toolwall(handler, { policy })`
 *   so any tool response with an IPI score >= mcpPolicy().threshold
 *   is rejected with a structured `Blocked` error.
 * - Audit log written to KV on every tool invocation.
 */

import { Blocked, mcpPolicy, toolwall } from "@bryteai/toolwall-core";
import { audit } from "./audit.js";

export interface ToolDef {
  readonly name: string;
  readonly description: string;
  readonly handler: (input: unknown) => Promise<string>;
}

const POLICY = mcpPolicy();

/**
 * Wrap a list of MCP tool definitions with toolwall. Returns a fresh
 * descriptor list — never mutates input. Each handler is also wrapped
 * with an audit-logger so every call leaves a trail.
 */
export function wireTools(
  tools: readonly ToolDef[],
  auditKv: KVNamespace,
  sessionId: string,
): ToolDef[] {
  return tools.map((t) => {
    const firewalled = toolwall(t.handler, { policy: POLICY });
    const wrapped: ToolDef["handler"] = async (input) => {
      const ts = new Date().toISOString();
      try {
        const out = await firewalled(input);
        await audit(auditKv, {
          ts,
          session: sessionId,
          tool: t.name,
          decision: "allow",
        });
        return out;
      } catch (err) {
        if (err instanceof Blocked) {
          const ev = err.evidence as {
            score?: number;
            detections?: { kind: string; score: number }[];
          };
          await audit(auditKv, {
            ts,
            session: sessionId,
            tool: t.name,
            decision: "block",
            reason: err.reason,
            ...(typeof ev.score === "number" ? { score: ev.score } : {}),
            ...(ev.detections ? { detections: ev.detections } : {}),
          });
        }
        throw err;
      }
    };
    return { name: t.name, description: t.description, handler: wrapped };
  });
}

export const EXAMPLE_TOOLS: ToolDef[] = [
  {
    name: "echo",
    description: "Echo a string back. Useful for transport smoke tests.",
    handler: async (input) => {
      const v = (input as { value?: unknown })?.value;
      return typeof v === "string" ? v : JSON.stringify(v ?? null);
    },
  },
];
