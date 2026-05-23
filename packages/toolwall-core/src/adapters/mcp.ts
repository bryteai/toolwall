/**
 * Adapter for `@modelcontextprotocol/sdk` servers.
 *
 * The TS MCP SDK exposes tool registration via `server.tool(name, schema, handler)`.
 * Our middleware patches `server.tool` so every registered handler is
 * wrapped with `toolwall()` before the SDK stores it. We refuse to fork.
 *
 * Usage::
 *
 *     import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
 *     import { wrap, mcpPolicy } from "@bryteai/toolwall-core/adapters/mcp";
 *
 *     const server = new McpServer({ name: "demo", version: "0.1.0" });
 *     wrap(server, { policy: mcpPolicy() });
 *     server.tool("fetch_url", schema, async ({ url }) => ...);
 */

import { toolwall, TOOLWALL_WRAPPED } from "../decorator.js";
import type { Policy } from "../policy.js";
import type { Detector } from "../types.js";

export { mcpPolicy } from "../policy.js";

// Minimal structural type for the MCP server bits we touch.
interface McpServerLike {
  tool: (...args: unknown[]) => unknown;
}

export interface WrapOptions {
  readonly policy: Policy;
  readonly detector?: Detector;
}

/**
 * Patch an MCP server so every tool registered after this call has
 * its handler firewalled. Idempotent — calling `wrap` twice on the
 * same server is a no-op.
 */
export function wrap<S extends McpServerLike>(
  server: S,
  options: WrapOptions,
): S {
  const flag = Symbol.for("toolwall.mcp.wrapped");
  if ((server as unknown as Record<symbol, unknown>)[flag]) return server;

  const original = server.tool.bind(server) as (
    ...args: unknown[]
  ) => unknown;

  const patched = (...args: unknown[]): unknown => {
    // The handler is the LAST function-typed argument the SDK accepts.
    let handlerIndex = -1;
    for (let i = args.length - 1; i >= 0; i -= 1) {
      if (typeof args[i] === "function") {
        handlerIndex = i;
        break;
      }
    }
    if (handlerIndex === -1) return original(...args);

    const handler = args[handlerIndex] as (
      ...handlerArgs: unknown[]
    ) => unknown;
    if ((handler as unknown as Record<symbol, unknown>)[TOOLWALL_WRAPPED]) {
      return original(...args);
    }

    const firewalled = toolwall(handler, {
      policy: options.policy,
      ...(options.detector ? { detector: options.detector } : {}),
    });
    const newArgs = [...args];
    newArgs[handlerIndex] = firewalled;
    return original(...newArgs);
  };

  Object.defineProperty(server, "tool", {
    value: patched,
    writable: true,
    configurable: true,
  });
  Object.defineProperty(server, flag, {
    value: true,
    enumerable: false,
  });
  return server;
}
