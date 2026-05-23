import { describe, expect, it } from "vitest";
import { TOOLWALL_WRAPPED } from "../src/decorator.js";
import { wrap } from "../src/adapters/mcp.js";
import { mcpPolicy } from "../src/policy.js";

class FakeMcpServer {
  registered: { name: string; handler: (...args: unknown[]) => unknown }[] = [];
  tool(name: string, _schema: unknown, handler: (...args: unknown[]) => unknown): void {
    this.registered.push({ name, handler });
  }
}

describe("MCP server adapter", () => {
  it("wraps handlers registered AFTER wrap() is called", async () => {
    const server = new FakeMcpServer();
    wrap(server, { policy: mcpPolicy() });

    server.tool("echo", { x: "string" }, async ({ value }: { value: string }) =>
      `echo:${value}`,
    );
    const reg = server.registered[0]!;
    expect(
      (reg.handler as unknown as Record<symbol, unknown>)[TOOLWALL_WRAPPED],
    ).toBe(true);
    const out = await reg.handler({ value: "ok" });
    expect(out).toBe("echo:ok");
  });

  it("is idempotent at the server level", () => {
    const server = new FakeMcpServer();
    const first = server.tool;
    wrap(server, { policy: mcpPolicy() });
    const afterFirst = server.tool;
    wrap(server, { policy: mcpPolicy() });
    const afterSecond = server.tool;
    expect(afterFirst).not.toBe(first);
    expect(afterSecond).toBe(afterFirst);
  });

  it("does not double-wrap an already-wrapped handler", async () => {
    const server = new FakeMcpServer();
    wrap(server, { policy: mcpPolicy() });
    const handler = async () => "ok";
    server.tool("a", {}, handler);
    const first = server.registered[0]!.handler;
    server.tool("b", {}, first);
    const second = server.registered[1]!.handler;
    expect(second).toBe(first);
  });

  it("passes through registration calls with no handler argument", () => {
    const server = new FakeMcpServer();
    wrap(server, { policy: mcpPolicy() });
    // No function-typed arg → original tool() invoked with originals.
    expect(() => server.tool("noop", {} as never, null as never)).not.toThrow();
  });
});
