import { describe, expect, it } from "vitest";
import { TOOLWALL_WRAPPED } from "../src/decorator.js";
import { wrap } from "../src/adapters/vercel-ai.js";
import { webFetchPolicy } from "../src/policy.js";

describe("Vercel AI SDK adapter", () => {
  it("wraps execute and preserves other fields", async () => {
    const tool = {
      description: "Echo back the input",
      parameters: { x: "string" },
      execute: async ({ value }: { value: string }) => `echo:${value}`,
    };
    const wrapped = wrap(tool, { policy: webFetchPolicy() });
    expect(wrapped.description).toBe(tool.description);
    expect(wrapped.parameters).toBe(tool.parameters);
    expect(wrapped).not.toBe(tool); // new descriptor, not mutated
    expect(typeof wrapped.execute).toBe("function");

    const out = await wrapped.execute!({ value: "hi" });
    expect(out).toBe("echo:hi");
  });

  it("rejects descriptors without an execute function", () => {
    expect(() =>
      wrap({ description: "no execute" }, { policy: webFetchPolicy() }),
    ).toThrow(TypeError);
  });

  it("is idempotent — second wrap returns the same descriptor", () => {
    const tool = {
      description: "x",
      execute: async () => "ok",
    };
    const once = wrap(tool, { policy: webFetchPolicy() });
    const twice = wrap(once, { policy: webFetchPolicy() });
    expect(twice).toBe(once);
  });

  it("the new execute carries the toolwall sentinel", () => {
    const tool = { description: "x", execute: async () => "ok" };
    const wrapped = wrap(tool, { policy: webFetchPolicy() });
    expect(
      (wrapped.execute as unknown as Record<symbol, unknown>)[
        TOOLWALL_WRAPPED
      ],
    ).toBe(true);
  });
});
