/**
 * Adapter for the Vercel AI SDK v6 (`ai` package).
 *
 * Vercel AI tools are objects of the shape::
 *
 *     {
 *       description: string,
 *       parameters: ZodSchema,
 *       execute: (args, ctx) => Promise<unknown>,
 *     }
 *
 * We wrap the `execute` function with `toolwall()` and return a new
 * object with the same shape. Idempotent via the `TOOLWALL_WRAPPED`
 * symbol on the patched execute.
 *
 * Usage::
 *
 *     import { tool } from "ai";
 *     import { wrap, webFetchPolicy } from "@bryteai/toolwall-core/adapters/vercel-ai";
 *
 *     const fetchUrl = wrap(
 *       tool({
 *         description: "Fetch a URL",
 *         parameters: z.object({ url: z.string() }),
 *         execute: async ({ url }) => (await fetch(url)).text(),
 *       }),
 *       { policy: webFetchPolicy() },
 *     );
 */

import { toolwall, TOOLWALL_WRAPPED } from "../decorator.js";
import type { Policy } from "../policy.js";
import type { Detector } from "../types.js";

export { webFetchPolicy, mcpPolicy } from "../policy.js";

interface VercelToolLike {
  execute?: (...args: unknown[]) => unknown;
  [key: string]: unknown;
}

export interface WrapOptions {
  readonly policy: Policy;
  readonly detector?: Detector;
}

/**
 * Wrap a Vercel AI SDK tool descriptor's `execute` with a toolwall
 * policy. Returns a NEW descriptor (does not mutate input) so it can
 * be safely co-located with non-wrapped tools in the same `tools: {}`
 * object passed to `generateText` / `streamText`.
 */
export function wrap<T extends VercelToolLike>(
  toolDescriptor: T,
  options: WrapOptions,
): T {
  if (typeof toolDescriptor.execute !== "function") {
    throw new TypeError(
      "expected Vercel AI tool descriptor with an `execute` function",
    );
  }
  const exec = toolDescriptor.execute;
  if ((exec as unknown as Record<symbol, unknown>)[TOOLWALL_WRAPPED]) {
    return toolDescriptor;
  }
  const firewalled = toolwall(exec, {
    policy: options.policy,
    ...(options.detector ? { detector: options.detector } : {}),
  });
  return { ...toolDescriptor, execute: firewalled } as T;
}
