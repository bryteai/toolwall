/**
 * The `toolwall()` higher-order function — wraps any async tool
 * callable with the three-layer firewall.
 *
 *   1. (request layer is enforced inside adapters; the bare callable
 *       wrapper has no visibility into URL/path args without a contract)
 *   2. detector layer  — composite IPI score on the response
 *   3. enforcement     — redact / quarantine / block
 *
 * Sync callables are accepted too; we await the result either way.
 */

import { CompositeDetector } from "./detect/composite.js";
import type { Policy } from "./policy.js";
import { redact } from "./redact.js";
import type { Detector } from "./types.js";
import { Blocked } from "./types.js";

export interface ToolwallOptions {
  readonly policy: Policy;
  /** Optional override; defaults to a stateless `CompositeDetector`. */
  readonly detector?: Detector;
}

const DEFAULT_DETECTOR = new CompositeDetector();

type AnyFn = (...args: unknown[]) => unknown;
type ToolFn<T extends AnyFn> = (
  ...args: Parameters<T>
) => Promise<Awaited<ReturnType<T>>>;

/**
 * Wrap a tool callable with a toolwall policy. Returns an async fn
 * that yields the sanitized response, throws `Blocked` on detection
 * above the threshold.
 *
 * The returned function preserves the original argument shape and
 * carries a `[Symbol.for("toolwall.wrapped")] = true` marker so
 * adapters can guard against double-wrapping.
 */
export function toolwall<T extends AnyFn>(
  fn: T,
  options: ToolwallOptions,
): ToolFn<T> {
  const detector = options.detector ?? DEFAULT_DETECTOR;
  const { policy } = options;

  const wrapped = async (
    ...args: Parameters<T>
  ): Promise<Awaited<ReturnType<T>>> => {
    const result = await Promise.resolve(fn(...(args as unknown[]))).then(
      (r) => r as Awaited<ReturnType<T>>,
    );

    if (typeof result !== "string") {
      // Non-string outputs (objects, dicts) pass through unmodified;
      // string fields nested deeper need an explicit traversal that
      // the adapters do per-framework (e.g. MCP content blocks).
      return result;
    }

    const truncated =
      result.length > policy.responseMaxBytes
        ? result.slice(0, policy.responseMaxBytes)
        : result;

    const { score, detections } = detector.score(truncated);
    if (score >= policy.responseIpiThreshold) {
      throw new Blocked({
        reason: "ipi-detected",
        evidence: {
          score,
          threshold: policy.responseIpiThreshold,
          detections,
        },
      });
    }

    const redacted = redact(truncated, policy.redact);
    return redacted as Awaited<ReturnType<T>>;
  };

  Object.defineProperty(wrapped, Symbol.for("toolwall.wrapped"), {
    value: true,
    enumerable: false,
  });
  return wrapped;
}

export const TOOLWALL_WRAPPED = Symbol.for("toolwall.wrapped");
