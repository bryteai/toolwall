/**
 * `@bryteai/toolwall-core` — tool-boundary firewall for AI agents.
 *
 * Four-line example::
 *
 *     import { toolwall, webFetchPolicy } from "@bryteai/toolwall-core";
 *
 *     const fetchUrl = toolwall(
 *       async (url: string) => (await fetch(url)).text(),
 *       { policy: webFetchPolicy() },
 *     );
 *
 * Adapters live under `@bryteai/toolwall-core/adapters/*`.
 */

export { toolwall, TOOLWALL_WRAPPED } from "./decorator.js";
export {
  fileReadPolicy,
  mcpPolicy,
  PolicySchema,
  policy,
  RedactKindSchema,
  webFetchPolicy,
} from "./policy.js";
export type { Policy, RedactKind } from "./policy.js";
export { Blocked } from "./types.js";
export type {
  BlockedDetails,
  Detection,
  Detector,
  DetectorResult,
} from "./types.js";
export { CompositeDetector } from "./detect/composite.js";
export type { CompositeOptions } from "./detect/composite.js";
