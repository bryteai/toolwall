/**
 * Shared types for `@bryteai/toolwall-core`.
 *
 * Mirror of `toolwall/_types` on the Python side. We keep the shape
 * identical so that anyone porting a policy between stacks (e.g. a
 * Cloudflare Worker MCP in TS that imports a Python-authored policy
 * JSON) does not get bitten by name drift.
 */

export interface Detection {
  /** Stable identifier of the detector that fired. */
  readonly kind: string;
  /** Inclusive-exclusive character span within the inspected text. */
  readonly span: readonly [number, number];
  /** Detector confidence in `[0, 1]`. Worst score wins. */
  readonly score: number;
  /** Free-form evidence the detector attached for the audit log. */
  readonly evidence: Readonly<Record<string, unknown>>;
}

export interface DetectorResult {
  readonly score: number;
  readonly detections: readonly Detection[];
}

export interface Detector {
  score(text: string): DetectorResult;
}

export interface BlockedDetails {
  readonly reason: string;
  readonly evidence: Readonly<Record<string, unknown>>;
}

export class Blocked extends Error {
  readonly reason: string;
  readonly evidence: Readonly<Record<string, unknown>>;
  constructor({ reason, evidence }: BlockedDetails) {
    super(`toolwall blocked: ${reason}`);
    this.name = "Blocked";
    this.reason = reason;
    this.evidence = evidence;
  }
}
