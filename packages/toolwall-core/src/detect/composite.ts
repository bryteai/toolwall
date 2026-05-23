/**
 * Composite detector — runs every sub-detector and returns the worst
 * score with the union of detections, matching the Python shape.
 *
 * Judge model is intentionally NOT in this port. The TS distribution
 * is the lightweight rule layer; agents that want the judge call into
 * a hosted endpoint via an injected `Detector`.
 */

import type { Detection, Detector, DetectorResult } from "../types.js";
import * as markdownExfil from "./markdown-exfil.js";
import * as patterns from "./patterns.js";
import * as unicodeTags from "./unicode-tags.js";

export interface CompositeOptions {
  readonly markdownAllowlist?: readonly string[];
  /** Optional remote judge detector to chain after rules. */
  readonly judge?: Detector;
}

export class CompositeDetector implements Detector {
  private readonly markdownAllowlist: readonly string[];
  private readonly judge: Detector | undefined;

  constructor(opts: CompositeOptions = {}) {
    this.markdownAllowlist = opts.markdownAllowlist ?? [];
    this.judge = opts.judge;
  }

  score(text: string): DetectorResult {
    const detections: Detection[] = [];
    detections.push(...patterns.detect(text));
    detections.push(...unicodeTags.detect(text));
    detections.push(...markdownExfil.detect(text, this.markdownAllowlist));
    if (this.judge) {
      const j = this.judge.score(text);
      detections.push(...j.detections);
    }
    if (detections.length === 0) return { score: 0, detections: [] };
    const worst = detections.reduce((acc, d) => (d.score > acc ? d.score : acc), 0);
    return { score: worst, detections };
  }
}
