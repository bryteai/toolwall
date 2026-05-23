/**
 * Hidden-character detector — feature-parity with the Python module.
 *
 * Three classes:
 *
 * 1. U+E0000 tag block (Goodside 2024 / CVE-2021-42574 family).
 * 2. Zero-width characters: U+200B/200C/200D/2060/FEFF.
 * 3. Bidi overrides: U+202A..202E and U+2066..2069.
 *
 * If we see any tag-block runs >= 3 chars OR any bidi override, we
 * return a single Detection at score 1.0 (these never appear in
 * legitimate tool responses).
 */

import type { Detection } from "../types.js";

const TAG_RE = /[\u{E0000}-\u{E007F}]+/gu;
const ZERO_WIDTH_RE = /[​‌‍⁠﻿]/gu;
const BIDI_RE = /[‪-‮⁦-⁩]/gu;

export function detect(text: string): readonly Detection[] {
  const out: Detection[] = [];

  let m: RegExpExecArray | null;
  TAG_RE.lastIndex = 0;
  while ((m = TAG_RE.exec(text)) !== null) {
    if (m[0].length >= 3) {
      out.push({
        kind: "unicode-tag-block",
        span: [m.index, m.index + m[0].length],
        score: 1.0,
        evidence: {
          chars: m[0].length,
          first_codepoint: `U+${m[0].codePointAt(0)!.toString(16).toUpperCase()}`,
        },
      });
    }
  }

  BIDI_RE.lastIndex = 0;
  while ((m = BIDI_RE.exec(text)) !== null) {
    out.push({
      kind: "bidi-override",
      span: [m.index, m.index + m[0].length],
      score: 0.95,
      evidence: { codepoint: `U+${m[0].codePointAt(0)!.toString(16).toUpperCase()}` },
    });
  }

  ZERO_WIDTH_RE.lastIndex = 0;
  let zwCount = 0;
  while ((m = ZERO_WIDTH_RE.exec(text)) !== null) {
    zwCount += 1;
  }
  if (zwCount >= 3) {
    out.push({
      kind: "zero-width-cluster",
      span: [0, text.length],
      score: 0.7,
      evidence: { count: zwCount },
    });
  }

  return out;
}
