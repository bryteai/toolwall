/**
 * Regex-based detector. Pattern set mirrors the Python `attack_corpus.csv`
 * subset for the families a regex layer can cover (semantic-class
 * attacks fall through to the judge model).
 */

import type { Detection } from "../types.js";

interface Rule {
  readonly id: string;
  readonly kind: string;
  readonly pattern: RegExp;
  readonly score: number;
  readonly cite: string;
}

const RULES: readonly Rule[] = [
  {
    id: "ipi-001",
    kind: "imperative-instruction",
    pattern:
      /(?:ignore (?:all )?previous instructions|disregard (?:the )?(?:system|prior|earlier) (?:prompt|instructions)|forget everything (?:you|i) (?:were|was) told)/i,
    score: 0.92,
    cite: "InjecAgent ACL Findings 2024",
  },
  {
    id: "ipi-002",
    kind: "system-role-marker",
    pattern: /(?:<\|im_start\|>|<\|system\|>|\[INST\]|<\|begin_of_text\|>)/i,
    score: 0.88,
    cite: "Greshake AISec 2023",
  },
  {
    id: "ipi-003",
    kind: "exfiltration-imperative",
    pattern:
      /(?:send (?:the )?(?:user('s)?|my) (?:calendar|emails?|files?|api[_ ]?keys?|secrets?) (?:to|via)|post.{0,40}(?:attacker|webhook|requestbin|burpcollab))/i,
    score: 0.9,
    cite: "EchoLeak CVE-2025-32711",
  },
  {
    id: "ipi-004",
    kind: "tool-poisoning-mutation",
    pattern:
      /(?:after (?:this|the) (?:tool|server) was approved|now that (?:i|the tool) (?:have|has) been (?:approved|trusted))/i,
    score: 0.85,
    cite: "Invariant Labs MCP rug-pull 2026-04",
  },
  {
    id: "ipi-005",
    kind: "schema-poisoning",
    pattern:
      /(?:additional[_ ]?(?:hidden[_ ]?)?(?:instructions?|tool[_ ]?call)|invisible_field\s*[:=])/i,
    score: 0.82,
    cite: "CyberArk full-schema-poisoning 2026-05",
  },
];

export function detect(text: string): readonly Detection[] {
  const out: Detection[] = [];
  for (const rule of RULES) {
    const m = rule.pattern.exec(text);
    if (m && m.index !== undefined) {
      out.push({
        kind: rule.kind,
        span: [m.index, m.index + m[0].length],
        score: rule.score,
        evidence: { rule: rule.id, cite: rule.cite, match: m[0] },
      });
    }
  }
  return out;
}
