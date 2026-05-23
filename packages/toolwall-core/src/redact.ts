/**
 * Named redaction patterns — feature-parity with `toolwall/_redact.py`.
 *
 * Each kind has a regex and a replacement token. We redact in-place
 * on the tool response BEFORE it is returned to the model.
 */

import type { RedactKind } from "./policy.js";

interface RedactRule {
  readonly pattern: RegExp;
  readonly replacement: string;
}

const RULES: Record<RedactKind, RedactRule> = {
  EMAIL: {
    pattern: /[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}/g,
    replacement: "[REDACTED:EMAIL]",
  },
  API_KEY: {
    pattern:
      /\b(?:sk-(?:proj-|live-)?|sk_live_|sk_test_|ghp_|gho_|ghu_|ghs_|ghr_|github_pat_|AIza|xoxb-|xoxp-|AKIA[0-9A-Z]{16})[A-Za-z0-9_\-]{10,}\b/g,
    replacement: "[REDACTED:API_KEY]",
  },
  PHONE_E164: {
    pattern: /(?<![0-9])\+[1-9]\d{6,14}(?![0-9])/g,
    replacement: "[REDACTED:PHONE]",
  },
  BEARER_TOKEN: {
    pattern: /\b[Bb]earer\s+[A-Za-z0-9._\-~+/=]{16,}/g,
    replacement: "[REDACTED:BEARER]",
  },
  URL_PRIVATE_IP: {
    pattern:
      /https?:\/\/(?:10\.\d{1,3}\.\d{1,3}\.\d{1,3}|192\.168\.\d{1,3}\.\d{1,3}|172\.(?:1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3}|127\.\d{1,3}\.\d{1,3}\.\d{1,3}|localhost|169\.254\.\d{1,3}\.\d{1,3})(?::\d+)?(?:\/[^\s]*)?/g,
    replacement: "[REDACTED:PRIVATE_URL]",
  },
};

export function redact(text: string, kinds: readonly RedactKind[]): string {
  let out = text;
  for (const k of kinds) {
    const rule = RULES[k];
    out = out.replace(rule.pattern, rule.replacement);
  }
  return out;
}
