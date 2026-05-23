/**
 * The Policy schema, Zod-validated, byte-for-byte equivalent to the
 * Python `Policy` dataclass.
 *
 * If a user serializes a Policy on the Python side to JSON and passes
 * it to a TypeScript worker via env, the worker must accept it. That
 * cross-language invariant is what `PolicySchema` enforces.
 */

import { z } from "zod";

export const RedactKindSchema = z.enum([
  "EMAIL",
  "API_KEY",
  "PHONE_E164",
  "BEARER_TOKEN",
  "URL_PRIVATE_IP",
]);
export type RedactKind = z.infer<typeof RedactKindSchema>;

export const PolicySchema = z
  .object({
    /** Host glob allowlist for outbound fetches (e.g. `*.gov.uk`). */
    urlAllowlist: z.array(z.string()).default([]),
    /** Host glob denylist; wins over allowlist. */
    urlDenylist: z.array(z.string()).default([]),
    /** Host glob list of egress targets to refuse on POST/PUT/PATCH. */
    egressDenylist: z.array(z.string()).default([]),
    /** Chroot-style filesystem scope. `null` means "no path access". */
    pathScope: z.string().nullable().default(null),
    /** Named redaction patterns to apply on tool response payloads. */
    redact: z.array(RedactKindSchema).default([]),
    /** Hard cap on response body length, bytes. */
    responseMaxBytes: z.number().int().positive().default(500_000),
    /** Composite IPI score above which we block. Range [0, 1]. */
    responseIpiThreshold: z.number().min(0).max(1).default(0.6),
    /** Soft rate limit per minute, per decorated call site. */
    callsPerMin: z.number().int().positive().default(30),
    /** Hard cost cap, cents, per decorated call site per minute. */
    costCentsMax: z.number().nonnegative().default(50),
  })
  .strict();

export type Policy = z.infer<typeof PolicySchema>;

/**
 * Construct a Policy with defaults filled in. Throws ZodError on bad
 * input — we refuse silent coercion at API boundaries.
 */
export function policy(input: Partial<Policy> = {}): Policy {
  return PolicySchema.parse(input);
}

/** Preset: outbound web fetch. */
export function webFetchPolicy(
  overrides: Partial<Policy> = {},
): Policy {
  return PolicySchema.parse({
    urlAllowlist: [],
    egressDenylist: ["*"],
    redact: ["EMAIL", "API_KEY", "BEARER_TOKEN"],
    responseMaxBytes: 500_000,
    responseIpiThreshold: 0.6,
    ...overrides,
  });
}

/** Preset: MCP server middleware. */
export function mcpPolicy(overrides: Partial<Policy> = {}): Policy {
  return PolicySchema.parse({
    urlAllowlist: [],
    redact: ["EMAIL", "API_KEY", "BEARER_TOKEN", "URL_PRIVATE_IP"],
    responseMaxBytes: 200_000,
    responseIpiThreshold: 0.55,
    callsPerMin: 60,
    ...overrides,
  });
}

/** Preset: file read tool with chroot scope. */
export function fileReadPolicy(
  pathScope: string,
  overrides: Partial<Policy> = {},
): Policy {
  return PolicySchema.parse({
    pathScope,
    redact: ["EMAIL", "API_KEY", "BEARER_TOKEN"],
    responseMaxBytes: 1_000_000,
    responseIpiThreshold: 0.6,
    ...overrides,
  });
}
