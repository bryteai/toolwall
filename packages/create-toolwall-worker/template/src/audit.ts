/**
 * KV-backed audit log. Every tool call writes one entry with:
 * timestamp, session id, tool name, decision (allow/block/redact),
 * detection summary if any. Keys are sortable by time so a `list` with
 * prefix returns chronological order.
 */

export interface AuditEntry {
  readonly ts: string;
  readonly session: string;
  readonly tool: string;
  readonly decision: "allow" | "block" | "redact";
  readonly score?: number;
  readonly detections?: readonly { kind: string; score: number }[];
  readonly reason?: string;
}

export async function audit(
  kv: KVNamespace,
  entry: AuditEntry,
): Promise<void> {
  const key = `${entry.ts}:${entry.session}:${crypto.randomUUID()}`;
  await kv.put(key, JSON.stringify(entry), {
    // 90-day retention by default — long enough for an audit trail,
    // short enough that KV usage stays free-tier.
    expirationTtl: 60 * 60 * 24 * 90,
  });
}
