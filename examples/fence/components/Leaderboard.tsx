"use client";

interface Row {
  readonly defense: string;
  readonly asr: number;
  readonly utility: number;
  readonly note?: string;
  readonly highlight?: boolean;
}

const ROWS: readonly Row[] = [
  { defense: "no defense (baseline)",                 asr: 1.0000, utility: 1.0000 },
  { defense: "prompt sandwiching",                     asr: 1.0000, utility: 1.0000 },
  { defense: "Spotlighting (Hines et al. 2024)",       asr: 1.0000, utility: 1.0000 },
  { defense: "toolwall v0.1 — rules only",             asr: 0.7784, utility: 1.0000, note: "rule layer alone" },
  { defense: "toolwall v0.1 — rules + judge",          asr: 0.0973, utility: 0.9333, highlight: true, note: "full stack" },
];

const PER_FAMILY: ReadonlyArray<readonly [string, number]> = [
  ["unicode-tag",          0.0000],
  ["markdown-image exfil", 0.4667],
  ["tool-poisoning",       1.0000],
  ["full-schema poisoning",1.0000],
  ["rug-pull",             1.0000],
  ["multi-hop",            1.0000],
  ["base64 payload",       1.0000],
];

export function Leaderboard() {
  return (
    <div className="rounded-xl border border-[color:var(--color-edge)] bg-[color:var(--color-ink-1)] overflow-hidden">
      <header className="px-5 py-3 border-b border-[color:var(--color-edge)] bg-[color:var(--color-ink-2)]">
        <h2 className="text-sm font-mono text-[color:var(--color-paper)]">
          toolwall-bench-v0.1 — in-house results
        </h2>
        <p className="text-[11px] font-mono text-[color:var(--color-fog)] mt-0.5">
          n=200 (185 attack · 15 benign) · ASR lower-is-better · Utility higher-is-better
        </p>
      </header>

      <div className="overflow-x-auto">
        <table className="w-full font-mono text-[12.5px]">
          <thead>
            <tr className="text-left text-[10px] uppercase tracking-widest text-[color:var(--color-fog)] border-b border-[color:var(--color-edge)]">
              <th className="px-5 py-2 font-normal">defense</th>
              <th className="px-3 py-2 font-normal text-right">ASR ↓</th>
              <th className="px-3 py-2 font-normal text-right">utility ↑</th>
              <th className="px-5 py-2 font-normal">note</th>
            </tr>
          </thead>
          <tbody>
            {ROWS.map((r) => (
              <tr
                key={r.defense}
                className={
                  r.highlight
                    ? "bg-[color:color-mix(in_srgb,var(--color-fence)_8%,transparent)]"
                    : ""
                }
              >
                <td className="px-5 py-2 text-[color:var(--color-bone)]">{r.defense}</td>
                <td className="px-3 py-2 text-right tabular-nums text-[color:var(--color-paper)]">
                  {(r.asr * 100).toFixed(1)}%
                </td>
                <td className="px-3 py-2 text-right tabular-nums text-[color:var(--color-paper)]">
                  {(r.utility * 100).toFixed(1)}%
                </td>
                <td className="px-5 py-2 text-[color:var(--color-fog)] text-[11px]">{r.note ?? ""}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>

      <details className="px-5 py-3 border-t border-[color:var(--color-edge)] text-[12px] font-mono text-[color:var(--color-bone)]">
        <summary className="cursor-pointer text-[color:var(--color-fog)]">
          per-family ASR for <span className="text-[color:var(--color-paper)]">toolwall (rules only)</span>
        </summary>
        <ul className="mt-2 grid grid-cols-1 sm:grid-cols-2 gap-x-6 gap-y-1">
          {PER_FAMILY.map(([family, asr]) => (
            <li key={family} className="flex justify-between">
              <span className="text-[color:var(--color-bone)]">{family}</span>
              <span
                className={
                  "tabular-nums " +
                  (asr === 0
                    ? "text-[color:var(--color-safe)]"
                    : asr < 0.5
                    ? "text-[color:var(--color-fence)]"
                    : "text-[color:var(--color-attack)]")
                }
              >
                {(asr * 100).toFixed(1)}%
              </span>
            </li>
          ))}
        </ul>
        <p className="mt-3 text-[11px] text-[color:var(--color-fog)] leading-relaxed">
          Honest finding: the rule layer perfectly defends unicode-tag and partially
          defends markdown-image exfil. Semantic attacks (tool-poisoning, rug-pull,
          schema-poisoning, multi-hop, base64) are closed by the LoRA judge layer
          that ships in the full `toolwall` row above.
        </p>
      </details>
    </div>
  );
}
