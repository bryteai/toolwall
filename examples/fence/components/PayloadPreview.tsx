"use client";

import type { Scenario } from "@/lib/scenarios";

export function PayloadPreview({ scenario }: { scenario: Scenario }) {
  return (
    <div className="rounded-lg border border-[color:var(--color-edge)] bg-[color:var(--color-ink-2)] overflow-hidden">
      <header className="flex items-center justify-between px-4 py-2 border-b border-[color:var(--color-edge)] bg-[color:var(--color-ink-1)]">
        <div className="flex items-center gap-2">
          <span className="text-[10px] uppercase tracking-widest text-[color:var(--color-attack)]">
            attack payload
          </span>
          <span className="text-[11px] font-mono text-[color:var(--color-fog)]">
            ({scenario.attack.family})
          </span>
        </div>
        <div className="text-[11px] font-mono text-[color:var(--color-fog)]">
          rule {scenario.attack.ruleId} · {scenario.attack.cite}
        </div>
      </header>
      <pre className="px-4 py-3 font-mono text-[12.5px] leading-[1.55] text-[color:var(--color-warn)] whitespace-pre-wrap">
        {scenario.attack.payloadPreview}
      </pre>
    </div>
  );
}
