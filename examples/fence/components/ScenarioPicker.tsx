"use client";

import type { Scenario } from "@/lib/scenarios";

interface Props {
  readonly scenarios: readonly Scenario[];
  readonly activeId: string;
  readonly onPick: (id: string) => void;
}

export function ScenarioPicker({ scenarios, activeId, onPick }: Props) {
  return (
    <div
      role="tablist"
      aria-label="Attack scenarios"
      className="flex flex-wrap gap-2"
    >
      {scenarios.map((s) => {
        const active = s.id === activeId;
        return (
          <button
            key={s.id}
            role="tab"
            type="button"
            aria-selected={active}
            onClick={() => onPick(s.id)}
            className={
              "group rounded-lg border px-3 py-2 text-left transition-colors min-w-[160px] " +
              (active
                ? "border-[color:var(--color-fence)] bg-[color:var(--color-ink-2)]"
                : "border-[color:var(--color-edge)] bg-transparent hover:border-[color:var(--color-fence-dim)]")
            }
          >
            <p
              className={
                "text-sm font-mono " +
                (active ? "text-[color:var(--color-paper)]" : "text-[color:var(--color-bone)]")
              }
            >
              {s.label}
            </p>
            <p className="text-[11px] font-mono text-[color:var(--color-fog)] mt-0.5">
              {s.short}
            </p>
          </button>
        );
      })}
    </div>
  );
}
