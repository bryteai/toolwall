"use client";

import { useState } from "react";

const PY = `from toolwall import toolwall, policy

@toolwall(policy=policy.web_fetch())
def fetch(url: str) -> str:
    return httpx.get(url).text`;

const CLI = `pip install -e ".[judge]"     # from a clone of the repo
toolwall check --judge response.json
# {"blocked": true, "score": ..., "threshold": 0.6, "detections": ["judge-attack"]}; exit code 2 = blocked`;

type Tab = "py" | "cli";
const TABS: ReadonlyArray<readonly [Tab, string]> = [
  ["py", "Python"],
  ["cli", "CLI"],
];

const SRC: Record<Tab, string> = { py: PY, cli: CLI };

export function CodeSnippet() {
  const [tab, setTab] = useState<Tab>("py");

  return (
    <div className="rounded-xl border border-[color:var(--color-edge)] bg-[color:var(--color-ink-1)] overflow-hidden">
      <header className="flex items-center gap-2 px-5 py-3 border-b border-[color:var(--color-edge)] bg-[color:var(--color-ink-2)]">
        <h2 className="text-sm font-mono text-[color:var(--color-paper)] mr-auto">
          wrap a tool
        </h2>
        <div className="flex gap-1">
          {TABS.map(([id, label]) => (
            <button
              key={id}
              type="button"
              onClick={() => setTab(id)}
              className={
                "rounded-md px-3 py-1 text-[11px] font-mono uppercase tracking-wider transition-colors " +
                (tab === id
                  ? "bg-[color:var(--color-fence)] text-black"
                  : "text-[color:var(--color-fog)] hover:text-[color:var(--color-paper)]")
              }
            >
              {label}
            </button>
          ))}
        </div>
      </header>
      <pre className="px-5 py-4 font-mono text-[12.5px] leading-[1.6] text-[color:var(--color-bone)] overflow-x-auto fence-scroll">
        {SRC[tab]}
      </pre>
    </div>
  );
}
