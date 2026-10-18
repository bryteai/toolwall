// From results/v0_2/summary.json (release run). k / n = responses that got through (ASR)
// or were wrongly blocked (FPR); lower is better for both.
interface Row {
  readonly set: string;
  readonly metric: "ASR" | "FPR";
  readonly tw: readonly [number, number];
  readonly pa: readonly [number, number];
  readonly final?: boolean;
}

const ROWS: readonly Row[] = [
  {
    "set": "InjecAgent, unseen tools \u00d7 unseen instructions (base)",
    "metric": "ASR",
    "tw": [
      0,
      95
    ],
    "pa": [
      27,
      95
    ]
  },
  {
    "set": "InjecAgent, same, enhanced setting",
    "metric": "ASR",
    "tw": [
      0,
      95
    ],
    "pa": [
      0,
      95
    ]
  },
  {
    "set": "deepset test split",
    "metric": "ASR",
    "tw": [
      13,
      60
    ],
    "pa": [
      31,
      60
    ]
  },
  {
    "set": "Lakera Gandalf test split",
    "metric": "ASR",
    "tw": [
      23,
      112
    ],
    "pa": [
      0,
      112
    ]
  },
  {
    "set": "InjecAgent benign twins",
    "metric": "FPR",
    "tw": [
      0,
      150
    ],
    "pa": [
      43,
      150
    ]
  },
  {
    "set": "Wikipedia, random",
    "metric": "FPR",
    "tw": [
      1,
      400
    ],
    "pa": [
      72,
      400
    ]
  },
  {
    "set": "Wikipedia security articles",
    "metric": "FPR",
    "tw": [
      11,
      91
    ],
    "pa": [
      29,
      91
    ]
  },
  {
    "set": "Workplace emails with requests",
    "metric": "FPR",
    "tw": [
      0,
      296
    ],
    "pa": [
      148,
      296
    ]
  },
  {
    "set": "BIPIA, run once after freezing",
    "metric": "ASR",
    "tw": [
      142,
      150
    ],
    "pa": [
      123,
      150
    ],
    "final": true
  },
  {
    "set": "BIPIA clean contexts",
    "metric": "FPR",
    "tw": [
      3,
      150
    ],
    "pa": [
      33,
      150
    ],
    "final": true
  }
];

function pct([k, n]: readonly [number, number]): string {
  return `${((100 * k) / n).toFixed(1)} %`;
}

export function Results() {
  return (
    <div className="rounded-xl border border-[color:var(--color-edge)] bg-[color:var(--color-ink-1)] overflow-hidden">
      <header className="px-5 py-3 border-b border-[color:var(--color-edge)] bg-[color:var(--color-ink-2)]">
        <h2 className="text-sm font-mono text-[color:var(--color-paper)]">toolwall v0.2 — held-out results</h2>
        <p className="text-[11px] font-mono text-[color:var(--color-fog)] mt-0.5">
          ASR = attacks that get through · FPR = benign responses blocked · lower is better · baseline: ProtectAI deberta-v3 v2
        </p>
      </header>
      <div className="overflow-x-auto fence-scroll">
        <table className="w-full font-mono text-[12px]">
          <thead>
            <tr className="text-left text-[10px] uppercase tracking-widest text-[color:var(--color-fog)] border-b border-[color:var(--color-edge)]">
              <th className="px-5 py-2 font-normal">set</th>
              <th className="px-3 py-2 font-normal">metric</th>
              <th className="px-3 py-2 font-normal text-right">toolwall</th>
              <th className="px-3 py-2 font-normal text-right">ProtectAI</th>
            </tr>
          </thead>
          <tbody>
            {ROWS.map((r) => (
              <tr key={r.set + r.metric} className={r.final ? "border-t border-[color:var(--color-edge)] bg-[color:color-mix(in_srgb,var(--color-attack)_8%,transparent)]" : ""}>
                <td className="px-5 py-2 text-[color:var(--color-bone)]">{r.set}</td>
                <td className="px-3 py-2 text-[color:var(--color-fog)]">{r.metric}</td>
                <td className="px-3 py-2 text-right tabular-nums text-[color:var(--color-paper)] whitespace-nowrap">
                  {pct(r.tw)} <span className="text-[color:var(--color-fog)]">({r.tw[0]}/{r.tw[1]})</span>
                </td>
                <td className="px-3 py-2 text-right tabular-nums text-[color:var(--color-paper)] whitespace-nowrap">
                  {pct(r.pa)} <span className="text-[color:var(--color-fog)]">({r.pa[0]}/{r.pa[1]})</span>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
      <p className="px-5 py-3 border-t border-[color:var(--color-edge)] text-[11.5px] text-[color:var(--color-bone)] leading-relaxed">
        Four candidate classifiers were trained and the choice used the sets above, so they informed model selection.
        Only BIPIA was run after the choice. Intervals, the remaining sets and raw per-row decisions are in{" "}
        <a className="underline" href="https://github.com/bryteai/toolwall/tree/main/results/v0_2">results/v0_2</a>.
      </p>
    </div>
  );
}
