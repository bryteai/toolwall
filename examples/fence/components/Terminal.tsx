"use client";

import { useEffect, useRef } from "react";
import type { Banner, Line, LineKind, ScenarioSide } from "@/lib/scenarios";

const KIND_STYLE: Record<LineKind, string> = {
  prompt:    "text-[color:var(--color-paper)]",
  stdout:    "text-[color:var(--color-bone)]",
  stderr:    "text-[color:var(--color-warn)]",
  system:    "text-[color:var(--color-fog)]",
  danger:    "text-[color:var(--color-attack)]",
  firewall:  "text-[color:var(--color-fence)]",
  safe:      "text-[color:var(--color-safe)]",
  muted:     "text-[color:var(--color-fog)]",
};

const KIND_PREFIX: Record<LineKind, string> = {
  prompt:   "$ ",
  stdout:   "  ",
  stderr:   "! ",
  system:   "· ",
  danger:   "✗ ",
  firewall: "▮ ",
  safe:     "✓ ",
  muted:    "  ",
};

interface Props {
  readonly side: ScenarioSide;
  /** Milliseconds since play started. */
  readonly t: number;
  /** Visual lane — affects accent colors only. */
  readonly lane: "attack" | "fence";
}

export function Terminal({ side, t, lane }: Props) {
  const scrollRef = useRef<HTMLDivElement | null>(null);
  const visibleCount = side.lines.filter((l) => t >= l.at).length;

  useEffect(() => {
    const el = scrollRef.current;
    if (el) el.scrollTop = el.scrollHeight;
  }, [visibleCount]);

  const accent = lane === "attack"
    ? "border-[color:var(--color-attack-dim)]"
    : "border-[color:var(--color-fence-dim)]";

  const dotColor = lane === "attack" ? "bg-[color:var(--color-attack)]" : "bg-[color:var(--color-fence)]";

  const showBanner = t >= side.banner.at;

  return (
    <div
      className={`flex flex-col rounded-xl border ${accent} bg-[color:var(--color-ink-1)] overflow-hidden h-full min-h-[480px]`}
    >
      <header className="flex items-center gap-3 px-4 py-3 border-b border-[color:var(--color-edge)] bg-[color:var(--color-ink-2)]">
        <span className={`inline-block w-2.5 h-2.5 rounded-full ${dotColor}`} aria-hidden />
        <div className="flex-1 min-w-0">
          <h3 className="text-sm font-mono text-[color:var(--color-paper)] truncate">
            {side.title}
          </h3>
          <p className="text-[11px] font-mono text-[color:var(--color-fog)] truncate">
            {side.subtitle}
          </p>
        </div>
        <span className="text-[10px] uppercase tracking-widest text-[color:var(--color-fog)]">
          {lane === "attack" ? "raw" : "fenced"}
        </span>
      </header>

      <div
        ref={scrollRef}
        className="fence-scroll flex-1 overflow-y-auto px-4 py-3 font-mono text-[12.5px] leading-[1.55]"
      >
        {side.lines.map((line: Line, idx: number) => {
          if (t < line.at) return null;
          return (
            <pre
              key={idx}
              className={`whitespace-pre-wrap ${KIND_STYLE[line.kind]} mb-1`}
            >
              <span className="opacity-60">{KIND_PREFIX[line.kind]}</span>
              {line.text}
            </pre>
          );
        })}
        {!showBanner && visibleCount > 0 && (
          <span className="fence-cursor inline-block h-4" aria-hidden />
        )}
      </div>

      <BannerEl banner={side.banner} visible={showBanner} />
    </div>
  );
}

function BannerEl({ banner, visible }: { banner: Banner; visible: boolean }) {
  const tone = banner.tone === "red"
    ? "bg-[color:var(--color-attack)] text-black"
    : "bg-[color:var(--color-safe)] text-black";

  return (
    <div
      className={`transition-[max-height,opacity] duration-500 overflow-hidden ${
        visible ? "max-h-32 opacity-100" : "max-h-0 opacity-0"
      }`}
      aria-live="polite"
    >
      <div className={`px-4 py-3 ${tone}`}>
        <p className="text-sm font-bold font-mono">{banner.headline}</p>
        <p className="text-[11px] font-mono opacity-90">{banner.detail}</p>
      </div>
    </div>
  );
}
