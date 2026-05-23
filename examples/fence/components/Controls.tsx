"use client";

interface Props {
  readonly playing: boolean;
  readonly t: number;
  readonly durationMs: number;
  readonly onPlay: () => void;
  readonly onPause: () => void;
  readonly onReset: () => void;
}

export function Controls({ playing, t, durationMs, onPlay, onPause, onReset }: Props) {
  const pct = Math.min(100, (t / durationMs) * 100);
  const done = t >= durationMs;

  return (
    <div className="flex items-center gap-3">
      {!playing && !done && (
        <button
          type="button"
          onClick={onPlay}
          className="rounded-md bg-[color:var(--color-fence)] px-4 py-2 text-sm font-mono font-semibold text-black hover:brightness-110"
        >
          ▶ play
        </button>
      )}
      {playing && (
        <button
          type="button"
          onClick={onPause}
          className="rounded-md border border-[color:var(--color-fence-dim)] px-4 py-2 text-sm font-mono text-[color:var(--color-paper)] hover:bg-[color:var(--color-ink-2)]"
        >
          ❚❚ pause
        </button>
      )}
      {(done || t > 0) && (
        <button
          type="button"
          onClick={onReset}
          className="rounded-md border border-[color:var(--color-edge)] px-4 py-2 text-sm font-mono text-[color:var(--color-bone)] hover:bg-[color:var(--color-ink-2)]"
        >
          ↻ replay
        </button>
      )}
      <div className="flex-1 h-1 bg-[color:var(--color-edge)] rounded-full overflow-hidden">
        <div
          className="h-full bg-[color:var(--color-fence)] transition-[width] duration-100"
          style={{ width: `${pct}%` }}
        />
      </div>
      <span className="text-[11px] font-mono text-[color:var(--color-fog)] tabular-nums w-14 text-right">
        {(t / 1000).toFixed(1)}s
      </span>
    </div>
  );
}
