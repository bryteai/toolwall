/**
 * Single rAF-driven clock shared by both terminals.
 *
 * IMPORTANT: every animation reads `performance.now()` (which the
 * Playwright recorder under `eval/recorder/` patches) rather than
 * `Date.now()` or `setTimeout`. This keeps the demo reproducible
 * frame-for-frame at any recording rate.
 */
import { useEffect, useRef, useState } from "react";

export interface ClockState {
  /** Milliseconds since play started. Pauses freeze this value. */
  readonly t: number;
  /** Whether the clock is currently advancing. */
  readonly playing: boolean;
}

export interface ClockControls {
  play(): void;
  pause(): void;
  reset(): void;
  seek(ms: number): void;
}

export function useClock(): readonly [ClockState, ClockControls] {
  const [t, setT] = useState(0);
  const [playing, setPlaying] = useState(false);
  const rafRef = useRef<number | null>(null);
  const lastRef = useRef<number | null>(null);
  const tRef = useRef(0);

  useEffect(() => {
    if (!playing) {
      if (rafRef.current !== null) cancelAnimationFrame(rafRef.current);
      lastRef.current = null;
      return;
    }
    const step = (now: number) => {
      if (lastRef.current === null) lastRef.current = now;
      const dt = now - lastRef.current;
      lastRef.current = now;
      tRef.current += dt;
      setT(tRef.current);
      rafRef.current = requestAnimationFrame(step);
    };
    rafRef.current = requestAnimationFrame(step);
    return () => {
      if (rafRef.current !== null) cancelAnimationFrame(rafRef.current);
    };
  }, [playing]);

  const controls: ClockControls = {
    play: () => setPlaying(true),
    pause: () => setPlaying(false),
    reset: () => {
      tRef.current = 0;
      lastRef.current = null;
      setT(0);
      setPlaying(false);
    },
    seek: (ms: number) => {
      tRef.current = ms;
      lastRef.current = null;
      setT(ms);
    },
  };

  return [{ t, playing }, controls] as const;
}
