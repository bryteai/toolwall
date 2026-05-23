"use client";

import { useEffect, useMemo, useState } from "react";
import { useClock } from "@/lib/clock";
import { getScenario, SCENARIOS } from "@/lib/scenarios";
import { Controls } from "./Controls";
import { PayloadPreview } from "./PayloadPreview";
import { ScenarioPicker } from "./ScenarioPicker";
import { Terminal } from "./Terminal";

export function DemoStage() {
  const [activeId, setActiveId] = useState<string>(SCENARIOS[0]!.id);
  const scenario = useMemo(() => getScenario(activeId), [activeId]);
  const [{ t, playing }, ctl] = useClock();

  useEffect(() => {
    ctl.reset();
    // Tiny tail-call so visitors immediately see something on switch.
    const handle = requestAnimationFrame(() => ctl.play());
    return () => cancelAnimationFrame(handle);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [activeId]);

  useEffect(() => {
    if (t >= scenario.durationMs && playing) ctl.pause();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [t, scenario.durationMs, playing]);

  return (
    <section
      data-fence-stage
      className="rounded-2xl border border-[color:var(--color-edge)] bg-gradient-to-br from-[color:var(--color-ink-1)] to-[color:var(--color-ink-0)] p-5 sm:p-7"
    >
      <ScenarioPicker
        scenarios={SCENARIOS}
        activeId={activeId}
        onPick={setActiveId}
      />

      <div className="mt-5">
        <PayloadPreview scenario={scenario} />
      </div>

      <div className="mt-5 grid gap-5 lg:grid-cols-2">
        <Terminal side={scenario.unsafe} t={t} lane="attack" />
        <Terminal side={scenario.safe}   t={t} lane="fence" />
      </div>

      <div className="mt-5">
        <Controls
          playing={playing}
          t={t}
          durationMs={scenario.durationMs}
          onPlay={ctl.play}
          onPause={ctl.pause}
          onReset={() => {
            ctl.reset();
            requestAnimationFrame(() => ctl.play());
          }}
        />
      </div>
    </section>
  );
}
