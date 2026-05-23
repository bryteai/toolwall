# fence — toolwall live demo

The page that powers [`fence.bryteai.studio`](https://fence.bryteai.studio).

Two terminals side by side: the left one runs an agent without
toolwall and gets exfil'd; the right one runs the same agent with
`@toolwall(policy=...)` wrapping its fetch tool. A picker at the top
switches between five attack scenarios (calendar exfil, file exfil,
markdown image exfil, full-schema poisoning, rug-pull). All scripted
deterministically off `performance.now()` so the Playwright recorder
in `eval/recorder/` can capture the same frames every run.

## Stack

- Next.js 16 (Turbopack) static export — no server runtime needed,
  drops straight onto Cloudflare Pages.
- React 19, Tailwind v4 (`@import "tailwindcss"`, no config file).
- TypeScript strict + `noUncheckedIndexedAccess`.

## Develop

```bash
pnpm install            # workspace root
pnpm --filter fence-demo dev
# → http://localhost:4173
```

## Build (static export)

```bash
pnpm --filter fence-demo build
# → examples/fence/out/  (drop into Cloudflare Pages or any static host)
```

## Layout

```
examples/fence/
  app/
    layout.tsx       # html shell, metadata
    page.tsx         # hero + DemoStage + Leaderboard + CodeSnippet + footer
    globals.css      # Tailwind v4 + design tokens + fence-* utilities
  components/
    DemoStage.tsx    # owns active scenario + clock
    Terminal.tsx     # one terminal pane, t-driven line reveal + banner
    ScenarioPicker.tsx
    PayloadPreview.tsx
    Controls.tsx     # play / pause / reset + progress bar
    Leaderboard.tsx  # in-house bench numbers from results/v0.1.csv
    CodeSnippet.tsx  # tabbed Python / TS / MCP integration sample
  lib/
    scenarios.ts     # five scripted scenarios (unsafe + safe sides)
    clock.ts         # useClock — single rAF clock, deterministic on
                     #   replay because animations read performance.now()
                     #   (not setTimeout — that breaks recording)
```

## Deterministic recording note

`lib/clock.ts` advances state inside `requestAnimationFrame`, reading
the timestamp `rAF` passes (which is `performance.now()`-derived). The
Playwright recorder under `eval/recorder/` patches `performance.now()`
+ `Date.now()` + `requestAnimationFrame` itself to drive a virtual
clock — so this page can be recorded frame-for-frame identically at
any target FPS.

NEVER replace `requestAnimationFrame` with `setTimeout` here. React's
scheduler reads `setTimeout` for its own work, and patching it breaks
the renderer in the recorder.
