# @toolwall/recorder

Deterministic Playwright recorder for [`fence.bryteai.studio`](https://fence.bryteai.studio)
and any other page whose animations run off `requestAnimationFrame` +
`performance.now()`.

## Why it exists

Real-time screen capture races the compositor: dropped frames, jitter,
hardware-dependent output. This recorder owns the in-page clock — it
patches `rAF` / `cAF` / `performance.now` / `Date.now`, advances them
exactly `1000/fps` ms per captured frame, then pipes PNG bytes straight
into `ffmpeg image2pipe`. Same git SHA + same `crf` = bit-stable mp4.

Crucially we do **not** patch `setTimeout` / `setInterval` /
`queueMicrotask`. React's scheduler reads those for its own work loop;
patching them desyncs the renderer. Lesson burned in during NEBULA —
see [`feedback_deterministic_browser_recording`](../../docs/recipes/deterministic-browser-recording.md).

## Build & test

```bash
pnpm install                 # workspace root
pnpm --filter @toolwall/recorder build
pnpm --filter @toolwall/recorder test
```

## Record

```bash
# Serve the static fence demo first
( cd ../../examples/fence && pnpm build && cd out && python3 -m http.server 4173 ) &

# 60-second portrait cut for socials
pnpm --filter @toolwall/recorder record:portrait
# → eval/recorder/out/portrait-60s.mp4   (~ 1080×1920)

# 5-minute landscape cut for docs / website hero
pnpm --filter @toolwall/recorder record:landscape
# → eval/recorder/out/landscape-5min.mp4 (~ 1920×1080)

# Custom run
pnpm --filter @toolwall/recorder build
node dist/record.js --cut portrait-60s --url http://localhost:4173/ --dry 10
```

`--dry N` captures only N frames — handy for smoke-testing the patch
without rendering 90 seconds of video.

## Add a new cut

1. Add a `Cut` config under `src/cuts/`:
   ```ts
   export const myCut: Cut = {
     id: "my-cut",
     description: "...",
     url: process.env.FENCE_URL ?? "http://localhost:4173/",
     viewport: { width: 1080, height: 1920 },
     fps: 30,
     durationMs: 30_000,
     waypoints: [
       { at: 0,     action: { kind: "scroll-to-top" } },
       { at: 5_000, action: { kind: "click-text", text: "..." } },
     ],
   };
   ```
2. Register it in `src/cuts/index.ts`.

## Files

```
src/
  clock-patch.ts   the four-global patch (string, injected via addInitScript)
  record.ts        Node-side driver — Playwright + ffmpeg pipe
  types.ts         Cut + Waypoint contracts
  cuts/
    portrait-60s.ts   socials
    landscape-5min.ts docs
    index.ts          registry
test/
  clock-patch.test.ts unit test of the patch contract (no Chromium)
```

## License

Apache-2.0.
