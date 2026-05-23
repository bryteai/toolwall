import type { Cut } from "../types.js";

/**
 * 5-minute landscape cut for docs / website hero / Show HN embed.
 * Plays every scenario in full, then a guided tour of leaderboard
 * + integration snippets + threat model excerpt.
 *
 *    0:00–0:10  hero
 *    0:10–0:35  Calendar exfil (full 7.4s, lingers on banners)
 *    0:35–1:00  File exfil
 *    1:00–1:25  Markdown image exfil
 *    1:25–1:50  Full-schema poisoning
 *    1:50–2:15  Rug-pull
 *    2:15–2:50  Leaderboard + per-family expand
 *    2:50–3:30  Code snippet: Python → TS → MCP
 *    3:30–4:30  Three pillars + footer / disclosure
 *    4:30–5:00  Return to hero, end-card
 */
export const landscape5min: Cut = {
  id: "landscape-5min",
  description: "5min landscape — docs cut",
  url: process.env.FENCE_URL ?? "http://localhost:4173/",
  viewport: { width: 1920, height: 1080 },
  deviceScaleFactor: 1,
  fps: 30,
  durationMs: 300_000,
  encoder: { crf: 22, preset: "slow", pixFmt: "yuv420p" },
  waypoints: [
    { at:       0, action: { kind: "scroll-to-top" } },
    { at:   8_000, action: { kind: "scroll-into-view", selector: "[data-fence-stage]" } },
    { at:  10_000, action: { kind: "click-text",  text: "Calendar exfil" } },
    { at:  35_000, action: { kind: "click-text",  text: "File exfil" } },
    { at:  60_000, action: { kind: "click-text",  text: "Markdown image exfil" } },
    { at:  85_000, action: { kind: "click-text",  text: "Full-schema poisoning" } },
    { at: 110_000, action: { kind: "click-text",  text: "Rug-pull" } },
    { at: 135_000, action: { kind: "scroll-into-view", selector: "table tbody tr:nth-child(4)" } },
    { at: 165_000, action: { kind: "click-text",  text: "per-family ASR" } },
    { at: 195_000, action: { kind: "scroll-into-view", selector: "pre" } },
    { at: 210_000, action: { kind: "click-text",  text: "TypeScript" } },
    { at: 225_000, action: { kind: "click-text",  text: "MCP server" } },
    { at: 245_000, action: { kind: "scroll-y",    y: 99999 }, note: "pillars + footer" },
    { at: 285_000, action: { kind: "scroll-to-top" } },
  ],
};
