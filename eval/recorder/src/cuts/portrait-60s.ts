import type { Cut } from "../types.js";

/**
 * 60-second portrait cut for X / LinkedIn / IG Reels. Plays:
 *   00.0–05.0  hero header lingers (typing-cursor catches the eye)
 *   05.0–13.0  Calendar exfil scenario in full
 *   13.0–18.0  switch → Markdown image (zero-click bombshell)
 *   18.0–26.0  Markdown image scenario in full
 *   26.0–31.0  switch → Full-schema poisoning
 *   31.0–38.0  Full-schema scenario in full
 *   38.0–46.0  scroll to leaderboard, highlight ASR row
 *   46.0–54.0  scroll to code snippet, cycle Python → TS → MCP
 *   54.0–60.0  scroll back to hero CTA, end frame
 */
export const portrait60s: Cut = {
  id: "portrait-60s",
  description: "60s portrait — socials cut",
  url: process.env.FENCE_URL ?? "http://localhost:4173/",
  viewport: { width: 1080, height: 1920 },
  deviceScaleFactor: 1,
  fps: 30,
  durationMs: 60_000,
  encoder: { crf: 23, preset: "medium", pixFmt: "yuv420p" },
  waypoints: [
    { at:     0, action: { kind: "scroll-to-top" }, note: "open on hero" },
    { at:  5_000, action: { kind: "click-text",   text: "Calendar exfil" }, note: "scenario 1" },
    { at:  5_200, action: { kind: "scroll-into-view", selector: "[data-fence-stage]" } },
    { at: 13_000, action: { kind: "click-text",   text: "Markdown image exfil" }, note: "scenario 2" },
    { at: 26_000, action: { kind: "click-text",   text: "Full-schema poisoning" }, note: "scenario 3" },
    { at: 38_000, action: { kind: "scroll-into-view", selector: "table tbody tr:nth-child(4)" }, note: "leaderboard zoom" },
    { at: 46_000, action: { kind: "scroll-into-view", selector: "pre" }, note: "code snippet" },
    { at: 48_000, action: { kind: "click-text",   text: "TypeScript" } },
    { at: 51_000, action: { kind: "click-text",   text: "MCP server" } },
    { at: 54_000, action: { kind: "scroll-to-top" } },
  ],
};
