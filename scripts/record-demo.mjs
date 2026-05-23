#!/usr/bin/env node
/**
 * scripts/record-demo.mjs
 *
 * Reproducibility wrapper for the demo recordings. Records both the
 * 1080×1920 60-second portrait (socials) and the 1920×1080 5-minute
 * landscape (docs) cut of fence.bryteai.studio, then transcodes the
 * portrait to ≤1.5 MB and lays both finals into `assets/`.
 *
 * Assumes:
 *   - examples/fence/out/ has been built (`pnpm --filter fence-demo build`)
 *   - A static server is reachable at $FENCE_URL (default http://localhost:4173/)
 *   - ffmpeg + ffprobe are on PATH
 *   - eval/recorder/ has been built (`pnpm --filter @toolwall/recorder build`)
 *
 * Usage:
 *   node scripts/record-demo.mjs              # record both cuts
 *   node scripts/record-demo.mjs --only portrait
 *   node scripts/record-demo.mjs --only landscape
 *
 * The actual recorder source-of-truth lives at:
 *   eval/recorder/src/record.ts
 *   eval/recorder/src/clock-patch.ts
 *   eval/recorder/src/cuts/{portrait-60s,landscape-5min}.ts
 *
 * Do NOT add `setTimeout` to the clock patch. React's scheduler reads
 * it; patching it desyncs the renderer.
 *
 * Apache-2.0. Author: Muhammad Hasnain.
 */
import { spawnSync } from "node:child_process";
import { copyFileSync, mkdirSync, statSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const ROOT = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const REC_DIR = resolve(ROOT, "eval", "recorder");
const REC_OUT = resolve(REC_DIR, "out");
const ASSETS  = resolve(ROOT, "assets");

const FENCE_URL = process.env.FENCE_URL ?? "http://localhost:4173/";

function sh(cmd, args, opts = {}) {
  const r = spawnSync(cmd, args, { stdio: "inherit", ...opts });
  if (r.status !== 0) throw new Error(`${cmd} ${args.join(" ")} exited ${r.status}`);
}

function recordCut(cutId) {
  console.log(`\n=== recording ${cutId} from ${FENCE_URL} ===\n`);
  sh("node", ["--enable-source-maps", "dist/record.js", "--cut", cutId, "--url", FENCE_URL], { cwd: REC_DIR });
}

function transcodePortrait() {
  const src = resolve(REC_OUT, "portrait-60s.mp4");
  const dst = resolve(ASSETS, "demo-60s.mp4");
  // CRF 27 + preset slow lands at ~1.42 MB on the 60s cut — under the 1.5 MB
  // social-platform inline-preview ceiling.
  sh("ffmpeg", [
    "-y", "-loglevel", "warning",
    "-i", src,
    "-c:v", "libx264",
    "-preset", "slow",
    "-crf", "27",
    "-pix_fmt", "yuv420p",
    "-movflags", "+faststart",
    "-an",
    dst,
  ]);
  console.log(`wrote ${dst} (${statSync(dst).size} bytes)`);
}

function copyLandscape() {
  const src = resolve(REC_OUT, "landscape-5min.mp4");
  const dst = resolve(ASSETS, "demo-5min.mp4");
  copyFileSync(src, dst);
  console.log(`wrote ${dst} (${statSync(dst).size} bytes)`);
}

function thumbnails() {
  const src = resolve(REC_OUT, "portrait-60s.mp4");
  const dst = resolve(ASSETS, "demo-thumbnails.png");
  // 5 evenly-spaced frames from the 60s portrait, scaled to 432x768 each,
  // tiled horizontally with 8px padding on a near-black ground.
  sh("ffmpeg", [
    "-y", "-loglevel", "warning",
    "-i", src,
    "-vf", "select='eq(n\\,150)+eq(n\\,540)+eq(n\\,900)+eq(n\\,1260)+eq(n\\,1650)',scale=432:768,tile=5x1:padding=8:color=0x0a0a0a",
    "-frames:v", "1", "-update", "1",
    dst,
  ]);
  console.log(`wrote ${dst} (${statSync(dst).size} bytes)`);
}

function main() {
  const args = process.argv.slice(2);
  let only = null;
  for (let i = 0; i < args.length; i++) {
    if (args[i] === "--only") only = args[++i] ?? null;
  }
  mkdirSync(ASSETS, { recursive: true });

  if (only === null || only === "portrait") {
    recordCut("portrait-60s");
    transcodePortrait();
    thumbnails();
  }
  if (only === null || only === "landscape") {
    recordCut("landscape-5min");
    copyLandscape();
  }
}

main();
