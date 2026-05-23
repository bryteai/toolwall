#!/usr/bin/env node
/**
 * Toolwall deterministic recorder.
 *
 * Run a Chromium tab against `fence.bryteai.studio` (or any URL whose
 * animations read `performance.now()` through `requestAnimationFrame`),
 * advance a *virtual* clock at fixed FPS, capture a PNG per frame via
 * Page.captureScreenshot, and stream the bytes into ffmpeg image2pipe
 * to produce an mp4. Output is bit-stable across runs at the same
 * `crf` + `preset` + git revision of the page.
 *
 * The only patched globals are rAF / cAF / performance.now / Date.
 * setTimeout / setInterval are LEFT ALONE — React's scheduler depends
 * on them, and patching them desyncs the renderer. Hard-learned.
 *
 * Usage:
 *   node dist/record.js --cut portrait-60s
 *   node dist/record.js --cut landscape-5min --url http://localhost:4173/
 */
import { spawn, type ChildProcess } from "node:child_process";
import { mkdir, stat } from "node:fs/promises";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { chromium, type Browser, type Page } from "playwright";

import type { Action, Cut, Waypoint } from "./types.js";
import { CUTS } from "./cuts/index.js";
import { CLOCK_PATCH_SOURCE } from "./clock-patch.js";

interface CliArgs {
  readonly cut: string;
  readonly url?: string;
  readonly outDir: string;
  readonly headless: boolean;
  readonly dryFrames?: number;
}

function parseArgs(argv: readonly string[]): CliArgs {
  let cut = "portrait-60s";
  let url: string | undefined;
  let outDir = resolve(dirname(fileURLToPath(import.meta.url)), "..", "out");
  let headless = true;
  let dryFrames: number | undefined;
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i];
    if (a === "--cut")            cut       = argv[++i] ?? cut;
    else if (a === "--url")       url       = argv[++i];
    else if (a === "--out")       outDir    = argv[++i] ?? outDir;
    else if (a === "--headed")    headless  = false;
    else if (a === "--dry")       dryFrames = Number(argv[++i] ?? "10");
    else if (a === "-h" || a === "--help") {
      // eslint-disable-next-line no-console
      console.log(
        [
          "usage: toolwall-record [--cut <id>] [--url <url>] [--out <dir>]",
          "                       [--headed] [--dry <frames>]",
          "",
          "available cuts:",
          ...Object.keys(CUTS).map((k) => `  ${k}`),
        ].join("\n"),
      );
      process.exit(0);
    }
  }
  return { cut, ...(url !== undefined ? { url } : {}), outDir, headless, ...(dryFrames !== undefined ? { dryFrames } : {}) };
}

async function ensureDir(dir: string): Promise<void> {
  try { await stat(dir); }
  catch { await mkdir(dir, { recursive: true }); }
}

interface FfmpegHandle {
  readonly proc: ChildProcess;
  readonly outPath: string;
  done(): Promise<void>;
  writeFrame(buf: Buffer): Promise<void>;
}

function startFfmpeg(cut: Cut, outDir: string): FfmpegHandle {
  const outPath = join(outDir, `${cut.id}.mp4`);
  const enc = cut.encoder ?? {};
  const args = [
    "-y",
    "-loglevel", "warning",
    "-f", "image2pipe",
    "-framerate", String(cut.fps),
    "-i", "-",
    "-c:v", "libx264",
    "-pix_fmt", enc.pixFmt ?? "yuv420p",
    "-preset", enc.preset ?? "medium",
    "-crf", String(enc.crf ?? 23),
    "-movflags", "+faststart",
    ...(enc.extraArgs ?? []),
    outPath,
  ];
  const proc = spawn("ffmpeg", args, { stdio: ["pipe", "inherit", "inherit"] });
  proc.on("error", (e) => {
    // eslint-disable-next-line no-console
    console.error("[ffmpeg] failed to spawn:", e);
  });

  return {
    proc,
    outPath,
    writeFrame: (buf: Buffer) =>
      new Promise<void>((res, rej) => {
        const ok = proc.stdin!.write(buf, (err) => (err ? rej(err) : res()));
        if (ok) res();
      }),
    done: () =>
      new Promise<void>((res, rej) => {
        proc.stdin!.end();
        proc.on("close", (code) =>
          code === 0 ? res() : rej(new Error(`ffmpeg exited ${code ?? "null"}`)),
        );
      }),
  };
}

async function performAction(page: Page, action: Action): Promise<void> {
  switch (action.kind) {
    case "click":
      await page.locator(action.selector).first().click({ timeout: 4_000 });
      return;
    case "click-text":
      await page.getByText(action.text, { exact: false }).first().click({ timeout: 4_000 });
      return;
    case "scroll-into-view":
      await page.locator(action.selector).first().scrollIntoViewIfNeeded({ timeout: 4_000 });
      return;
    case "scroll-to-top":
      await page.evaluate(() => window.scrollTo({ top: 0, behavior: "auto" }));
      return;
    case "scroll-y":
      await page.evaluate((y) => window.scrollTo({ top: y, behavior: "auto" }), action.y);
      return;
    case "eval":
      await page.evaluate(action.fn);
      return;
    case "wait":
      // The recorder owns time; sleeping the Node side here would
      // desync. "wait" is a virtual-time hint — we just no-op.
      return;
  }
}

async function record(cut: Cut, args: CliArgs): Promise<string> {
  const url = args.url ?? cut.url;
  const totalFrames = Math.round((cut.durationMs / 1000) * cut.fps);
  const framesToRender = args.dryFrames ?? totalFrames;
  const frameMs = 1000 / cut.fps;

  await ensureDir(args.outDir);

  // eslint-disable-next-line no-console
  console.log(
    `[recorder] cut=${cut.id} url=${url} viewport=${cut.viewport.width}x${cut.viewport.height} ` +
    `fps=${cut.fps} duration=${cut.durationMs}ms frames=${framesToRender}`,
  );

  const browser: Browser = await chromium.launch({
    headless: args.headless,
    args: ["--disable-blink-features=AutomationControlled"],
  });
  const context = await browser.newContext({
    viewport: cut.viewport,
    deviceScaleFactor: cut.deviceScaleFactor ?? 1,
    reducedMotion: "no-preference",
  });
  await context.addInitScript({ content: CLOCK_PATCH_SOURCE });
  const page = await context.newPage();

  await page.goto(url, { waitUntil: "networkidle" });

  // Sanity — the patch must have stuck before any user JS ran.
  const patched = await page.evaluate(() => Boolean((window as unknown as { __toolwall_clock_installed?: boolean }).__toolwall_clock_installed));
  if (!patched) {
    await browser.close();
    throw new Error("clock patch did not install before user JS — addInitScript() may have raced");
  }

  // Settle the layout once at virtual t=0 so the first frame is clean.
  await page.evaluate(() => (window as unknown as { __toolwall_advance: (n: number) => void }).__toolwall_advance(0));
  await page.waitForLoadState("domcontentloaded");

  const ff = startFfmpeg(cut, args.outDir);

  // Sort waypoints once; track the next one to fire.
  const waypoints = [...cut.waypoints].sort((a, b) => a.at - b.at);
  let wpIdx = 0;

  const t0 = Date.now();

  for (let f = 0; f < framesToRender; f++) {
    const virtualT = f * frameMs;

    // Fire any waypoints whose `at` has been reached.
    while (wpIdx < waypoints.length && waypoints[wpIdx]!.at <= virtualT) {
      const wp: Waypoint = waypoints[wpIdx]!;
      wpIdx++;
      if (wp.action) {
        try { await performAction(page, wp.action); }
        catch (e) {
          // eslint-disable-next-line no-console
          console.warn(`[recorder] waypoint at=${wp.at}ms (${wp.note ?? ""}) failed:`, (e as Error).message);
        }
      }
    }

    // Advance the patched clock by exactly one frame.
    await page.evaluate(
      (dt) => (window as unknown as { __toolwall_advance: (n: number) => void }).__toolwall_advance(dt),
      frameMs,
    );
    // Yield one microtask round-trip so React can commit the rAF
    // callbacks we just fired. We use evaluate(... Promise.resolve())
    // rather than waitForTimeout because waitForTimeout would burn
    // real wall-clock seconds we don't have.
    await page.evaluate(() => new Promise<void>((r) => Promise.resolve().then(() => Promise.resolve().then(() => r()))));

    const png = await page.screenshot({ type: "png", omitBackground: false });
    await ff.writeFrame(png);

    if (f % cut.fps === 0) {
      const wall = ((Date.now() - t0) / 1000).toFixed(1);
      // eslint-disable-next-line no-console
      console.log(`[recorder]   frame ${f}/${framesToRender}  vt=${(virtualT / 1000).toFixed(1)}s  wall=${wall}s`);
    }
  }

  await ff.done();
  await browser.close();
  return ff.outPath;
}

async function main(): Promise<void> {
  const args = parseArgs(process.argv.slice(2));
  const cut = CUTS[args.cut];
  if (!cut) {
    // eslint-disable-next-line no-console
    console.error(`unknown cut: ${args.cut}`);
    // eslint-disable-next-line no-console
    console.error("available:", Object.keys(CUTS).join(", "));
    process.exit(2);
  }
  const outPath = await record(cut, args);
  // eslint-disable-next-line no-console
  console.log(`[recorder] wrote ${outPath}`);
}

const isMain = fileURLToPath(import.meta.url) === resolve(process.argv[1] ?? "");
if (isMain) {
  main().catch((err: unknown) => {
    // eslint-disable-next-line no-console
    console.error("[recorder] fatal:", err);
    process.exit(1);
  });
}

export { record, parseArgs };
