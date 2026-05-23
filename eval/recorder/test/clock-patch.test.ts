import { describe, expect, it } from "vitest";
import { CLOCK_PATCH_SOURCE } from "../src/clock-patch.js";

/**
 * The patch is shipped as a string to `addInitScript()`. We evaluate
 * it inside a Function() and assert the contract holds.
 *
 * We do NOT spin up Chromium here — that's covered by the full
 * recorder run in CI / dry mode. These checks are unit-grade.
 */
describe("clock-patch contract", () => {
  it("installs the four named globals", () => {
    const win: Record<string, unknown> & {
      performance: { now(): number };
      Date: DateConstructor;
      requestAnimationFrame?: unknown;
      cancelAnimationFrame?: unknown;
    } = {
      performance: { now: () => 999 },
      Date,
    };
    const ctx = {
      window: win,
      performance: win.performance,
      Date: win.Date,
      console,
    };
    // eslint-disable-next-line @typescript-eslint/no-implied-eval
    new Function("window", "performance", "Date", "console", CLOCK_PATCH_SOURCE)(
      ctx.window, ctx.performance, ctx.Date, ctx.console,
    );

    expect(typeof ctx.window.requestAnimationFrame).toBe("function");
    expect(typeof ctx.window.cancelAnimationFrame).toBe("function");
    expect(typeof ctx.performance.now).toBe("function");
    // After patch the virtual clock starts at 0.
    expect(ctx.performance.now()).toBe(0);
    // Driver protocol is exposed.
    expect(typeof (ctx.window as Record<string, unknown>).__toolwall_advance).toBe("function");
    expect(typeof (ctx.window as Record<string, unknown>).__toolwall_clock).toBe("function");
  });

  it("advances virtual time and drains the rAF queue", () => {
    const win: Record<string, unknown> & {
      performance: { now(): number };
      Date: DateConstructor;
    } = { performance: { now: () => 0 }, Date };
    // eslint-disable-next-line @typescript-eslint/no-implied-eval
    new Function("window", "performance", "Date", "console", CLOCK_PATCH_SOURCE)(
      win, win.performance, win.Date, console,
    );

    const calls: number[] = [];
    (win.requestAnimationFrame as (cb: (t: number) => void) => number)((t) => calls.push(t));
    (win.requestAnimationFrame as (cb: (t: number) => void) => number)((t) => calls.push(t * 2));

    (win.__toolwall_advance as (ms: number) => void)(16.6667);

    expect(calls).toEqual([16.6667, 33.3334]);
    expect((win.__toolwall_clock as () => number)()).toBeCloseTo(16.6667, 4);
    // Subsequent advances continue the clock.
    (win.__toolwall_advance as (ms: number) => void)(16.6667);
    expect((win.__toolwall_clock as () => number)()).toBeCloseTo(33.3334, 4);
  });

  it("cancels queued callbacks", () => {
    const win: Record<string, unknown> & {
      performance: { now(): number };
      Date: DateConstructor;
    } = { performance: { now: () => 0 }, Date };
    // eslint-disable-next-line @typescript-eslint/no-implied-eval
    new Function("window", "performance", "Date", "console", CLOCK_PATCH_SOURCE)(
      win, win.performance, win.Date, console,
    );

    const calls: string[] = [];
    const id = (win.requestAnimationFrame as (cb: () => void) => number)(() => calls.push("a"));
    (win.requestAnimationFrame as (cb: () => void) => number)(() => calls.push("b"));
    (win.cancelAnimationFrame as (id: number) => void)(id);

    (win.__toolwall_advance as (ms: number) => void)(16);
    expect(calls).toEqual(["b"]);
  });

  it("does not patch setTimeout (React scheduler must stay intact)", () => {
    const realSetTimeout = (fn: () => void, ms?: number) => {
      void fn; void ms;
      return 7 as unknown as ReturnType<typeof setTimeout>;
    };
    const win: Record<string, unknown> & {
      performance: { now(): number };
      Date: DateConstructor;
      setTimeout: typeof realSetTimeout;
    } = { performance: { now: () => 0 }, Date, setTimeout: realSetTimeout };
    // eslint-disable-next-line @typescript-eslint/no-implied-eval
    new Function("window", "performance", "Date", "console", CLOCK_PATCH_SOURCE)(
      win, win.performance, win.Date, console,
    );
    // setTimeout must be the same reference after patch installs.
    expect(win.setTimeout).toBe(realSetTimeout);
  });

  it("is idempotent — installing twice does not double-wrap", () => {
    const win: Record<string, unknown> & {
      performance: { now(): number };
      Date: DateConstructor;
    } = { performance: { now: () => 0 }, Date };
    const install = (): void => {
      // eslint-disable-next-line @typescript-eslint/no-implied-eval
      new Function("window", "performance", "Date", "console", CLOCK_PATCH_SOURCE)(
        win, win.performance, win.Date, console,
      );
    };
    install();
    const firstRaf = win.requestAnimationFrame;
    install();
    expect(win.requestAnimationFrame).toBe(firstRaf);
  });
});
