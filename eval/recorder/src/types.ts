/**
 * Recorder waypoint script — drives a recording end-to-end.
 *
 * The recorder walks the waypoint list once, advancing the virtual
 * clock by `1000 / fps` per frame. When the running virtual time
 * passes a waypoint's `at`, the waypoint's `action` is performed
 * synchronously before the screenshot for that frame is taken.
 *
 * Keep actions cheap (clicks, scrolls, eval). Anything that needs
 * to wait on the network or model output belongs outside the
 * recorder — the demo is pure client-side animation.
 */
export type Action =
  | { readonly kind: "click"; readonly selector: string }
  | { readonly kind: "click-text"; readonly text: string }
  | { readonly kind: "scroll-into-view"; readonly selector: string }
  | { readonly kind: "scroll-to-top" }
  | { readonly kind: "scroll-y"; readonly y: number }
  | { readonly kind: "eval"; readonly fn: string }
  | { readonly kind: "wait"; readonly ms: number };

export interface Waypoint {
  readonly at: number;
  readonly action?: Action;
  readonly note?: string;
}

export interface Cut {
  readonly id: string;
  readonly description: string;
  readonly url: string;
  readonly viewport: { readonly width: number; readonly height: number };
  readonly deviceScaleFactor?: number;
  readonly fps: number;
  readonly durationMs: number;
  readonly waypoints: readonly Waypoint[];
  /**
   * Encoder profile. Output is mp4 with H.264 + yuv420p — universally
   * playable on X / LinkedIn / GitHub README, no audio track.
   */
  readonly encoder?: {
    readonly crf?: number;
    readonly preset?: string;
    readonly pixFmt?: string;
    readonly extraArgs?: readonly string[];
  };
}
