import type { Cut } from "../types.js";
import { landscape5min } from "./landscape-5min.js";
import { portrait60s } from "./portrait-60s.js";

export const CUTS: Readonly<Record<string, Cut>> = {
  "portrait-60s":  portrait60s,
  "landscape-5min": landscape5min,
};
