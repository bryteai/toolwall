import { defineConfig } from "tsup";

export default defineConfig({
  entry: { cli: "src/cli.ts" },
  format: ["esm"],
  clean: true,
  splitting: false,
  sourcemap: false,
  treeshake: true,
  minify: false,
  target: "node20",
  shims: false,
  banner: { js: "#!/usr/bin/env node" },
});
