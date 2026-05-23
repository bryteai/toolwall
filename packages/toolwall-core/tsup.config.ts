import { defineConfig } from "tsup";

export default defineConfig({
  entry: {
    index: "src/index.ts",
    "adapters/mcp": "src/adapters/mcp.ts",
    "adapters/vercel-ai": "src/adapters/vercel-ai.ts",
  },
  format: ["esm", "cjs"],
  dts: true,
  clean: true,
  splitting: false,
  sourcemap: true,
  treeshake: true,
  minify: false,
  target: "es2022",
  external: ["zod"],
});
