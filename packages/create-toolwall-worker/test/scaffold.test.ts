import { execSync } from "node:child_process";
import { mkdtempSync, readFileSync, rmSync, statSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterAll, beforeAll, describe, expect, it } from "vitest";

const CLI = join(import.meta.dirname, "..", "dist", "cli.js");

describe("create-toolwall-worker CLI", () => {
  let work: string;

  beforeAll(() => {
    // Build the CLI before running scaffold tests.
    execSync("pnpm build", { cwd: join(import.meta.dirname, "..") });
    work = mkdtempSync(join(tmpdir(), "ctw-"));
  });

  afterAll(() => {
    rmSync(work, { recursive: true, force: true });
  });

  it("scaffolds into an empty directory and substitutes the project name", () => {
    const name = "my-mcp";
    execSync(`node ${CLI} ${name}`, { cwd: work });

    const projectDir = join(work, name);
    expect(statSync(projectDir).isDirectory()).toBe(true);
    expect(statSync(join(projectDir, "wrangler.toml")).isFile()).toBe(true);
    expect(statSync(join(projectDir, "package.json")).isFile()).toBe(true);
    expect(statSync(join(projectDir, "src", "index.ts")).isFile()).toBe(true);
    expect(statSync(join(projectDir, "src", "mcp.ts")).isFile()).toBe(true);
    expect(statSync(join(projectDir, "src", "oauth.ts")).isFile()).toBe(true);
    expect(statSync(join(projectDir, "src", "audit.ts")).isFile()).toBe(true);

    const pkg = JSON.parse(
      readFileSync(join(projectDir, "package.json"), "utf8"),
    ) as { name: string; dependencies: Record<string, string> };
    expect(pkg.name).toBe(name);
    expect(pkg.dependencies["@bryteai/toolwall-core"]).toMatch(/^\^/);

    const wrangler = readFileSync(join(projectDir, "wrangler.toml"), "utf8");
    expect(wrangler).toContain(`name = "${name}"`);
    expect(wrangler).not.toContain("__PROJECT_NAME__");
  });

  it("refuses to scaffold into a non-empty dir without --force", () => {
    expect(() =>
      execSync(`node ${CLI} my-mcp`, { cwd: work, stdio: "pipe" }),
    ).toThrow();
  });

  it("--force overwrites a non-empty dir", () => {
    expect(() =>
      execSync(`node ${CLI} my-mcp --force`, { cwd: work, stdio: "pipe" }),
    ).not.toThrow();
  });
});
