/**
 * `create-toolwall-worker` — scaffolds a Cloudflare Workers MCP server
 * with @bryteai/toolwall-core, OAuth 2.1 PKCE, Streamable HTTP transport,
 * a KV audit log, and a Durable Object session store pre-wired.
 *
 * Usage::
 *
 *     npx create-toolwall-worker my-mcp
 *     cd my-mcp
 *     pnpm install
 *     wrangler deploy
 *
 * No interactive prompts beyond the project name on argv — refuses to
 * grow a survey UI. Every choice we'd ask about has a sane default in
 * the template and the README tells the user how to override it.
 */

import { cpSync, existsSync, readdirSync, readFileSync, writeFileSync } from "node:fs";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { argv, exit, stdout } from "node:process";

const HERE = dirname(fileURLToPath(import.meta.url));
// dist/ sits next to template/ in the published package
const TEMPLATE_DIR = join(HERE, "..", "template");

interface CliArgs {
  readonly target: string;
  readonly force: boolean;
}

function parseArgs(): CliArgs {
  const args = argv.slice(2);
  let target = "";
  let force = false;
  for (const a of args) {
    if (a === "--force" || a === "-f") {
      force = true;
    } else if (a === "--help" || a === "-h") {
      printHelp();
      exit(0);
    } else if (!a.startsWith("-") && !target) {
      target = a;
    }
  }
  if (!target) {
    printHelp();
    exit(2);
  }
  return { target, force };
}

function printHelp(): void {
  stdout.write(
    [
      "create-toolwall-worker — scaffold a Cloudflare Workers MCP server.",
      "",
      "Usage:",
      "  npx create-toolwall-worker <project-name> [--force]",
      "",
      "What you get:",
      "  - Cloudflare Workers + Durable Object MCP server (TypeScript)",
      "  - Streamable HTTP transport (not SSE — that lane is dead)",
      "  - OAuth 2.1 PKCE with KV-backed token store",
      "  - @bryteai/toolwall-core wrapping every tool handler",
      "  - KV audit log of every tool call (request + decision + redaction)",
      "  - wrangler.toml ready to `wrangler deploy`",
      "",
    ].join("\n"),
  );
}

function isEmptyDir(path: string): boolean {
  try {
    return readdirSync(path).length === 0;
  } catch {
    return true;
  }
}

function substituteName(content: string, name: string): string {
  return content.replaceAll("__PROJECT_NAME__", name);
}

function applyNameSubstitution(root: string, name: string): void {
  const walk = (dir: string): void => {
    for (const entry of readdirSync(dir, { withFileTypes: true })) {
      const p = join(dir, entry.name);
      if (entry.isDirectory()) {
        walk(p);
        continue;
      }
      if (!isTextFile(entry.name)) continue;
      const original = readFileSync(p, "utf8");
      if (!original.includes("__PROJECT_NAME__")) continue;
      writeFileSync(p, substituteName(original, name));
    }
  };
  walk(root);
}

function isTextFile(name: string): boolean {
  return /\.(ts|js|json|toml|md|txt|yaml|yml)$|^README$/.test(name);
}

function main(): void {
  const { target, force } = parseArgs();
  const dest = resolve(target);
  const name = target.replace(/[/\\].*$/, "").replace(/[^a-z0-9-]+/gi, "-");

  if (existsSync(dest) && !isEmptyDir(dest) && !force) {
    stdout.write(
      `refusing to scaffold into non-empty directory: ${dest}\n` +
        `use --force to overwrite.\n`,
    );
    exit(1);
  }

  cpSync(TEMPLATE_DIR, dest, { recursive: true });
  applyNameSubstitution(dest, name);

  stdout.write(
    [
      `scaffolded ${name} at ${dest}`,
      "",
      "next steps:",
      `  cd ${target}`,
      "  pnpm install",
      "  wrangler secret put OAUTH_CLIENT_SECRET",
      "  wrangler kv namespace create AUDIT",
      "  wrangler kv namespace create OAUTH",
      "  # paste the IDs into wrangler.toml",
      "  wrangler deploy",
      "",
    ].join("\n"),
  );
}

main();
