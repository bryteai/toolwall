/**
 * Markdown image / link sink detector — the EchoLeak class.
 *
 * Any markdown image or link whose URL host does NOT match the
 * caller's allowlist is treated as an exfil sink. We score the worst
 * case found in the text. Hosts on the allowlist are silently
 * accepted (they are typically the agent's own CDN / docs site).
 */

import type { Detection } from "../types.js";

const MD_IMAGE_RE = /!\[[^\]]*\]\(([^)\s]+)/g;
const MD_LINK_RE = /\[[^\]]+\]\(([^)\s]+)/g;

function hostOf(url: string): string | null {
  try {
    return new URL(url).hostname.toLowerCase();
  } catch {
    return null;
  }
}

function matchesGlob(host: string, glob: string): boolean {
  const g = glob.toLowerCase().trim();
  if (g === "*") return true;
  if (g.startsWith("*.")) return host === g.slice(2) || host.endsWith(g.slice(1));
  return host === g;
}

export function detect(
  text: string,
  allowlist: readonly string[] = [],
): readonly Detection[] {
  const out: Detection[] = [];
  const scan = (re: RegExp, kind: string, score: number): void => {
    re.lastIndex = 0;
    let m: RegExpExecArray | null;
    while ((m = re.exec(text)) !== null) {
      const url = m[1];
      if (!url) continue;
      const host = hostOf(url);
      if (!host) continue;
      if (allowlist.some((g) => matchesGlob(host, g))) continue;
      out.push({
        kind,
        span: [m.index, m.index + m[0].length],
        score,
        evidence: { url, host },
      });
    }
  };
  // Images first — strongest sink because they auto-fetch on render.
  scan(MD_IMAGE_RE, "markdown-image-exfil", 0.9);
  scan(MD_LINK_RE, "markdown-link-exfil", 0.65);
  return out;
}
