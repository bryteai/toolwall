import { CodeSnippet } from "@/components/CodeSnippet";
import { DemoStage } from "@/components/DemoStage";
import { Leaderboard } from "@/components/Leaderboard";

export default function Page() {
  return (
    <main className="relative">
      <div className="fence-grid absolute inset-x-0 top-0 h-[520px] opacity-40 pointer-events-none" aria-hidden />
      <div className="relative mx-auto max-w-6xl px-5 sm:px-8 pt-12 sm:pt-16 pb-24">
        <Header />

        <div className="mt-10">
          <DemoStage />
        </div>

        <div className="mt-12 grid gap-6 lg:grid-cols-[3fr_2fr]">
          <Leaderboard />
          <CodeSnippet />
        </div>

        <BelowTheFold />
        <Footer />
      </div>
    </main>
  );
}

function Header() {
  return (
    <header className="relative">
      <div className="flex items-center gap-2">
        <span className="inline-block w-2 h-2 rounded-full bg-[color:var(--color-fence)]" aria-hidden />
        <span className="text-[11px] font-mono uppercase tracking-[0.2em] text-[color:var(--color-fog)]">
          fence.bryteai.studio · live demo
        </span>
      </div>
      <h1 className="mt-4 text-3xl sm:text-5xl font-semibold tracking-tight text-[color:var(--color-paper)]">
        Tool calls have a trust boundary now.
      </h1>
      <p className="mt-4 max-w-2xl text-[color:var(--color-bone)] leading-relaxed">
        <span className="text-[color:var(--color-paper)]">toolwall</span> is an
        opensource Apache-2.0 library that wraps the tools your AI agent
        already uses and blocks indirect prompt injection at the tool–response
        boundary. Pick an attack on the right side, hit play, and watch the
        same agent get exfil&apos;d on the left and defended on the right.
      </p>
      <div className="mt-5 flex flex-wrap items-center gap-x-5 gap-y-2 text-[12px] font-mono text-[color:var(--color-fog)]">
        <a
          href="https://github.com/bryteai/toolwall"
          className="text-[color:var(--color-paper)] hover:text-[color:var(--color-fence)] transition-colors"
        >
          ↗ github.com/bryteai/toolwall
        </a>
        <a
          href="https://arxiv.org/abs/2606.XXXXX"
          className="text-[color:var(--color-paper)] hover:text-[color:var(--color-fence)] transition-colors"
        >
          ↗ arXiv preprint (cs.CR)
        </a>
        <a
          href="https://huggingface.co/datasets/bryteai/toolwall-bench-v0.1"
          className="text-[color:var(--color-paper)] hover:text-[color:var(--color-fence)] transition-colors"
        >
          ↗ HF · toolwall-bench-v0.1
        </a>
        <span>·</span>
        <span>Apache-2.0 · v0.1.0</span>
      </div>
    </header>
  );
}

function BelowTheFold() {
  return (
    <section className="mt-16 grid gap-8 md:grid-cols-3">
      <Pillar
        title="three layers, one decorator"
        body="Policy declares what the tool may see and return. Detector scores every payload (rules + judge). Enforcement either passes a sanitized response, returns the redacted span, or raises Blocked(reason, evidence)."
      />
      <Pillar
        title="capability-based, deny-by-default"
        body="No allowlist, no call. Egress hosts, paths, response size, IPI score, rate, and cost are all explicit. Failing open is a bug, not a feature."
      />
      <Pillar
        title="ships where your agent runs"
        body="Python + TypeScript with identical shape. Adapters for CrewAI, LangGraph, Claude SDK, OpenAI Agents SDK, MCP servers, and a one-command Cloudflare Workers MCP template."
      />
    </section>
  );
}

function Pillar({ title, body }: { title: string; body: string }) {
  return (
    <article className="rounded-xl border border-[color:var(--color-edge)] bg-[color:var(--color-ink-1)] p-5">
      <h3 className="text-sm font-mono uppercase tracking-widest text-[color:var(--color-fence)]">
        {title}
      </h3>
      <p className="mt-3 text-[14px] text-[color:var(--color-bone)] leading-relaxed">{body}</p>
    </article>
  );
}

function Footer() {
  return (
    <footer className="mt-20 pt-8 border-t border-[color:var(--color-edge)] text-[11px] font-mono text-[color:var(--color-fog)] leading-relaxed">
      <p>
        toolwall is a research artefact released under Apache-2.0 by{" "}
        <span className="text-[color:var(--color-paper)]">Muhammad Hasnain</span>{" "}
        — bryteai.studio (Bin Abdullah LLC, Brooklyn NY) · NVIDIA Inception member.
      </p>
      <p className="mt-2">
        The lib does not prevent model-direct jailbreaks, host sandbox escapes,
        or supply-chain compromise. See{" "}
        <a href="https://github.com/bryteai/toolwall/blob/main/THREAT_MODEL.md" className="underline">
          THREAT_MODEL.md
        </a>{" "}
        for the full set of failure modes.
      </p>
      <p className="mt-2">
        Disclosure: <a href="mailto:disclosure@bryteai.studio" className="underline">disclosure@bryteai.studio</a> · 90-day window.
      </p>
    </footer>
  );
}
