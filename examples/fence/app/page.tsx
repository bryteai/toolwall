import { CodeSnippet } from "@/components/CodeSnippet";
import { Examples } from "@/components/Examples";
import { Results } from "@/components/Results";

export default function Page() {
  return (
    <main className="relative">
      <div className="fence-grid absolute inset-x-0 top-0 h-[520px] opacity-40 pointer-events-none" aria-hidden />
      <div className="relative mx-auto max-w-6xl px-4 sm:px-8 pt-12 sm:pt-16 pb-24">
        <Header />

        <div className="mt-10">
          <Examples />
        </div>

        <div className="mt-12 grid gap-6 lg:grid-cols-[3fr_2fr]">
          <Results />
          <CodeSnippet />
        </div>

        <BelowTheFold />
        <Footer />
      </div>
    </main>
  );
}

const LINK = "text-[color:var(--color-paper)] hover:text-[color:var(--color-fence)] transition-colors";

function Header() {
  return (
    <header className="relative">
      <div className="flex items-center gap-2">
        <span className="inline-block w-2 h-2 rounded-full bg-[color:var(--color-fence)]" aria-hidden />
        <span className="text-[11px] font-mono uppercase tracking-[0.2em] text-[color:var(--color-fog)]">
          fence.bryteai.studio · toolwall v0.2
        </span>
      </div>
      <h1 className="mt-4 text-3xl sm:text-5xl font-semibold tracking-tight text-[color:var(--color-paper)]">
        Check every tool response before your agent reads it.
      </h1>
      <p className="mt-4 max-w-2xl text-[color:var(--color-bone)] leading-relaxed">
        <span className="text-[color:var(--color-paper)]">toolwall</span> is an
        open-source (Apache-2.0) library that scores what a tool returns (a web
        page, an email, an API result) for instructions aimed at the AI agent,
        and blocks it before it reaches the model. It uses regex rules and a
        small fine-tuned classifier. Below are three real outputs of v0.2.0,
        one of them a miss, and its held-out results.
      </p>
      <div className="mt-5 flex flex-wrap items-center gap-x-5 gap-y-2 text-[12px] font-mono text-[color:var(--color-fog)]">
        <a href="https://github.com/bryteai/toolwall" className={LINK}>↗ github.com/bryteai/toolwall</a>
        <a href="https://github.com/bryteai/toolwall/blob/main/paper/toolwall-v0.2-report.pdf" className={LINK}>↗ technical report (PDF)</a>
        <a href="https://huggingface.co/bryteai/toolwall-judge-v0.2" className={LINK}>↗ HF · toolwall-judge-v0.2</a>
        <span>·</span>
        <span>Apache-2.0 · v0.2.0</span>
      </div>
    </header>
  );
}

function BelowTheFold() {
  return (
    <section className="mt-16 grid gap-8 md:grid-cols-3">
      <Pillar
        title="three layers, one decorator"
        body="Policy declares what the tool may see and return. Detectors score every response: rules first, then the classifier. Enforcement passes the response, redacts it, or raises Blocked(reason, evidence), and logs the decision."
      />
      <Pillar
        title="explicit limits"
        body="URL allowlists, an egress denylist, a path scope, response size, injection-score threshold, rate and cost limits are all declared in the policy."
      />
      <Pillar
        title="where it falls short"
        body="It misses most attacks that change the answer instead of overriding instructions (BIPIA: 8 of 150 caught). It checks single responses; it does not measure what the agent does next. The report lists every limitation."
      />
    </section>
  );
}

function Pillar({ title, body }: { title: string; body: string }) {
  return (
    <article className="rounded-xl border border-[color:var(--color-edge)] bg-[color:var(--color-ink-1)] p-5">
      <h3 className="text-sm font-mono uppercase tracking-widest text-[color:var(--color-fence)]">{title}</h3>
      <p className="mt-3 text-[14px] text-[color:var(--color-bone)] leading-relaxed">{body}</p>
    </article>
  );
}

function Footer() {
  return (
    <footer className="mt-20 pt-8 border-t border-[color:var(--color-edge)] text-[11px] font-mono text-[color:var(--color-fog)] leading-relaxed">
      <p>
        toolwall is a research prototype released under Apache-2.0 by{" "}
        <a href="https://hasnain.bryteai.studio" className="text-[color:var(--color-paper)] underline">Muhammad Hasnain</a>{" "}
        — bryteai.studio (Bin Abdullah LLC) · NVIDIA Inception member.
      </p>
      <p className="mt-2">
        It does not prevent direct jailbreaks typed by the user, sandbox escapes, or supply-chain compromise. See{" "}
        <a href="https://github.com/bryteai/toolwall/blob/main/THREAT_MODEL.md" className="underline">THREAT_MODEL.md</a>.
      </p>
      <p className="mt-2">
        Security reports:{" "}
        <a href="https://github.com/bryteai/toolwall/security/advisories/new" className="underline">private vulnerability report</a>.
      </p>
    </footer>
  );
}
