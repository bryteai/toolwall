# Decisions log --- `bryteai/toolwall`

This file is the public, append-only log of one-way-door decisions that
affect what is shipped, what is excluded, and what risks the project has
**accepted as accepted-rather-than-mitigated**. Every entry names the
decision, the reason, and what was knowingly not done.

The point is that future contributors, reviewers, and security
researchers can read this file and understand which corners of the
project are intentional vs. accidental.

---

## 2026-05-23 --- Honest negative results stay published

We publish, in the same release as the headline numbers:

- The dev-set saturation disclosure for the judge LoRA
  (`training/MODEL_CARD.md` §5.3).
- The novel-family generalization probe (`asr = 0.80` on 10 CrewAI-
  generated attack families outside the canonical 7), in
  `results/leaderboard.json` under
  `defense=toolwall_rules_only, split=novel_attacks_crewai_holdout`.
- The MinHash overlap audit between train and held-out test splits
  (`results/train_test_similarity.json`).

Reason: it is easier to defend a published weakness than an unpublished
one that a reviewer finds first. We would rather lose the cherry-pick
critique than the credibility.

Not done: we did not suppress, gate, or footnote-bury any of the above
to make the headline ASR look stronger.

---

## 2026-05-23 --- Apache-2.0 base-model substitution for the judge

The frozen specification names `meta-llama/Llama-3.1-8B-Instruct` as the
judge base. The shipped artifacts use `Qwen/Qwen2.5-7B-Instruct`
(Apache-2.0) instead.

Reason: Llama 3.1 is gated. Distributing a LoRA adapter on top of a
gated base creates a license question that we are not equipped to
answer responsibly today. Qwen2.5-7B-Instruct is open under Apache-2.0,
which composes cleanly with the rest of the project license.

This substitution is disclosed in:

- `paper/toolwall-arxiv.tex` (Sec. 4, methodology).
- `training/MODEL_CARD.md` (substitution rationale).
- `results/leaderboard.json` (judge metadata block).
- `models/judge-v0.1/README.md` (redirect to the model card).

Not done: we did not retrain on the originally-specified base and
silently swap numbers; the numbers reported are from the Qwen-based
judge.

---

## 2026-05-24 --- Pre-orphan history is permanently disclosed (ACCEPTED RISK)

The current `main` branch was rewritten via orphan-squash on
2026-05-23. The pre-orphan history contained Day-N commit messages
("Day 5 LoRA judge", etc.) and other founder-process narrative that
was deemed inappropriate for a public OSS release.

Even though `bryteai/toolwall` no longer references those commits,
they were public on GitHub for several hours before the lockdown.
That window was sufficient for several public mirrors to ingest the
history. In particular:

- `gharchive.org` ingests every public PushEvent and ships them to
  Google BigQuery (`githubarchive.day.*`). Their copy is
  **unrecoverable** by the repository owner.
- Software Heritage may have crawled the repo during the window;
  their archival is similarly one-way.
- Search-index mirrors (Sourcegraph zoekt, public code-search
  crawlers) may hold cached snapshots until their refresh cycle.

We accept this risk. It cannot be mitigated by force-push, repository
deletion, or repository re-creation. The only things that **can** be
mitigated are:

1. That the current published surface is clean. We have verified this
   via anonymous-clone stranger sweeps at every amend cycle.
2. That future commits do not repeat the pattern. The single-line
   commit-message policy, the default-deny public-flip rule (see
   founder memory), and the `chore(...)`/`docs(...)`/`feat(...)`
   prefix convention are in place to prevent recurrence.

Not done: we did not approach GHArchive / Software Heritage / Google
BigQuery to request takedown. Their archives are explicitly designed
to be irrevocable in the name of research reproducibility, and asking
for a research-archive takedown would draw far more attention to the
pre-orphan history than the history itself attracts.

---

## 2026-05-24 --- v0.1.0 references the tag, not stale SHAs

All published metadata --- `results/leaderboard.json`,
`scripts/update_leaderboard.py`, `paper/toolwall-arxiv.tex` ---
references the release as `git_tag: "v0.1.0"`, not as a 7-character
SHA prefix.

Reason: the v0.1.0 tag survives orphan-squash + force-push; an SHA
prefix does not. We had three amend cycles in 24 hours; pinning to
SHAs was a non-trivial source of inconsistency. The tag is the
single source of truth.

Not done: we did not preserve any pre-tag SHA as a "historical"
reference; if you cloned the repo before tag v0.1.0 was annotated at
the current main, you are out of date and your local copy is not
reproducible against published numbers.

---

## 2026-05-24 --- Dependency-CVE triage is tracked in the public issue tracker

Transitive CVEs from `crewai`, `langgraph`, and other dev-dependencies
are not gated on release. They are tracked in the GitHub issue
tracker under the `chore(deps)` label so that:

- Anyone reviewing the project can see them.
- Dependabot can auto-PR fixes.
- We do not block v0.1.0 on issues that have no exploit path in this
  project's actual runtime code (the runtime only imports
  `toolwall.detect.*`; `crewai` and `langgraph` are dev-only).

Not done: we did not pin every transitive dependency to the latest
patch release as a precondition of v0.1.0. That work continues on
the main branch after release.
