# Contributing to `toolwall`

Thanks for considering a contribution. `toolwall` is a security
library, so the bar for changes is "would I trust this to defend
my own agent's tool-response boundary?" — please apply that lens
before opening a PR.

## Where contributions are explicitly welcomed at v0.1.0

1. **New attack cases** in `bench/cases/mcp_v0_1.py`. Every case
   must cite a public disclosure (CVE, vendor blog, conference
   paper). PRs that invent attacks without provenance are
   declined. See `bench/README.md`.
2. **Framework adapters** following the existing template:
   `≤80 lines`, single `wrap()` entry point, one runnable example
   under `examples/<framework>/`. Prior art:
   `src/toolwall/adapters/` and `packages/toolwall-core/src/adapters/`.
3. **Detector patterns** for `src/toolwall/detect/patterns.py` and
   the Unicode-tag scanner. Each pattern must be cited in
   `src/toolwall/detect/attack_corpus.csv` against its public
   source.
4. **Reproducibility fixes** to `eval/`. If you can shorten the
   harness, sharpen a baseline, or surface a contamination case,
   please do — that work is the most valuable kind here.

## Where contributions are NOT welcomed at v0.1.0

These items are parked in `ROADMAP.md` and will open up later:

- New `Policy` fields beyond the 9 in the frozen v0.1 dataclass.
  Adding a field is an API change; we want it batched, not
  incremental.
- Public-facing leaderboard submissions. The submission protocol
  is locked to v0.2 — see `results/leaderboard.json`.
- Rust core ports — v0.4 territory.

## Process

1. Open an issue first for non-trivial work. A short design note
   beats a surprising PR.
2. Branch off `main`. Keep PRs ≤500 LOC where possible.
3. Run the local checks:
   ```bash
   uv sync --all-extras --dev
   ruff check . && ruff format --check .
   mypy src/toolwall
   pytest -q
   pnpm --filter @bryteai/toolwall-core test
   pnpm --filter @toolwall/recorder test
   python -m eval.run_pipeline --inhouse-only --force
   ```
4. Sign your commits (`git commit -s`). This adds a `Signed-off-by:`
   line and constitutes the Developer Certificate of Origin
   (https://developercertificate.org/) — your statement that you
   have the right to contribute the code under Apache-2.0.
5. Open a PR against `main`. Reference any related issue.

## Code style

- Python: `ruff` defaults, `mypy --strict`, type hints on every
  public symbol.
- TypeScript: `tsc --strict`, no `any`, `eslint` clean.
- Tests: every new public symbol gets at least one test; new
  attack patterns get a positive and a negative test.
- Docstrings/comments: written for the next reader. No marketing
  copy in source.

## Security

If you find a vulnerability in `toolwall` itself, please **do not**
open a public issue. Email `security@bryteai.studio` per
`SECURITY.md` — 90-day coordinated disclosure window.

## License

By contributing, you agree your changes are licensed under
Apache-2.0 (`LICENSE`).
