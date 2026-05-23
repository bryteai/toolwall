# `paper/` — arXiv preprint sources

Preprint that ships with `toolwall` v0.1.0:

> **Toolwall: A Defense-in-Depth Library for Indirect Prompt Injection
> at the Tool–Response Boundary**
> Muhammad Hasnain · bryteai.studio · Bin Abdullah LLC (Brooklyn, NY) · NVIDIA Inception
> arXiv: `cs.CR` primary · `cs.AI` cross-list (submission pending)

## Build locally

`toolwall-arxiv.tex` compiles with a stock TeX Live install. The
bibliography is inline (`\begin{thebibliography}`) to keep the
preprint self-contained for arXiv's compile pipeline, which does
not run BibTeX by default on first submission.

```bash
cd paper/
pdflatex toolwall-arxiv.tex
pdflatex toolwall-arxiv.tex   # second pass for refs
# → toolwall-arxiv.pdf
```

Or with `latexmk`:

```bash
latexmk -pdf toolwall-arxiv.tex
```

## arXiv submission

Upload the single `.tex` file. No external `.bib` is needed. arXiv's
auto-classifier should pick `cs.CR`; cross-list to `cs.AI` is added
on the submission form.

The CITATION.cff at repo root mirrors the citation block so GitHub
generates the "Cite this repository" button automatically.

## Versioning

The preprint is versioned in lockstep with `toolwall` releases:

| Preprint | toolwall | What changed |
|---|---|---|
| v1 (this) | v0.1.0   | First public release; rule-only floor; judge-pending. |
| v2        | v0.2.0   | Will add rules+judge measured numbers + held-out test split. |

Numbers in the abstract and §5 are replaced — never massaged — when
new measurements land.

## License

Apache-2.0, same as the codebase. Camera-ready figures and source
images (when added) live under `paper/figures/`.
