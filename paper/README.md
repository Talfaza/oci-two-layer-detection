# Paper — "Hidden Channels in the Cloud"

First-draft preprint (ACM `acmart`, sigconf). Single self-contained source; all
figures are generated in-document with TikZ/pgfplots (no external image files).

## Compile

```bash
pdflatex main.tex     # run twice so cross-references/labels resolve
pdflatex main.tex
```

Requires a TeX distribution with `acmart`, `tikz`, `pgfplots` (>= 1.18),
`booktabs` (all standard in TeX Live / MiKTeX). Produces `main.pdf` (~4 pages).

## Before submitting

- Fill in the real author name / affiliation (top of `main.tex`, marked `TODO`).
- Figures are now backed by measurement: the byte-ratio (`fig:ratio`) is the live
  eBPF trace (B1 1:1, C 17:1; `results/trace_live.out`), and the crossover
  (`fig:crossover`) is a measured two-point result (static scan of both carriers +
  the live trace), not an interpolated curve.
- Verify/expand the `thebibliography` entries; switch to a `.bib` +
  `ACM-Reference-Format` for the venue version.
- It is set `nonacm` + copyright suppressed for a preprint; remove those for the
  camera-ready and add the real `\acmConference`/rights block.

## Structure

Intro (+ dual-use note) · Background (layers/whiteouts/eBPF) · Threat model ·
Dataset design (triplet + control ladder) · Static detection · Dynamic detection ·
Evaluation (static verdicts, byte-ratio, crossover) · Related work · Limitations ·
Conclusion. Findings are deliberately scoped as preliminary/single-carrier.
