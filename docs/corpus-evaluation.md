# Corpus evaluation — scaling from proof-of-concept to measured claims

The generalization matrix (`experiments/generalize/`) shows the static detector
works on a handful of hand-built images. That is an existence proof, not an
evaluation. This harness turns it into measured claims: a **false-positive rate
on a large real corpus** and a **detection rate broken down per construction
factor**, each with a 95% confidence interval.

Everything streams — pull/build, scan, record, delete — so disk stays flat no
matter how many thousands of images you run. The persistent artifacts are the
verdict logs (CSV) and the report; the image tarballs are transient.

## The two classes

**Negatives — the false-positive test (`run_clean.py`).** Real, unmodified
upstream images from `images.txt`. Any HIGH on an untouched image is a false
positive. The log records which image, which finding kind, and the offending
path, which is exactly what you need to build the scale allowlist that CLAUDE.md
flags as an open problem. Multiple tags per repo are listed on purpose: layer
structure changes between versions, and that is where false positives hide.

**Positives — the detection test (`gen_stego.py`).** No public corpus of stego
container images exists, so the positive class is synthesised. `stegofactory.py`
injects carriers **without Docker** by appending gzip layer blobs to a base
`docker save` tarball and extending its `manifest.json` `Layers` list — the same
structure the scanner consumes. For every base in `bases.txt` it streams a full
factorial:

| Axis | Values | Stresses |
|---|---|---|
| carrier family | whiteout, appended | the static-vs-dynamic crossover |
| payload size | 1 KB, 100 KB, 5 MB | entropy cap, ratio, blob size |
| entropy | low (plaintext), high (packed/encrypted) | the `ENTROPY_HIGH` signal |
| whiteout style | file (`.wh.<name>`), opaque (`.wh..wh..opq`) | both hide mechanisms |
| hide depth | 1, 4 layers between add and whiteout | robustness of the correlation |

The **appended** family is deliberately included even though the static layer is
expected to miss it: that miss, measured at scale, is what grounds the crossover
claim and the appended PNGs are the inputs the dynamic (eBPF) evaluation reuses.

## Running it

```bash
# false-positive rate on the real corpus (resumable; --limit N to sample)
python3 experiments/corpus/run_clean.py

# synthetic positives, full factorial per base (resumable; --limit N)
python3 experiments/corpus/gen_stego.py

# aggregate both logs -> results/corpus/report.md (Wilson 95% CIs)
python3 experiments/corpus/analyze.py
```

Both harnesses are **resumable**: a base/image already present in the CSV is
skipped, so you can grow the corpus incrementally or run it in the background and
top it up later. For an unattended, resumable one-shot of all three steps:

```bash
nohup bash experiments/corpus/run_all.sh &   # survives the terminal closing
tail -f results/corpus/run.log               # follow progress
```

## Scale guidance

The lists ship at a runnable pilot size. To reach the paper target, extend the
two text files:

- **`images.txt`** → ~1,000 image:tag lines for a tight FPR interval. More tags
  per repo costs little and probes more layer layouts.
- **`bases.txt`** → ~50–60 diverse carriers. At 30 factorial cells per base that
  is ~1,500–1,800 positive samples, enough for per-factor recall with narrow CIs.

## Outputs

```
results/corpus/clean_verdicts.csv    one row per real image (FP evidence)
results/corpus/stego_verdicts.csv    one row per synthetic variant (recall)
results/corpus/report.md             FPR + per-factor recall, with 95% CIs
```

## What this does and does not establish

- It measures the static layer's FPR and its recall on the **whiteout** family
  across construction parameters. That is the core quantitative claim.
- It does **not** by itself add a tool-vs-tool baseline (Trivy/Grype/dive/ClamAV)
  or a dynamic-layer ROC. Those are the next artifacts; this corpus is the
  substrate they run on.
