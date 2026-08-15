# Research Journal — OCI/Docker Image Steganography Detection

Running log of progress, decisions, and findings. Newest entries at the top.

---

## 2026-08-15 — Large-scale corpus evaluation (`experiments/corpus/`)

Turned the 6-image generalization matrix into a measured evaluation with a false-
positive rate and per-factor recall, each with Wilson 95% CIs. New harness under
`experiments/corpus/`; design in `docs/corpus-evaluation.md`.

**Method.** Two classes, streamed (pull/build → scan → delete, so disk stays flat
at any scale; both harnesses resumable via the CSV logs):
- *Negatives (FPR):* real unmodified Docker Hub images from `images.txt`, scanned
  as-is. Any HIGH = a false positive. (`run_clean.py`)
- *Positives (recall):* synthesized by `stegofactory.py`, which injects carriers
  **without Docker** — appends gzip layer blobs to a base `docker save` tar and
  extends `manifest.json` `Layers`, the exact structure the scanner consumes. Full
  factorial per base: family (whiteout/appended) × payload size (1K/100K/5M) ×
  entropy (low/high) × whiteout style (file/opaque) × hide depth (1/4) = 30
  variants/base. (`gen_stego.py`) Aggregated by `analyze.py` → `results/corpus/report.md`.

**Results.**
- **Recall (static, whiteout family): 1104/1104 = 100%** (95% CI 99.7–100%) across
  **46 diverse bases** (os/lang/db/web/broker/ci/monitoring, mixed distros) and
  every factorial cell. Detection keys on *structure* (planted-exec + add-then-hide),
  so payload size, encryption, whiteout style, and hide depth do not defeat it.
- **Appended family: 0/276 by static** — the by-design blind spot; grounds the
  crossover at scale and feeds the dynamic eval. These PNGs double as extractor inputs.
- **FPR:** 1 false positive across the clean corpus → **`rockylinux:8`** ships two
  executable Anaconda **kickstart scripts** (`tmp/ks-script-*`, entropy ~4.5) that
  trip the "planted executable in a data dir" rule. Notably **planted-alone, not
  add-then-hide** — the core whiteout correlation did not misfire — and the other
  RPM-family images (fedora, almalinux, amazonlinux, rockylinux:9) were clean, so
  it is image-build-specific, not distro-wide. This is exactly the "needs an
  allowlist at scale" limitation predicted below, now measured with a named cause.

**Gotchas found.**
- 3 stego bases (`openjdk:17-slim`, `consul:1.19`, `vault:1.17`) failed to pull —
  deprecated/removed from Docker Hub (openjdk → eclipse-temurin; consul/vault →
  `hashicorp/` namespace). Effective base count 46.
- **Docker Hub anonymous pull rate limit** (100 pulls/6hr) hit mid-run after ~46
  stego + ~62 clean pulls; the remaining clean images failed as a block until the
  window cleared. `run_clean.py` is resumable, so re-running fills the gap. For a
  1,000-image corpus, `docker login` (200/6hr) or a paid account is needed first.

TODO: fold FPR + per-factor recall tables into the paper; add the rockylinux:8 FP
as a "false positives and fixes" discussion (allowlist `ks-script-*` / require
add-then-hide for HIGH / skip low-entropy plaintext); give the dynamic layer the
same corpus treatment (benign-memfd negatives + extractor ratio sweep + ROC).

---

## 2026-08-12 — Repo reorganized for GitHub

Restructured into a conventional layout: `static/`, `dynamic/` (+`docker/`),
`experiments/generalize/`, `samples/`, `results/`, `docs/`, `scripts/`, `paper/`.
Stripped verbose comments from all code and moved the design knowledge into
`docs/` (overview, static-detection, dynamic-detection, generalization). Added
root `README.md` and `.gitignore` (ignores `venv/`, `samples/*.tar`, build
artifacts). Renamed `baseline/static_scanner.py` → `static/baseline_scanner.py`,
`layer_scanner.py` → `static/layer_scanner.py`; scanners now default to
`samples/*.tar`. Updated all internal paths (Makefile, run_matrix.sh,
summarize.py, docs). Verified after move: both scanners, OCI scan, dynamic `make host-test`,
`summarize.py`, and the paper all still work. Deleted 9-byte junk
`tetragon-$GOOS-$GOARCH.tar.gz`. Not yet `git init`'d.

---

## Project at a glance

**Question:** Can a payload be smuggled inside a container image so that it is
invisible in the runtime filesystem yet still physically present in the image,
and can a layer-aware scanner detect it where a naive scanner cannot?

**Technique under study:** overlayfs **whiteout** smuggling — add a payload in a
lower layer, then "delete" it in a higher layer with a `.wh.<name>` marker. In
the flattened rootfs the file is gone; in the layer blobs the bytes remain
(recoverable / re-materializable).

**Corpus (three `httpd`-based images):**
| Image | Delivery | Expected verdict |
|-------|----------|------------------|
| `clean.tar` | none (control) | clean |
| `plain.tar` | payload visible in a layer | detectable |
| `stego.tar` | payload hidden via whiteout | evasive |
| `stego_oci/` | same as stego, OCI layout | (format-parity check) |

Payload body: `systemd-journal-cache.sh` (disguised) / `payload.sh` (plain);
both drop `/tmp/stego_marker` as harmless proof-of-execution.

---

## 2026-08-12 — Crossover grounded in real measurement (both endpoints)

Closed the last "illustrative" gap. Measured the static detector on the
content-embedded (appended-data PNG) carrier by building `stego:c`
(carrier.png in htdocs + extractor in /usr/local/bin), docker save, scan:
**layer_scanner = CLEAN, 0 HIGH** — confirming static's blind spot (extractor is
in a normal path, carrier is a valid asset). Combined with the earlier results
this makes the crossover a measured 2-point result:
- structural (whiteout): static DETECT (add-then-hide), dynamic n/a
- content-embedded (appended): static MISS (measured clean), dynamic DETECT (17:1)
Paper: replaced the interpolated crossover line with a measured grouped-bar figure
(static/dynamic/union × 2 carriers), rewrote the crossover text and caption as
"measured, not interpolated." Recompiles clean (4pp). Every figure cell now maps
to an actual scan or trace.

---

## 2026-08-12 — Dynamic eBPF detector fired LIVE (Phase 3 result captured)

Ran `hunt.bt` live and captured the real trace. No sudo in this env, so ran the
sensor inside a **privileged container** (`quay.io/iovisor/bpftrace`, `--pid=host`,
tracefs + BTF mounted) observing host syscalls, and detonated the control ladder
on the host. Trace saved at `results/trace_live.out`.

Measured (exactly as designed):
- B0 (normal execve): no event — correctly silent (no memfd).
- B1 (fileless-plain): read=1904B wrote=1072B -> **ratio 1:1** -> `FILELESS-EXEC`.
- C  (stego extractor): read=18497B wrote=1072B -> **ratio 17:1** -> `STEGO-EXTRACTION`.

B1's 1904B = 1072B payload + ~832B loader header read()s; ratio still rounds to
1:1, so libc startup noise did not break the discriminator. Threshold=4 cleanly
separates B1 from C. This is the paper's core dynamic result, now real not
illustrative. Paper updated: fig:ratio C=17, dynamic subsection rewritten as
live-measured, limitations softened (live firing demonstrated; large-scale FP
eval still future work). Recompiles clean.

Method note for repro: privileged bpftrace container is the workaround when the
agent lacks root; detonation runs as normal user on host and the global
tracepoints still see it.

---

## 2026-08-12 — Generalization matrix: static detector across 6 base images (`generalize/`)

Ran the static track across databases + language runtimes on mixed distros to
test that detection isn't httpd-specific (Phase 4 generalization). For each base,
built clean/plain/stego variants (stego via the 2-step `COPY`+`RUN rm` Dockerfile
= reproducible whiteout carrier on any image), `docker save`d, and scanned with
`layer_scanner.py`. Driver: `generalize/run_matrix.sh`; table: `summarize.py` →
`results/matrix.md`; raw per-image logs kept for the appendix.

**Result — clean across the board:**
- Detection: **12/12** malicious variants flagged (plain=1 HIGH planted-exec;
  stego=2 HIGH planted-exec + add-then-hide) on postgres, redis, mariadb, python,
  node, golang.
- False positives: **0/6** clean base images flagged. The `/var/log` location
  rule and entropy threshold do NOT trip on real debian/ubuntu/alpine/slim bases.

The 0/6 false-positive rate on real bases is a genuinely useful precision result
for the paper — strengthens the static section beyond the single-carrier httpd demo.
Note: gotcha found — initial inline table matched the word "HIGH" in the summary
line "0 HIGH finding(s)"; authoritative parse is the numeric count (fixed in both
`summarize.py` and `run_matrix.sh`). TODO: fold this matrix into the paper as a
generalization table.

---

## 2026-08-11 (pm) — First paper draft written (`paper/`)

Full first-draft preprint in `paper/main.tex` (ACM acmart sigconf, self-contained
TikZ/pgfplots figures, compiles to ~4 pages). Sections per Phase 5 plan incl.
dual-use note. Three figures: whiteout-smuggling diagram, read:write ratio bar
chart (B0/B1/C), and the coverage-crossover (static strong on structural carriers,
dynamic strong on content-embedded, union high across). Resolved the framing
tension honestly: crossover x-axis is *carrier type* (whiteout -> appended-data),
not "static vs stego" — our layer_scanner catches the whiteout carrier, so the
complementarity is between the two carrier families we actually built.
TODO before submit: real author/affiliation; replace illustrative crossover
end-points with measured eBPF numbers; expand bib.

---

## 2026-08-11 (pm) — Phase 3 dynamic layer prototyped (`dynamic/`)

### What we did
Built the runtime-extraction detection track: an in-rootfs stego carrier, a
fileless extractor, a control ladder, and an eBPF detector. All under `dynamic/`.

### Design
- **Carrier:** payload embedded as trailing data after a valid PNG (appended-data
  stego); the image still renders. `build_carrier.py` (stdlib-only, synthesizes a
  noisy cover PNG so carrier >> payload).
- **Payload:** tiny freestanding x86-64 ELF (`payload.c`, ~1KB, no libc), drops
  `/tmp/stego_marker`. ELF not shell script — shebang scripts can't be fileless-
  exec'd from a memfd via `execveat` (kernel ENOENT). Identical bytes in all variants.
- **Behavioral chain:** `openat(asset) → read(whole) → decode → memfd_create →
  write → execveat(AT_EMPTY_PATH)` (fileless).
- **Detector (`hunt.bt`):** filename-agnostic. Keys on memfd→execveat (fileless)
  plus the **read:write byte ratio** — a stego extractor reads a big carrier but
  executes a small decoded region.

### Control ladder (identical payload bytes)
| Variant | mechanism | read:write | verdict |
|---------|-----------|:----------:|---------|
| B0 plain | normal `execve` | – | not flagged |
| B1 fileless-plain | memfd+execveat, no decode | ~1:1 | `FILELESS-EXEC` |
| C stego | read carrier + decode + memfd+execveat | ~16:1 | `STEGO-EXTRACTION` |

B1 is the load-bearing control: same fileless mechanism as C, no carrier. The
read:write ratio is what separates "generic fileless exec" (Falco/Tetragon catch
this) from "stego extraction" (novel). That separation is the result.

### Verified
- All three chains run on host; fileless exec works; marker drops.
- Ratios measured: C = 17665:1072 (~16:1), B1 = ~1:1. Clean separation around the
  threshold (RATIO_ALERT=4).
- `carrier.png` remains a valid PNG (1080 trailing bytes past IEND).

### NOT yet done / caveats
- `hunt.bt` is written and hand-reviewed but **not run under root here** (no sudo
  in this env). Must validate the live trace on the box and capture output.
- Ratio is a per-PID byte-sum proxy, not data-flow taint (stated as future work).
- Container path (`Dockerfile.b0/b1/c`) written but images not built here (needs
  `httpd:2.4` base + docker daemon).

### Next
- [ ] Run `sudo bpftrace hunt.bt`, detonate B0/B1/C, capture the trace table.
- [ ] Fold the B1-vs-C separation into the crossover figure (static catches C at
      rest via layer_scanner; dynamic catches C's extraction — both halves shown).

---

## 2026-08-11 — Built and validated the layer-aware detector

### What we did
- Reviewed the existing baseline `static_scanner.py` and characterized its
  limits (see findings below).
- Wrote `layer_scanner.py`, a layer-aware detector, and validated it against the
  full corpus.
- Wrote repository documentation for future work.

### Findings on the baseline (`static_scanner.py`)
- **Signature-only:** matches payloads by hardcoded filename (`payload.sh`,
  `stego_marker`). Renaming the payload defeats it — and in fact it now misses
  `plain.tar` because the plain payload is named `systemd-journal-cache.sh`.
- **Entropy is decorative:** computed and printed but never used in a decision.
- **Whiteout-blind by design:** it *sees* the `.wh.` marker but classifies it as
  a normal deletion — this is the blind spot the research exists to expose.
- **Docker-archive only:** cannot parse OCI layout (`stego_oci/`).

### What `layer_scanner.py` does differently
1. **Entropy as a real threshold** (`ENTROPY_HIGH = 7.2` bits/byte) → flags
   packed/encrypted executables.
2. **Add-then-hide correlation:** walks layers in order, tracks every added
   executable, and when a whiteout hides a path that was an executable in a
   lower layer → **HIGH**. This is the core detection the baseline lacked.
3. **Location heuristic:** an executable planted in a data dir (`/var/log`,
   `/tmp`, `/var/tmp`, `/dev/shm`, …) → **HIGH**, regardless of filename. This
   catches the plain case *without* a signature.
4. **Both formats:** docker-archive (`manifest.json`) and OCI layout
   (`index.json`, dir or tar).
5. **CLI args + CI gating:** exits non-zero on any HIGH finding.

### Results
| Image | `static_scanner.py` | `layer_scanner.py` |
|-------|--------------------|--------------------|
| clean | clean | clean |
| plain | **CLEAN (missed — name mismatch)** | **HIGH** (planted in `/var/log`) |
| stego | CLEAN (whiteout ignored) | **HIGH** (location + add-then-hide) |
| stego_oci | (cannot parse) | **HIGH** (same as stego) |

Confirmed `stego.tar` and `stego_oci/` are the same payload (identical layer
digests `70207dd8741d` add / `732f5136a202` whiteout), so the detector gives the
same verdict across both packaging formats.

### Decisions
- **Keep `static_scanner.py` unchanged** as the baseline/strawman — its blindness
  is the control, not a bug to fix.
- **Adopt `layer_scanner.py` as the working detector** going forward.
- **Default no-arg run scans only the three tars** (OCI parsing stays in the code
  but is not exercised by default). Rationale: current experiment scope is the
  tar corpus; OCI path retained for later registry/production-scope work.

---

## Open gaps / caveats (things NOT yet solved)

- **Heuristics are corpus-tuned.** The `/var/log`-style location list and the 7.2
  entropy cutoff will need an allowlist before running against real base images,
  or they will throw false positives.
- **No content inspection.** A malicious payload placed where executables are
  normal (e.g. `/usr/local/bin`) with normal entropy and no whiteout would slip
  past. Closing this needs YARA rules / shell-script indicators.
- **Single-manifest selection.** For OCI, the scanner analyzes the final tag; a
  payload present only in an intermediate build tag is not yet cross-checked.
- **No recovery step.** We detect the hidden payload but have not scripted its
  extraction from the lower blob (proving recoverability).

---

## Candidate next steps

- [ ] Add a content-signature pass (YARA / script heuristics) to catch payloads
      in "legitimate" executable locations.
- [ ] Add an allowlist mechanism to suppress known-good executables/dirs.
- [ ] Script payload **recovery** from the lower blob to demonstrate the file is
      truly still present after the whiteout.
- [ ] Format round-trip test: `skopeo copy oci:stego_oci docker-archive:rt.tar`
      then scan, confirming the verdict survives conversion.
- [ ] Compare against external baselines already in the toolchain (Falco,
      Tetragon) for runtime vs. static detection contrast.
- [ ] `--json` output mode for reproducible result capture in the writeup.
