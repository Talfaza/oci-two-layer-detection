# Generalization

Tests that static detection is not specific to one base image, by repeating the
clean/plain/stego construction across databases and language runtimes on mixed
distributions.

## How it works (`experiments/generalize/`)

`run_matrix.sh` iterates a list of base images and, for each:

1. pulls the base,
2. builds a **plain** variant (`docker/Dockerfile.plain`: `COPY` the payload into
   `/var/log/`) and a **stego** variant (`docker/Dockerfile.stego`: `COPY` then
   `RUN rm`),
3. `docker save`s clean/plain/stego to tarballs,
4. scans each with `static/layer_scanner.py`,
5. writes raw per-image logs to `results/generalize/` and cleans up.

`summarize.py` parses those logs (the authoritative `Done. N HIGH finding(s).`
count) into `results/generalize/matrix.md`.

### The reproducible stego trick

The stego variant is built with a two-step Dockerfile:

```dockerfile
COPY payload /var/log/systemd-journal-cache.sh   # layer A: file present (executable)
RUN  rm      /var/log/systemd-journal-cache.sh   # layer B: whiteout; file persists in layer A blob
```

Docker naturally emits the `.wh.` whiteout in the upper layer while the file
remains in the lower layer's blob — the exact whiteout carrier, buildable on any
base image without special tooling.

## Result

Six base images (2 databases, 3 language runtimes; debian / ubuntu / alpine /
slim):

- **Detection: 12/12** malicious variants flagged — plain via planted-executable,
  stego additionally via add-then-hide.
- **False positives: 0/6** clean base images flagged.

Detection transfers across base images, and the location/entropy heuristics did
not misfire on real database and runtime images. The 0/6 result is a small but
meaningful precision signal; a larger image population would be needed to put a
firm number on the false-positive rate.

## Re-running

```
bash experiments/generalize/run_matrix.sh     # needs Docker + network
# regenerate just the table from existing logs:
python3 experiments/generalize/summarize.py
```
