# Static detection

Inspecting an image **at rest**, per layer, without running it.

## `static/layer_scanner.py` — the detector

Consumes an image (docker-archive tarball *or* OCI layout, directory or tar) and
iterates each layer archive **in application order** (lowest first), keeping a map
of every file introduced with metadata: executable bit, size, byte entropy. It
reports findings at three severities and exits non-zero on any `HIGH` so it can
gate CI.

```
python3 static/layer_scanner.py IMAGE [IMAGE ...]
# no args -> scans samples/{clean,plain,stego}.tar
```

### Signals

- **Add-then-hide (HIGH).** On a whiteout for path `p`, check whether `p` was
  previously added as an *executable* in a lower layer. If so, that is the
  structural fingerprint of whiteout smuggling — an executable present in the
  physical image but absent from the merged rootfs. This is the signal the naive
  baseline throws away.
- **Planted executable (HIGH).** An executable introduced into a data-only
  directory (`/var/log`, `/tmp`, `/var/tmp`, `/dev/shm`, …; see
  `SUSPICIOUS_EXEC_DIRS`) is flagged regardless of its name — catching plain
  delivery without a signature.
- **High-entropy executable (MEDIUM).** Executable whose byte entropy ≥ `7.2`
  bits/byte — possibly packed/encrypted.
- **Whiteouts without a matching executable add (LOW).** Ordinary deletions;
  reported but not alarming. Opaque directory whiteouts are LOW.

### Design notes

- Entropy is a real decision input (threshold `ENTROPY_HIGH`), not decoration.
  Files are only read for entropy if executable or ≤ 4096 B, and never above
  `ENTROPY_MAX_READ` (8 MiB), to avoid slurping large base layers.
- Format handling: `tarfile` `mode='r'` transparently decompresses the gzip'd
  (`tar+gzip`) OCI layers as well as uncompressed docker layers. OCI layouts are
  resolved via `index.json` → chosen manifest → ordered layer blobs.
- Layers are read fully into memory one at a time; fine for typical images, but
  see Limitations for very large layers.

### Heuristic caveats

The location list and entropy threshold are tuned to the corpus. On the six real
base images tested they produced **zero** false positives (see
[generalization.md](generalization.md)), but a large-scale deployment would still
want an allowlist to bound the false-positive rate. The scanner also does not
inspect file *content*: a payload placed where executables are normal, with
ordinary entropy and no whiteout, would pass — that is exactly the gap the
[dynamic layer](dynamic-detection.md) closes.

## `static/baseline_scanner.py` — the naive control

Deliberately weak, representing common rootfs/signature scanners. It is:

- **Signature-only** — matches payloads by hardcoded filename (`payload.sh`,
  `stego_marker`). Rename the payload and it is blind.
- **Whiteout-blind by design** — it *sees* `.wh.` markers and prints them but
  classifies them as normal cache/package deletions.
- **docker-archive only** — cannot parse OCI layouts.

It exists so the layer-aware detector has a baseline to beat. Do not "fix" its
blindness — that blindness is the experimental control.

## Expected verdicts (single carrier / whiteout)

| Image | `baseline_scanner.py` | `layer_scanner.py` |
|-------|-----------------------|--------------------|
| clean | clean | clean |
| plain | miss (name mismatch) | HIGH (planted exec) |
| stego (whiteout) | miss (whiteout ignored) | HIGH (add-then-hide) |
| stego (content-embedded) | miss | miss — **needs the dynamic layer** |
