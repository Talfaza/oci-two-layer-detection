# Overview

Detection of steganographic payload smuggling in OCI/Docker container images, and
the reason a single vantage point is not enough.

## The hiding surface

An OCI image is a stack of **layers**, each a tar archive of filesystem changes,
merged at runtime by a union filesystem (`overlayfs`). Two properties make images
good steganographic carriers:

1. **Whiteouts.** A layer marks a file from a lower layer as deleted with a
   `.wh.<name>` entry (or `.wh..wh..opq` for a whole directory). The file
   disappears from the merged rootfs, but its bytes remain physically present in
   the lower layer's blob. A scanner that inspects only the final rootfs sees
   nothing.
2. **Benign assets.** Images ship binary assets (images, fonts, sample data)
   whose spare capacity — trailing bytes, padding, metadata — can carry a payload
   without disturbing normal use.

## Two carrier families

- **Structural carrier (whiteout).** A real file added in a low layer and
  whited-out in a high layer. Invisible in the merged view, but leaves a
  structural trace across layers: an add followed by a delete of the same path.
- **Content-embedded carrier (appended data).** A payload hidden inside an asset
  that *remains present* in the rootfs (here, appended past a PNG's `IEND`). No
  whiteout, no misplaced file; at rest it is indistinguishable from a normal
  asset, and is decoded only at runtime.

## Why two detection layers

- **Static** analysis (inspect the image at rest) catches structural carriers but
  is blind to content-embedded ones.
- **Dynamic** analysis (observe the container at runtime with eBPF) catches the
  act of extracting a content-embedded payload, but only when it runs.

Neither alone is sufficient; together they cover each other's blind spots. This
is the project's central claim, demonstrated by measurement (see
[generalization.md](generalization.md)).

## Threat model

An adversary who can influence a distributed image (compromised build step,
malicious base image, insider) wants to ship a payload past image scanners and use
it at runtime. The defender can scan images before deployment and run a runtime
sensor. We do **not** assume container escape or host privileges: the
content-embedded payload is decoded by a normal in-container process from an asset
the image legitimately contains. Out of scope: covert network channels, DoS,
hardware side channels.

## Ethics

Detection-first, defensive research. The payload is a harmless marker
(`/tmp/stego_marker`); no malware is used. Embedding is described only as far as
needed to build and evaluate the detectors.

## Repository map

| Path | What |
|------|------|
| `static/` | static detectors: `layer_scanner.py` (ours), `baseline_scanner.py` (naive control) |
| `dynamic/` | runtime track: carrier builder, extractor, control binaries, `hunt.bt` eBPF detector |
| `experiments/generalize/` | multi-base-image generalization matrix |
| `samples/` | prebuilt image tarballs + OCI layout + original build inputs |
| `results/` | captured scanner logs and the live eBPF trace |
| `scripts/verify.sh` | environment/toolchain validator |
| `docs/` | this documentation |
