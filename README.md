# Hidden Channels in the Cloud

Two-layer detection of steganography in OCI/Docker container images — from static
bytes at rest to runtime extraction with eBPF.

A payload can be smuggled through a container image so that it is invisible in the
runtime filesystem yet physically present in the image (whiteout carrier), or
hidden inside a benign asset that is decoded only when it runs (content-embedded
carrier). No single vantage point catches both. This repo builds a **static**
layer-aware scanner and a **dynamic** eBPF sensor, and shows they are
complementary.

> Defensive security research. The payload is a harmless marker; no malware is
> used. See [docs/overview.md](docs/overview.md#ethics).

## Layout

```
static/        layer_scanner.py (ours) + baseline_scanner.py (naive control)
dynamic/       carrier builder, extractor, control binaries, hunt.bt (eBPF), docker/
experiments/   generalize/ — multi-base-image detection matrix
samples/       prebuilt image tarballs + OCI layout + original build inputs
results/       captured scanner logs + live eBPF trace
scripts/       verify.sh — toolchain validator
docs/          documentation (start with overview.md)
```

## Quick start

```bash
# Static: scan the prebuilt clean/plain/stego images
python3 static/layer_scanner.py                      # catches plain + stego
python3 static/baseline_scanner.py                   # naive baseline misses them

# Dynamic: build the runtime chain and smoke-test it (no eBPF needed)
cd dynamic && make all && make host-test

# Dynamic: live eBPF detection (needs root; see docs)
sudo bpftrace dynamic/hunt.bt                         # then detonate the variants

# Generalization across databases + language runtimes (needs Docker)
bash experiments/generalize/run_matrix.sh
```

## Documentation

- [docs/overview.md](docs/overview.md) — threat model, carriers, why two layers
- [docs/static-detection.md](docs/static-detection.md) — the scanners and signals
- [docs/dynamic-detection.md](docs/dynamic-detection.md) — the eBPF extraction detector
- [docs/generalization.md](docs/generalization.md) — the multi-image matrix
- [docs/journal.md](docs/journal.md) — running research log

## Requirements

Linux (kernel ≥ 5.15 for the eBPF work), Docker, a C compiler, Python 3, and
`bpftrace`. Run `scripts/verify.sh` to check the toolchain.

## License

Licensed under the [Apache License 2.0](LICENSE). This is defensive security
research; the proof-of-concept carrier/extractor code uses a harmless marker
payload and is intended for authorized, lawful, defensive use only (see
[`NOTICE`](NOTICE)).
