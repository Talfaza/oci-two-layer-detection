# Dynamic detection

Catching the **extraction step** of a content-embedded payload at runtime with
eBPF, keyed on behavior — never on filenames. This is the project's novel
contribution: it sees what the static layer cannot, because the payload is a valid
asset at rest and only becomes a program when it runs.

## The behavioral chain

```
openat(asset) -> read(whole asset) -> [decode] -> memfd_create -> write -> execveat(AT_EMPTY_PATH)
```

A process opens a benign asset, reads it, decodes the hidden region, writes the
result into an anonymous in-memory file (`memfd`), and executes it directly with
`execveat` — filelessly, leaving no on-disk artifact.

## The discriminator: read : write byte ratio

Fileless execution alone is a generic technique that runtime tools (Falco,
Tetragon) already flag. To identify *steganographic* behaviour specifically, note
that an extractor **reads much more than it executes**: it consumes a whole
carrier asset but runs only the small decoded region.

`hunt.bt` tracks, per process, bytes read vs. bytes written into the executed
`memfd`:

- ratio ≈ **1:1** → plain fileless execution (no carrier).
- ratio **≫ 1** (threshold `RATIO_ALERT = 4`) → extraction from a carrier.

## Control ladder (identical payload bytes)

| Variant | Source read | Decode | Fileless exec | read:write | Verdict |
|---------|-------------|:------:|:-------------:|:----------:|---------|
| **B0** | — | — | — (normal `execve`) | — | not flagged |
| **B1** | payload file | — | ✅ | ~1:1 | `FILELESS-EXEC` |
| **C**  | carrier asset | ✅ | ✅ | ~16–17:1 | `STEGO-EXTRACTION` |

**B1 is the load-bearing control.** It uses the exact same fileless mechanism as C
but with no carrier/decode. If the detector fired identically on B1 and C it would
only be catching generic fileless exec. The read:write ratio is what separates
them, and that separation is the result.

## Components (`dynamic/`)

| File | Role |
|------|------|
| `payload.c` | benign freestanding x86-64 ELF (~1 KB, no libc); drops `/tmp/stego_marker`; identical bytes in every variant |
| `build_carrier.py` | embeds the payload as trailing data after a valid PNG (stdlib-only; synthesizes a noisy cover so carrier ≫ payload) |
| `extractor.c` | **variant C**: read carrier → XOR-decode → `memfd_create` → `execveat` |
| `fileless_plain.c` | **variant B1**: read payload → `memfd_create` → `execveat` (no carrier/decode) |
| `hunt.bt` | the eBPF/`bpftrace` detector |
| `Makefile` | builds binaries + carrier; `make host-test` runs the C chain without eBPF/Docker |
| `docker/Dockerfile.{b0-plain,b1-fileless,c-stego}` | the three container variants (build context = `dynamic/`) |

### Why a freestanding ELF, not a shell script

A shebang script cannot be fileless-exec'd from a memfd via `execveat` (the kernel
returns `ENOENT`, because `binfmt_script` has no path to hand the interpreter). An
ELF works, and is also the more realistic dropper for this attack class. The
payload is kept tiny with `-nostdlib -static -Wl,--nmagic,--build-id=none` so it
stays ~1 KB (≪ carrier), keeping the ratio unambiguous.

## Running it

### Host-only smoke test (no eBPF)

```
cd dynamic && make all && make host-test   # asserts /tmp/stego_marker is dropped
```

### Live detection with eBPF

`bpftrace` needs root. If you have it:

```
cd dynamic && make all
sudo bpftrace hunt.bt          # terminal 1
./fileless_plain payload       # terminal 2 -> FILELESS-EXEC ~1:1
./extractor carrier.png        #            -> STEGO-EXTRACTION ~16:1
```

### Without root: privileged container

When you lack `sudo` but can use Docker, run the sensor in a privileged container
that shares the host kernel and PID namespace, and detonate on the host:

```
docker run -d --name ebpf --privileged --pid=host \
  -v /sys/kernel/debug:/sys/kernel/debug \
  -v /sys/kernel/btf:/sys/kernel/btf:ro \
  -v "$PWD":/work --entrypoint bpftrace \
  quay.io/iovisor/bpftrace:latest -o /work/trace.out /work/hunt.bt
# then, on the host: ./fileless_plain payload ; ./extractor carrier.png
docker stop ebpf && cat trace.out
```

The global tracepoints see the host processes regardless of the container
boundary. A captured trace is in [`../results/trace_live.out`](../results/trace_live.out).

## Measured result

```
[~] FILELESS-EXEC     comm=fileless_plain  read=1904B   wrote=1072B  ratio=1:1
[!] STEGO-EXTRACTION  comm=extractor       read=18497B  wrote=1072B  ratio=17:1
```

B1's 1904 B = 1072 B payload + ~832 B loader header reads; it still rounds to 1:1,
so libc startup noise does not break the discriminator.

## Limitations

- The ratio is a per-process **byte sum**, a provenance proxy, not data-flow
  taint. It proves "a fileless exec preceded by disproportionately large reads,"
  not "these exact bytes came from that file." Cross-process laundering (read in
  one process, exec in another) would require lineage tracking.
- To scope events to one container, add a cgroup filter in `hunt.bt` (compare
  `cgroup` against the container's `docker-<id>.scope` inode).
