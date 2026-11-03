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

### What counts as "read"

The read side is every byte a process pulls from a file, by any primitive:

- **Read family:** `read`, `pread64`, `readv`, `preadv` (bytes = return value).
- **File-backed `mmap`:** a non-anonymous mapping adds its `len`. A carrier read
  via `mmap` issues no read syscall, so without this it is invisible.

Two exclusions keep the dynamic loader from inflating every process's count
(a glibc binary otherwise picks up ~2.4 KB of ELF-header reads, the 2 MB libc
mapping, and the 112 KB `/etc/ld.so.cache` mapping before `main`):

- **Code descriptors.** When a descriptor gets a `PROT_EXEC` mapping, every
  byte already attributed to it (reads + mappings) is subtracted, and later
  reads/mappings of it are ignored. Shared libraries always get an exec
  mapping; carriers do not. This is content-agnostic and also covers `dlopen`.
- **`/etc/ld.so.cache`**, by path: it is mapped read-only, never exec.

Bytes are tracked per `(pid, fd)` and dropped on `close`. With both exclusions
the live benign noise floor is ~190 B (stdio + `/proc` reads), down from ~2.4 KB.

## Second signal: provenance of the exec'd ELF

The ratio needs the extractor to read the whole cover. A trailer carrier lets it
read only the tail (see the evasion audit), so `hunt.bt` also asks: **was the ELF
being executed ever read verbatim from the start of a file?**

- On the first `write` into the memfd, if it begins with `\x7fELF`, fingerprint
  its 64-byte ELF header (weighted sum of the 8 words).
- On every `read`/`pread64` that returns ≥ 64 bytes starting with `\x7fELF` **at
  file offset 0**, record the same fingerprint as "sourced". Offset is the
  `pread` argument, or for `read` a per-fd position tracked from read/readv
  returns and `lseek`. File mappings at offset 0 are fingerprinted at `munmap`
  (or when written to the memfd straight from the mapping).
- Fingerprints from code descriptors (`PROT_EXEC`-mapped) are dropped, so
  library headers never count.

At `execveat`: ratio ≥ 4 → `STEGO-EXTRACTION`; else an ELF whose header was never
sourced → `STEGO-DECODE`; else `FILELESS-EXEC`.

A benign fileless loader reads the ELF it runs from offset 0 of a file, so the
fingerprints match (B1: `sourced=1`). An extractor either **decodes** (XOR'd
header never appears in a read buffer) or **carves** a verbatim payload out of the
middle of a carrier (header appears, but at a non-zero offset or mid-buffer).
Neither depends on how much was read, so tail reads do not help.

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

## Evasion audit (`experiments/dynamic/`)

We red-teamed the detector against our own extractors. `run_dynamic.py`
detonates a parameterized `probe.c` over read strategy × cover:payload ratio
(2–1024) × payload size (1 KB / 16 KB / 64 KB), plus benign fileless loaders
that read ≤ their own image. With `--live` it runs `hunt.bt` itself in the
privileged container during the sweep and joins every alert to its run by pid,
so the numbers are the real detector's, loader noise included.
`analyze_dynamic.py` → [`../results/dynamic/report.md`](../results/dynamic/report.md).

Strategies: `read`, `chunk` (4 KB read loop), `pread`, `mmap` (whole carrier),
and two **tail** extractors that touch only the trailing payload region —
`tail` (`pread` 4 KB pages backwards from EOF until the magic) and `mmaptail`
(same, one mapped page at a time).

### Round 1 — syscall coverage

The first `hunt.bt` summed only `sys_exit_read`; `pread` and `mmap` carrier reads
were invisible. Live traces: [`hunt_evasion_before.out`](../results/dynamic/hunt_evasion_before.out)
(pread/mmap → `FILELESS-EXEC 0:1`), [`hunt_evasion_after.out`](../results/dynamic/hunt_evasion_after.out)
(pread hook added; mmap still 2:1).

### Round 2 — mmap accounting + loader exclusion

Adding the `pread` hook also started counting `ld.so`'s ELF-header `pread64`s,
lifting benign B1 from 1:1 to **3:1** — one step from the threshold. The
per-descriptor accounting above fixes both: `mmap` carriers are counted and
loader bytes are not. Live, 156 runs ([`live_sweep.out`](../results/dynamic/live_sweep.out)):

| Strategy | original | +pread | current (live) |
|---|---|---|---|
| read / chunk | 82% | 82% | 82% |
| pread | 0% | 82% | 82% |
| mmap | 0% | 0% | 82% |
| tail / mmaptail | 0% | 0% | 18–29% |
| **all stego** | 27% | 41% | **63%** |
| benign FPR | — | — | **0%** (max ratio 1.18) |

Every whole-cover miss is a 2:1 cover, below the threshold; at threshold 2
whole-cover recall is 100% with 0% FPR, but the margin over the benign maximum
(1.18) is thin, so the default stays 4.

### Tail reads defeat the ratio (closed by provenance)

An extractor that seeks to the appended payload never reads the cover, so
read ≈ write whatever the syscall coverage. Live: 0% caught at 16 KB and 64 KB
payloads (max ratio 1.26). The tail catches at 1 KB are a page-granularity
artifact (one 4 KB page / 1 KB payload ≈ 4), not detection. This is a limit of the
**signal**, not of the hooks: for trailer carriers (appended PNG) the ratio only
works against extractors that load the whole asset. Formats where decoding needs
the whole cover (LSB in pixel data) keep the ratio meaningful.

### Round 3 — ratio + provenance

Sweep widened to 364 live runs: 7 strategies (adds `exact`, which locates the
payload then `pread`s exactly its bytes, so the header *is* read verbatim, but
at a non-zero offset) × payload encoding (`xor`, `raw`) × size × cover ratio,
plus two benign classes. Live trace: [`live_sweep.out`](../results/dynamic/live_sweep.out).

| | ratio only | ratio + provenance |
|---|---|---|
| stego, whole-cover (read/chunk/pread/mmap) | 82% | **100%** |
| stego, tail / mmaptail / exact | 18–29% | **100%** |
| **all stego (238)** | 58% | **100%** |
| benign file loader (63) | 0% | **0%** |
| embedded-payload loader (63) | 0% | 100% (known FP class) |

The **embedded-payload loader** execs an ELF carried in its own memory, reading
only unrelated data. It has no file provenance and is indistinguishable from a
decode by construction. Legitimate instances (self-unpacking binaries,
in-memory runtimes) need a per-binary allowlist; in containers it is rare, and
fileless exec of an embedded ELF is itself what Falco/Tetragon alert on.

## Limitations

- The ratio is a per-process **byte sum**, a provenance proxy, not data-flow
  taint. It proves "a fileless exec preceded by disproportionately large reads,"
  not "these exact bytes came from that file." Cross-process laundering (read in
  one process, exec in another) would require lineage tracking.
- **Tail-reading extractors evade the ratio**; the provenance signal catches
  them. Its own gaps:
  - **Header mimicry.** Only the 64-byte ELF header is fingerprinted. A payload
    crafted to share its header with an on-disk binary (whose header the
    extractor then reads from offset 0) would be "sourced". Fingerprinting the
    program headers or the first page raises the bar.
  - **Write-path coverage.** Only `write` into the memfd is inspected, and only
    its first call (≥ 64 B). A tiny first write, `pwrite`/`writev`, or `mmap`ing
    the memfd skips the fingerprint (the last two also zero `wrote`, which
    makes the ratio fire instead).
  - **`readv`/`preadv`** buffers are counted but not fingerprinted; a benign
    loader that reads its ELF with `readv` would look unsourced.
  - **Embedded-payload loaders** are flagged by design (see Round 3).
- **`mmap` counts mapped length, not touched pages.** An extractor that maps
  only the payload's pages is the `mmaptail` case. Mapping the carrier
  `PROT_EXEC` would launder it through the code-descriptor exclusion; an exec
  mapping of a non-ELF file is itself anomalous but is not yet flagged.
- **Threshold sensitivity.** At the default threshold of 4, shallow covers
  (cover:payload 2) fall under the bar; benign fileless loaders (live max
  1.18) never trip it (FPR 0% for any threshold ≥ 2). See the ROC.
- To scope events to one container, add a cgroup filter in `hunt.bt` (compare
  `cgroup` against the container's `docker-<id>.scope` inode).
