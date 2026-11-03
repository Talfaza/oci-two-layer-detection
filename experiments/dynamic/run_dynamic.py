#!/usr/bin/env python3
"""Dynamic read:write-ratio sweep for the runtime extraction detector.

Detonates the parameterized probe across read strategy, carrier/read size, and
payload/write size, for two scenario classes:

  stego  : a real extraction -- reads a cover of size R, execs a payload of size
           W (R > W, since a cover must exceed what it hides). Ratio R/W.
  benign : a canonical fileless loader -- reads (a prefix of) the ELF it execs
           from offset 0 of a file (R <= W). Ratio <= 1.
  embedded: a loader that execs an ELF carried in its own memory, reading only
           unrelated data. Not stego, but indistinguishable from a decode by
           the provenance signal -- reported separately as a known FP class.

Stego runs cross the payload encoding: `xor` (decoded before exec) and `raw`
(stored verbatim in the carrier).

For each run it records rchar/wchar (kernel counters, i.e. exactly what hunt.bt
sums) and derives what hunt.bt *as written* would observe: it hooks only
sys_exit_read, so pread() and mmap() reads are invisible to it. `hunt_read` is
therefore rchar for read/chunk and ~0 for pread/mmap -- the syscall-coverage
evasion, measured. `mmap_ratio` adds the carrier bytes the probe mmap'd.

--live additionally runs dynamic/hunt.bt in a privileged bpftrace container
during the sweep and joins each run to the detector's own read/wrote by pid
(`live_*` columns): the ground truth, including loader noise the /proc/self/io
baseline subtraction hides. analyze_dynamic.py turns this into ROC + evasion
tables. See docs/dynamic-detection.md.
"""
import csv
import os
import re
import shutil
import struct
import subprocess
import sys
import tempfile
import time

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.abspath(os.path.join(HERE, "..", ".."))
OUT = os.path.join(ROOT, "results", "dynamic")
PROBE = os.path.join(HERE, "probe")
PAYLOAD = open(os.path.join(ROOT, "dynamic", "payload"), "rb").read()
PLEN = len(PAYLOAD)

MAGIC = b"STGO"
KEY = 0x5A
STRATEGIES = ["read", "chunk", "pread", "mmap", "tail", "mmaptail", "exact"]
ENCODINGS = {"xor": KEY, "raw": 0}
WRITE_SIZES = [PLEN, 16384, 65536]   # payload/memfd-write bytes (W)
MAX_CARRIER = 32 << 20
STEGO_MULT = [2, 4, 8, 32, 128, 1024]  # cover:payload ratios R = W*m
BENIGN_FRAC = [0.25, 0.5, 1.0]       # loader reads R = W*f (<= its image)
IOSTAT = re.compile(r"IOSTAT rchar=(\d+) wchar=(\d+) mapped=(\d+)")
ALERT = re.compile(r"\] (\S+)\s+pid=(\d+) .*read=(-?\d+)B wrote=(\d+)B "
                   r"ratio=\d+:1 sourced=(\d+)")
BPF_IMAGE = "quay.io/iovisor/bpftrace:latest"
CONTAINER = "hunt-sweep"

FIELDS = ["scenario", "encoding", "strategy", "read_size", "write_size", "rchar", "wchar",
          "mapped", "ratio", "hunt_read", "hunt_ratio", "mmap_ratio",
          "hunt_flags", "ideal_flags", "pid", "live_read", "live_wrote",
          "live_ratio", "live_flags", "live_sourced", "live_verdict"]


def build_probe():
    # regenerate the embedded payload blob from the freestanding ELF, then build
    hdr = os.path.join(HERE, "payload_blob.h")
    with open(hdr, "w") as f:
        f.write("/* generated from dynamic/payload by run_dynamic.py */\n")
        f.write(f"static const unsigned int PAYLOAD_LEN = {PLEN};\n")
        f.write("static const unsigned char PAYLOAD[] = {\n")
        for i in range(0, PLEN, 12):
            f.write("  " + ",".join(str(b) for b in PAYLOAD[i:i + 12]) + ",\n")
        f.write("};\n")
    subprocess.run(["cc", "-O2", "-o", PROBE, os.path.join(HERE, "probe.c")],
                   check=True, cwd=HERE)


def make_stego_carrier(path, total, wbytes, key=KEY):
    payload = (PAYLOAD + b"\x00" * max(0, wbytes - PLEN))[:wbytes]
    blob = MAGIC + struct.pack("<I", wbytes) + bytes(b ^ key for b in payload)
    filler = b"\x00" * max(0, total - len(blob))
    with open(path, "wb") as f:
        f.write(filler + blob)


def make_benign_data(path, total, image=True):
    head = PAYLOAD if image else b""
    with open(path, "wb") as f:
        f.write((head + b"\x00" * total)[:total])


def run(mode, strategy, carrier, pad):
    args = [PROBE, mode, strategy, carrier]
    if mode == "plain":
        args.append(str(pad))
    p = subprocess.Popen(args, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    _, err = p.communicate()
    m = IOSTAT.search(err.decode(errors="replace"))
    if not m:
        return None
    return p.pid, int(m.group(1)), int(m.group(2)), int(m.group(3))


def start_sensor(outdir):
    subprocess.run(["docker", "rm", "-f", CONTAINER], capture_output=True)
    trace = os.path.join(outdir, "trace.out")
    subprocess.run([
        "docker", "run", "-d", "--name", CONTAINER, "--privileged", "--pid=host",
        "-v", "/sys/kernel/debug:/sys/kernel/debug",
        "-v", "/sys/kernel/btf:/sys/kernel/btf:ro",
        "-v", f"{os.path.join(ROOT, 'dynamic')}:/src:ro", "-v", f"{outdir}:/out",
        "--entrypoint", "bpftrace", BPF_IMAGE, "-o", "/out/trace.out",
        "/src/hunt.bt"], check=True, capture_output=True)
    for _ in range(120):
        if os.path.exists(trace) and "Attaching" in open(trace).read():
            return trace
        time.sleep(0.5)
    sys.exit("hunt.bt did not attach; see `docker logs %s`" % CONTAINER)


def stop_sensor(trace):
    time.sleep(1)
    subprocess.run(["docker", "stop", CONTAINER], capture_output=True)
    subprocess.run(["docker", "rm", CONTAINER], capture_output=True)
    alerts = {}
    for line in open(trace):
        m = ALERT.search(line)
        if m:
            alerts[int(m.group(2))] = (int(m.group(3)), int(m.group(4)),
                                       int(m.group(5)), m.group(1))
    return alerts


def main():
    os.makedirs(OUT, exist_ok=True)
    build_probe()
    live = "--live" in sys.argv
    scratch = tempfile.mkdtemp(prefix="dyn_")
    trace = start_sensor(scratch) if live else None
    rows = []

    def emit(scenario, enc, strategy, R, W, pid, rchar, wchar, mapped):
        ratio = rchar / wchar if wchar else 0
        hunt_read = rchar if strategy in ("read", "chunk") else 0
        hunt_ratio = hunt_read / wchar if wchar else 0
        mmap_ratio = (rchar + mapped) / wchar if wchar else 0
        rows.append({
            "scenario": scenario, "encoding": enc, "strategy": strategy, "read_size": R,
            "write_size": W, "rchar": rchar, "wchar": wchar, "mapped": mapped,
            "ratio": round(ratio, 2), "hunt_read": hunt_read,
            "hunt_ratio": round(hunt_ratio, 2),
            "mmap_ratio": round(mmap_ratio, 2),
            "hunt_flags": int(hunt_ratio >= 4), "ideal_flags": int(ratio >= 4),
            "pid": pid})

    for W in WRITE_SIZES:
        for m in STEGO_MULT:
            R = W * m
            if R > MAX_CARRIER:
                continue
            for enc, key in ENCODINGS.items():
                car = os.path.join(scratch, f"s_{R}_{W}.bin")
                make_stego_carrier(car, R, W, key)
                mode = "stego" if key else "stegoraw"
                for s in STRATEGIES:
                    res = run(mode, s, car, 0)
                    if res:
                        emit("stego", enc, s, R, W, *res)
                os.remove(car)
        for f in BENIGN_FRAC:
            R = int(W * f)
            for scen, image in (("benign", True), ("embedded", False)):
                dat = os.path.join(scratch, f"b_{R}_{W}.bin")
                make_benign_data(dat, R, image)
                for s in STRATEGIES:
                    res = run("plain", s, dat, W - PLEN)
                    if res:
                        emit(scen, "-", s, R, W, *res)
                os.remove(dat)

    if live:
        alerts = stop_sensor(trace)
        shutil.copy(trace, os.path.join(OUT, "live_sweep.out"))
        for r in rows:
            a = alerts.get(r["pid"])
            if a:
                lr = a[0] / a[1] if a[1] else 0
                r.update(live_read=a[0], live_wrote=a[1],
                         live_ratio=round(lr, 2), live_flags=int(lr >= 4),
                         live_sourced=a[2], live_verdict=a[3])
        print(f"[=] live: {sum('live_read' in r for r in rows)}/{len(rows)} "
              f"runs matched a hunt.bt alert")

    path = os.path.join(OUT, "ratio.csv")
    with open(path, "w", newline="") as fh:
        w = csv.DictWriter(fh, fieldnames=FIELDS)
        w.writeheader()
        w.writerows(rows)
    print(f"[=] {len(rows)} runs -> {path}")


if __name__ == "__main__":
    main()
