#!/usr/bin/env python3
"""Docker-free steganographic carrier injector for OCI/Docker archives.

Builds stego variants by appending gzip layer blobs to a base `docker save`
tarball and extending its manifest `Layers` list. No Docker, no daemon: a base
tar goes in, a stego tar comes out, fully deterministic from the parameters.
The static scanner resolves layers straight from `manifest.json`, so these
tarballs are faithful detector inputs. See docs/corpus-evaluation.md.

Two carrier families (mirrors the paper):
  - whiteout  : payload added (exec, in a data dir) in a low layer, then
                whited-out in a higher layer -> gone from the merged rootfs,
                present in the lower blob. The static layer's target.
  - appended  : payload hidden past a PNG's IEND in a benign asset -> nothing
                anomalous at rest. Static is expected to MISS it (that is the
                point: it grounds the crossover and feeds the dynamic eval).
"""
import gzip
import hashlib
import io
import json
import os
import struct
import tarfile
import zlib

MAGIC = b"STGO"
XOR_KEY = 0x5A


# --------------------------------------------------------------------------
# payloads
# --------------------------------------------------------------------------
def gen_payload(size, entropy):
    """Return `size` bytes at the requested entropy class.

    high -> os.urandom (~8.0 bits/byte, models encrypted/packed/xored)
    low  -> repeated ascii text (~4.3 bits/byte, models a plaintext script/blob)
    """
    if entropy == "high":
        return os.urandom(size)
    line = b"#!/bin/sh\necho staging payload; :; do_work() { return 0; }\n"
    reps = (size // len(line)) + 1
    return (line * reps)[:size]


# --------------------------------------------------------------------------
# appended-PNG carrier (content-embedded family)
# --------------------------------------------------------------------------
def _make_png(width, height, seed=0xC0FFEE):
    import random
    rng = random.Random(seed)

    def chunk(tag, data):
        c = tag + data
        return struct.pack(">I", len(data)) + c + struct.pack(">I", zlib.crc32(c) & 0xFFFFFFFF)

    sig = b"\x89PNG\r\n\x1a\n"
    ihdr = struct.pack(">IIBBBBB", width, height, 8, 0, 0, 0, 0)
    raw = bytearray()
    for _y in range(height):
        raw.append(0)
        raw.extend(rng.getrandbits(8) for _ in range(width))
    idat = zlib.compress(bytes(raw), 6)
    return sig + chunk(b"IHDR", ihdr) + chunk(b"IDAT", idat) + chunk(b"IEND", b"")


def build_carrier_png(payload, cover_dim=128):
    cover = _make_png(cover_dim, cover_dim)
    enc = bytes(b ^ XOR_KEY for b in payload)
    return cover + MAGIC + struct.pack("<I", len(enc)) + enc


# --------------------------------------------------------------------------
# layer blob construction
# --------------------------------------------------------------------------
def _tar_member(tf, name, data, mode):
    ti = tarfile.TarInfo(name=name)
    ti.size = len(data)
    ti.mode = mode
    tf.addfile(ti, io.BytesIO(data))


def make_layer_blob(files):
    """files: list of (name, data, mode). Return (blob_path, gzip_bytes, diff_id)."""
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w") as tf:
        for name, data, mode in files:
            _tar_member(tf, name, data, mode)
    plain = buf.getvalue()
    diff_id = hashlib.sha256(plain).hexdigest()
    gz = gzip.compress(plain, compresslevel=6, mtime=0)
    digest = hashlib.sha256(gz).hexdigest()
    return f"blobs/sha256/{digest}", gz, diff_id


def make_whiteout_blob(datadir, name, opaque):
    marker = ".wh..wh..opq" if opaque else ".wh." + name
    wpath = f"{datadir}/{marker}" if not opaque else f"{datadir}/.wh..wh..opq"
    return make_layer_blob([(wpath, b"", 0o644)])


# --------------------------------------------------------------------------
# tar assembly: base members + new blobs, with an extended manifest
# --------------------------------------------------------------------------
def _write_variant(base_tar, out_tar, new_blobs, append_layer_paths):
    """Stream base members (rewriting manifest.json) then append new blobs."""
    with tarfile.open(base_tar, "r") as src:
        manifest = json.loads(src.extractfile("manifest.json").read())
        manifest[0]["Layers"] = list(manifest[0]["Layers"]) + list(append_layer_paths)
        new_manifest = json.dumps(manifest).encode()

        with tarfile.open(out_tar, "w") as dst:
            for m in src.getmembers():
                if m.name == "manifest.json":
                    _tar_member(dst, "manifest.json", new_manifest, 0o644)
                elif m.isfile():
                    dst.addfile(m, src.extractfile(m))
                else:
                    dst.addfile(m)
            for path, data in new_blobs:
                _tar_member(dst, path, data, 0o644)


def build_whiteout_variant(base_tar, out_tar, *, datadir="var/log",
                           name="update.bin", payload=b"", entropy="high",
                           opaque=False, depth=1):
    """Add an exec payload in `datadir`, then white it out `depth` layers later."""
    add_path, add_blob, _ = make_layer_blob([(f"{datadir}/{name}", payload, 0o755)])
    blobs = [(add_path, add_blob)]
    layer_paths = [add_path]

    for i in range(depth - 1):
        noop = f"var/lib/.stage{i}"
        p, b, _ = make_layer_blob([(noop, os.urandom(64), 0o644)])
        blobs.append((p, b))
        layer_paths.append(p)

    wpath, wblob, _ = make_whiteout_blob(datadir, name, opaque)
    blobs.append((wpath, wblob))
    layer_paths.append(wpath)

    _write_variant(base_tar, out_tar, blobs, layer_paths)


def build_appended_variant(base_tar, out_tar, *, assetdir="usr/share/nginx/html",
                           name="banner.png", payload=b""):
    """Add a benign PNG with the payload appended past IEND (non-exec asset)."""
    carrier = build_carrier_png(payload)
    p, b, _ = make_layer_blob([(f"{assetdir}/{name}", carrier, 0o644)])
    _write_variant(base_tar, out_tar, [(p, b)], [p])
