#!/usr/bin/env python3
"""Appended-data steganography carrier builder.

Embeds a payload as trailing bytes after a valid PNG (past IEND); the image still
renders. Layout: [PNG][ "STGO" | len(LE,4) | XOR(payload,0x5A) ].
See docs/dynamic-detection.md.
Usage: python3 build_carrier.py <payload> <out.png> [cover.png]
"""
import struct
import sys
import zlib

MAGIC = b"STGO"
KEY = 0x5A


def make_png(width=128, height=128):
    import random
    rng = random.Random(0xC0FFEE)

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


def embed(payload_path, out_path, cover_path=None):
    cover = open(cover_path, "rb").read() if cover_path else make_png()
    payload = open(payload_path, "rb").read()
    enc = bytes(b ^ KEY for b in payload)
    blob = MAGIC + struct.pack("<I", len(enc)) + enc
    with open(out_path, "wb") as fh:
        fh.write(cover + blob)
    print(f"[+] {out_path}: {len(cover)}B cover PNG + {len(blob)}B hidden "
          f"(payload {len(payload)}B). Read/exec ratio ~= {len(cover)+len(blob)}:{len(payload)}")


if __name__ == "__main__":
    if len(sys.argv) < 3:
        print(__doc__)
        sys.exit(1)
    embed(sys.argv[1], sys.argv[2], sys.argv[3] if len(sys.argv) > 3 else None)
