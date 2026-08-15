#!/usr/bin/env python3
"""Factorial generator for the synthetic stego-image corpus (the positive class).

For every base image in bases.txt, pull it once and stream a full factorial of
stego variants across the construction axes below. Each variant is built,
scanned by the static detector, its verdict recorded, then deleted, so disk
stays flat regardless of corpus size. The persistent artifact is the row log
(results/corpus/stego_verdicts.csv), which is fully sufficient to reproduce and
audit every sample. See docs/corpus-evaluation.md.

Axes (edit here to grow/shrink the corpus):
  family        : whiteout (structural) | appended (content-embedded)
  payload_size  : bytes
  entropy       : low (plaintext) | high (encrypted/packed)
  whiteout_style: file (.wh.<name>) | opaque (.wh..wh..opq)   [whiteout only]
  depth         : layers between the add and the whiteout       [whiteout only]

Usage: python3 experiments/corpus/gen_stego.py [--limit N] [--keep]
"""
import argparse
import csv
import os
import subprocess
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.abspath(os.path.join(HERE, "..", ".."))
sys.path.insert(0, HERE)
sys.path.insert(0, os.path.join(ROOT, "static"))
import stegofactory as sf          # noqa: E402
import layer_scanner as ls          # noqa: E402

OUT_CSV = os.path.join(ROOT, "results", "corpus", "stego_verdicts.csv")
BASES_FILE = os.path.join(HERE, "bases.txt")

PAYLOAD_SIZES = [1_024, 100_000, 5_000_000]
ENTROPIES = ["low", "high"]
WHITEOUT_STYLES = [("file", False), ("opaque", True)]
DEPTHS = [1, 4]

FIELDS = ["sample_id", "base", "category", "family", "payload_size", "entropy",
          "whiteout_style", "depth", "high_count", "planted", "add_then_hide",
          "detected"]


def load_bases():
    rows = []
    with open(BASES_FILE) as fh:
        for line in fh:
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            img, _, cat = line.partition("|")
            rows.append((img.strip(), (cat or "misc").strip()))
    return rows


def verdict_row(tar):
    findings = ls.analyze_image(tar)
    highs = [m for s, m in findings if s == "HIGH"]
    planted = sum(1 for m in highs if m.startswith("planted"))
    ath = sum(1 for m in highs if m.startswith("add-then-hide"))
    return len(highs), planted, ath


def cells():
    """Yield (family, size, entropy, style_name, opaque, depth) for one base."""
    for size in PAYLOAD_SIZES:
        for ent in ENTROPIES:
            for sname, opq in WHITEOUT_STYLES:
                for d in DEPTHS:
                    yield ("whiteout", size, ent, sname, opq, d)
            yield ("appended", size, ent, "-", False, 0)


def done_bases(path):
    seen = set()
    if os.path.exists(path):
        with open(path, newline="") as fh:
            for r in csv.DictReader(fh):
                seen.add(r["base"])
    return seen


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--limit", type=int, default=0, help="only first N bases")
    ap.add_argument("--keep", action="store_true", help="keep variant tars")
    args = ap.parse_args()

    bases = load_bases()
    if args.limit:
        bases = bases[:args.limit]

    already = done_bases(OUT_CSV)
    new_file = not os.path.exists(OUT_CSV)
    fh = open(OUT_CSV, "a", newline="")
    w = csv.DictWriter(fh, fieldnames=FIELDS)
    if new_file:
        w.writeheader()

    scratch = tempfile.mkdtemp(prefix="stegogen_")
    total = 0
    for img, cat in bases:
        if img in already:
            print(f"[skip] {img} (already in log)")
            continue
        safe = img.replace("/", "_").replace(":", "_")
        base_tar = os.path.join(scratch, f"{safe}.base.tar")
        print(f"\n=== {img} ({cat}) ===")
        if subprocess.run(["docker", "pull", img],
                          stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL).returncode:
            print("  [skip] pull failed")
            continue
        if subprocess.run(["docker", "save", img, "-o", base_tar],
                          stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL).returncode:
            print("  [skip] save failed")
            continue

        n = 0
        for family, size, ent, sname, opq, depth in cells():
            payload = sf.gen_payload(size, ent)
            sid = f"{safe}__{family}_{size}_{ent}_{sname}_d{depth}"
            var = os.path.join(scratch, sid + ".tar")
            if family == "whiteout":
                sf.build_whiteout_variant(base_tar, var, payload=payload,
                                          entropy=ent, opaque=opq, depth=depth)
            else:
                sf.build_appended_variant(base_tar, var, payload=payload)

            hc, planted, ath = verdict_row(var)
            w.writerow({"sample_id": sid, "base": img, "category": cat,
                        "family": family, "payload_size": size, "entropy": ent,
                        "whiteout_style": sname, "depth": depth,
                        "high_count": hc, "planted": planted,
                        "add_then_hide": ath, "detected": int(hc > 0)})
            if not args.keep:
                os.remove(var)
            n += 1
            total += 1
        fh.flush()
        print(f"  {n} variants scanned")
        os.remove(base_tar)
        subprocess.run(["docker", "rmi", img],
                       stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

    fh.close()
    print(f"\n[=] {total} new stego variants -> {OUT_CSV}")


if __name__ == "__main__":
    main()
