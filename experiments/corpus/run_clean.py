#!/usr/bin/env python3
"""Clean-corpus harness: the false-positive-rate test (the negative class).

Pulls each real, unmodified image in images.txt, saves it, scans it with the
static detector, records the verdict, then deletes the tar and image so disk
stays flat. Any HIGH finding on an unmodified upstream image is a false
positive; the log lets analyze.py compute the FPR with a confidence interval
and enumerate exactly which images/paths tripped it (the basis for an
allowlist). See docs/corpus-evaluation.md.

Usage: python3 experiments/corpus/run_clean.py [--limit N]
"""
import argparse
import csv
import os
import subprocess
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.abspath(os.path.join(HERE, "..", ".."))
sys.path.insert(0, os.path.join(ROOT, "static"))
import layer_scanner as ls          # noqa: E402

OUT_CSV = os.path.join(ROOT, "results", "corpus", "clean_verdicts.csv")
IMAGES_FILE = os.path.join(HERE, "images.txt")
FIELDS = ["image", "category", "layers", "high_count", "kinds", "detail"]


def load_images():
    rows = []
    with open(IMAGES_FILE) as fh:
        for line in fh:
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            img, _, cat = line.partition("|")
            rows.append((img.strip(), (cat or "misc").strip()))
    return rows


def done_images(path):
    seen = set()
    if os.path.exists(path):
        with open(path, newline="") as fh:
            for r in csv.DictReader(fh):
                seen.add(r["image"])
    return seen


def scan(tar):
    findings = ls.analyze_image(tar)
    highs = [m for s, m in findings if s == "HIGH"]
    kinds = sorted({m.split(" ")[0] for m in highs})
    return len(highs), kinds, highs[:3]


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--limit", type=int, default=0)
    args = ap.parse_args()

    images = load_images()
    if args.limit:
        images = images[:args.limit]

    already = done_images(OUT_CSV)
    new_file = not os.path.exists(OUT_CSV)
    fh = open(OUT_CSV, "a", newline="")
    w = csv.DictWriter(fh, fieldnames=FIELDS)
    if new_file:
        w.writeheader()

    scratch = tempfile.mkdtemp(prefix="cleancorpus_")
    fp = n = 0
    for img, cat in images:
        if img in already:
            print(f"[skip] {img}")
            continue
        safe = img.replace("/", "_").replace(":", "_")
        tar = os.path.join(scratch, safe + ".tar")
        if subprocess.run(["docker", "pull", img],
                          stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL).returncode:
            print(f"[skip] {img} pull failed")
            continue
        if subprocess.run(["docker", "save", img, "-o", tar],
                          stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL).returncode:
            print(f"[skip] {img} save failed")
            continue

        try:
            tags, layers = ls.load_image(tar)
            nlayers = len(layers)
        except Exception:
            nlayers = -1
        hc, kinds, detail = scan(tar)
        w.writerow({"image": img, "category": cat, "layers": nlayers,
                    "high_count": hc, "kinds": ";".join(kinds),
                    "detail": " || ".join(detail)})
        fh.flush()
        n += 1
        flag = "  <-- FALSE POSITIVE" if hc else ""
        if hc:
            fp += 1
        print(f"[{n}] {img}: {hc} HIGH{flag}")
        os.remove(tar)
        subprocess.run(["docker", "rmi", img],
                       stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

    fh.close()
    print(f"\n[=] {n} images scanned, {fp} false positives -> {OUT_CSV}")


if __name__ == "__main__":
    main()
