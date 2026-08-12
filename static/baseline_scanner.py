#!/usr/bin/env python3
"""Naive signature/rootfs scanner — the deliberately weak baseline.

Intentionally signature-only and whiteout-blind; see docs/static-detection.md.
Usage: python3 static/baseline_scanner.py   (scans samples/{clean,plain,stego}.tar)
"""
import tarfile
import json
import os
import math
from collections import Counter

DEFAULT_TARGETS = ["samples/clean.tar", "samples/plain.tar", "samples/stego.tar"]


def calculate_entropy(data):
    if not data:
        return 0.0
    entropy = 0
    length = len(data)
    for count in Counter(data).values():
        p = count / length
        entropy -= p * math.log2(p)
    return entropy


def analyze_image(tar_path):
    print(f"\n{'=' * 40}\n[*] Analyzing Image: {tar_path}\n{'=' * 40}")
    whiteouts_found = []
    suspicious_files = []
    try:
        with tarfile.open(tar_path, 'r') as image_tar:
            manifest_file = image_tar.extractfile('manifest.json')
            if not manifest_file:
                print("[-] Error: No manifest.json found.")
                return
            layers = json.loads(manifest_file.read())[0]['Layers']
            for layer_path in layers:
                layer_file = image_tar.extractfile(layer_path)
                with tarfile.open(fileobj=layer_file, mode='r') as layer_tar:
                    for member in layer_tar.getmembers():
                        filename = os.path.basename(member.name)
                        if filename.startswith('.wh.'):
                            whiteouts_found.append((layer_path, member.name))
                        if member.isfile() and filename in ("payload.sh", "stego_marker"):
                            f = layer_tar.extractfile(member)
                            ent = calculate_entropy(f.read() if f else b"")
                            suspicious_files.append((layer_path, member.name, ent))
    except Exception as e:
        print(f"[-] Error parsing {tar_path}: {e}")
        return

    if suspicious_files:
        print("[!] DANGER: Suspicious payload detected statically!")
        for s in suspicious_files:
            print(f"    -> File: {s[1]} (Entropy: {s[2]:.2f}) in layer {s[0][:12]}")
    else:
        print("[+] CLEAN: No malicious payloads detected in visible layers.")

    if whiteouts_found:
        print(f"[*] NOTE: {len(whiteouts_found)} whiteout(s) detected.")
        for w in whiteouts_found[:3]:
            print(f"    -> Marker: {w[1]} in layer {w[0][:12]}")
        if len(whiteouts_found) > 3:
            print(f"    -> ... and {len(whiteouts_found) - 3} more.")
        print("    (Static scanners usually ignore these as normal cache/package deletions)")


if __name__ == "__main__":
    for img in DEFAULT_TARGETS:
        if os.path.exists(img):
            analyze_image(img)
        else:
            print(f"\n[-] {img} not found. Did you run 'docker save'?")
