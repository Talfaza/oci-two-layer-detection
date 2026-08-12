#!/usr/bin/env python3
"""Layer-aware static detector for OCI/Docker image steganography.

See docs/static-detection.md for design and rationale.
Usage: python3 static/layer_scanner.py IMAGE [IMAGE ...]   (tar or OCI dir)
"""
import io
import json
import math
import os
import sys
import tarfile
from collections import Counter

ENTROPY_HIGH = 7.2
ENTROPY_MAX_READ = 8 << 20
WHITEOUT_PREFIX = ".wh."
OPAQUE_MARKER = ".wh..wh..opq"
SUSPICIOUS_EXEC_DIRS = (
    "var/log/", "tmp/", "var/tmp/", "dev/shm/", "run/", "var/run/",
    "var/cache/", "var/spool/", "var/lib/apt/", "proc/", "sys/",
)
DEFAULT_TARGETS = ["samples/clean.tar", "samples/plain.tar", "samples/stego.tar"]


def in_suspicious_dir(path):
    p = path.lstrip("./")
    return next((d for d in SUSPICIOUS_EXEC_DIRS if p.startswith(d)), None)


def calculate_entropy(data):
    if not data:
        return 0.0
    length = len(data)
    entropy = 0.0
    for count in Counter(data).values():
        p = count / length
        entropy -= p * math.log2(p)
    return entropy


def _open_layer_from_bytes(raw):
    return tarfile.open(fileobj=io.BytesIO(raw), mode="r")


def iter_layers_docker_archive(outer, manifest_bytes):
    manifest = json.loads(manifest_bytes)
    tags = manifest[0].get("RepoTags") or ["<none>"]
    layers = []
    for p in manifest[0]["Layers"]:
        raw = outer.extractfile(p).read()
        layers.append((p.split("/")[-1][:12], _open_layer_from_bytes(raw)))
    return tags, layers


def _resolve_oci(read_blob, index_bytes):
    manifests = json.loads(index_bytes)["manifests"]
    chosen = None
    for m in manifests:
        ref = m.get("annotations", {}).get("org.opencontainers.image.ref.name", "")
        if ref in ("stego", "latest"):
            chosen = m
    chosen = chosen or manifests[-1]
    ref = chosen.get("annotations", {}).get("org.opencontainers.image.ref.name", "<none>")
    manifest = json.loads(read_blob(chosen["digest"]))
    layers = []
    for lyr in manifest["layers"]:
        raw = read_blob(lyr["digest"])
        layers.append((lyr["digest"].split(":")[-1][:12], _open_layer_from_bytes(raw)))
    return [ref], layers


def load_image(path):
    if os.path.isdir(path):
        with open(os.path.join(path, "index.json"), "rb") as fh:
            index_bytes = fh.read()

        def read_blob(digest):
            algo, hexd = digest.split(":")
            with open(os.path.join(path, "blobs", algo, hexd), "rb") as fh:
                return fh.read()

        return _resolve_oci(read_blob, index_bytes)

    outer = tarfile.open(path, mode="r")
    names = set(outer.getnames())
    if "manifest.json" in names:
        return iter_layers_docker_archive(outer, outer.extractfile("manifest.json").read())
    if "index.json" in names:
        def read_blob(digest):
            algo, hexd = digest.split(":")
            return outer.extractfile(f"blobs/{algo}/{hexd}").read()

        return _resolve_oci(read_blob, outer.extractfile("index.json").read())
    raise ValueError("unrecognized image: no manifest.json or index.json")


def whiteout_target(member_name):
    d, base = os.path.split(member_name)
    if base == OPAQUE_MARKER:
        return (d, True)
    if base.startswith(WHITEOUT_PREFIX):
        real = base[len(WHITEOUT_PREFIX):]
        return (os.path.join(d, real) if d else real, False)
    return None


def analyze_image(path):
    print(f"\n{'=' * 44}\n[*] Analyzing: {path}\n{'=' * 44}")
    try:
        tags, layers = load_image(path)
    except Exception as e:
        print(f"[-] Could not load {path}: {e}")
        return []

    print(f"    tags: {', '.join(tags)}  |  layers: {len(layers)}")

    added = {}
    findings = []

    for layer_id, layer_tar in layers:
        for member in layer_tar.getmembers():
            wt = whiteout_target(member.name)

            if wt is not None:
                target, opaque = wt
                if opaque:
                    findings.append(("LOW",
                        f"opaque whiteout hides dir '{target}' (layer {layer_id})"))
                    continue
                prior = added.get(target)
                if prior and prior["exec"]:
                    findings.append(("HIGH",
                        f"add-then-hide: executable '{target}' added in layer "
                        f"{prior['layer']} (entropy {prior['entropy']:.2f}), then "
                        f"whited-out in layer {layer_id} — hidden from runtime "
                        f"but present in lower blob"))
                else:
                    findings.append(("LOW",
                        f"whiteout of '{target}' (layer {layer_id}) — no matching "
                        f"executable add; likely a normal deletion"))
                continue

            if not member.isfile():
                continue

            is_exec = bool(member.mode & 0o111)
            ent = 0.0
            if is_exec or member.size <= 4096:
                if member.size <= ENTROPY_MAX_READ:
                    fh = layer_tar.extractfile(member)
                    ent = calculate_entropy(fh.read()) if fh else 0.0
            added[member.name] = {"layer": layer_id, "exec": is_exec, "entropy": ent}

            if is_exec:
                bad_dir = in_suspicious_dir(member.name)
                if bad_dir:
                    findings.append(("HIGH",
                        f"planted executable '{member.name}' in data dir "
                        f"'{bad_dir}' (layer {layer_id}, entropy {ent:.2f}) — "
                        f"executables do not belong here"))
                if ent >= ENTROPY_HIGH:
                    findings.append(("MEDIUM",
                        f"high-entropy executable '{member.name}' (entropy "
                        f"{ent:.2f}, layer {layer_id}) — possibly packed/encrypted"))

    order = {"HIGH": 0, "MEDIUM": 1, "LOW": 2}
    findings.sort(key=lambda f: order[f[0]])
    if not findings:
        print("[+] CLEAN: no layer-level anomalies detected.")
    for sev, msg in findings:
        tag = {"HIGH": "[!]", "MEDIUM": "[~]", "LOW": "[.]"}[sev]
        print(f"    {tag} {sev}: {msg}")
    return findings


if __name__ == "__main__":
    targets = sys.argv[1:] or DEFAULT_TARGETS
    high = 0
    for t in targets:
        if not os.path.exists(t):
            print(f"\n[-] {t} not found.")
            continue
        high += sum(1 for sev, _ in analyze_image(t) if sev == "HIGH")
    print(f"\n{'=' * 44}")
    print(f"[=] Done. {high} HIGH finding(s).")
    sys.exit(1 if high else 0)
