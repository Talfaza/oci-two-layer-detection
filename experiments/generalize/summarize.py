#!/usr/bin/env python3
"""Regenerate matrix.md from the raw per-image scanner logs in results/generalize.

See docs/generalization.md.
"""
import re
import os

RESULTS = os.path.join(os.path.dirname(__file__), "..", "..", "results", "generalize")

META = [
    ("postgres_latest",   "postgres:latest",   "database",         "debian"),
    ("redis_alpine",      "redis:alpine",       "database",         "alpine"),
    ("mariadb_latest",    "mariadb:latest",     "database",         "ubuntu"),
    ("python_3_12-slim",  "python:3.12-slim",   "language runtime", "debian-slim"),
    ("node_20-alpine",    "node:20-alpine",     "language runtime", "alpine"),
    ("golang_1_22-alpine","golang:1.22-alpine", "language runtime", "alpine"),
]

FIND_KIND = {
    "planted executable": "planted-exec",
    "add-then-hide": "add-then-hide",
    "high-entropy": "high-entropy",
}


def parse(safe, variant):
    path = os.path.join(RESULTS, f"{safe}_{variant}.txt")
    if not os.path.exists(path):
        return None, []
    txt = open(path).read()
    m = re.search(r"Done\.\s+(\d+)\s+HIGH", txt)
    n = int(m.group(1)) if m else 0
    kinds = []
    for line in re.findall(r"\[!\] HIGH:\s+([a-z][a-z -]*?)[:\s]", txt):
        for key, short in FIND_KIND.items():
            if line.startswith(key.split()[0]) and short not in kinds:
                kinds.append(short)
    return n, kinds


def cell(safe, variant):
    n, kinds = parse(safe, variant)
    if n is None:
        return "n/a"
    if n == 0:
        return "clean ✓"
    tag = ", ".join(kinds) if kinds else "HIGH"
    return f"**{n} HIGH** ({tag})"


def main():
    out = ["# Generalization matrix — static `layer_scanner.py` across base images",
           "",
           "Clean = false-positive check (want *clean*). Plain/Stego = true-positive "
           "(want *HIGH*). Stego additionally exercises the whiteout add-then-hide path.",
           "",
           "| Base image | Role | Distro | Clean | Plain | Stego |",
           "|---|---|---|---|---|---|"]
    tp = fp = total_mal = total_clean = 0
    for safe, disp, role, distro in META:
        c = cell(safe, "clean")
        p = cell(safe, "plain")
        s = cell(safe, "stego")
        out.append(f"| `{disp}` | {role} | {distro} | {c} | {p} | {s} |")
        cn, _ = parse(safe, "clean"); pn, _ = parse(safe, "plain"); sn, _ = parse(safe, "stego")
        total_clean += 1
        if cn == 0: pass
        else: fp += 1
        for mv in (pn, sn):
            total_mal += 1
            if mv and mv > 0: tp += 1
    out += ["",
            f"**Detection:** {tp}/{total_mal} malicious variants flagged "
            f"(plain+stego across all bases). "
            f"**False positives:** {fp}/{total_clean} clean bases flagged.",
            ""]
    open(os.path.join(RESULTS, "matrix.md"), "w").write("\n".join(out))
    print("\n".join(out))


if __name__ == "__main__":
    main()
