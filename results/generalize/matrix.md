# Generalization matrix — static `layer_scanner.py` across base images

Clean = false-positive check (want *clean*). Plain/Stego = true-positive (want *HIGH*). Stego additionally exercises the whiteout add-then-hide path.

| Base image | Role | Distro | Clean | Plain | Stego |
|---|---|---|---|---|---|
| `postgres:latest` | database | debian | clean ✓ | **1 HIGH** (planted-exec) | **2 HIGH** (planted-exec, add-then-hide) |
| `redis:alpine` | database | alpine | clean ✓ | **1 HIGH** (planted-exec) | **2 HIGH** (planted-exec, add-then-hide) |
| `mariadb:latest` | database | ubuntu | clean ✓ | **1 HIGH** (planted-exec) | **2 HIGH** (planted-exec, add-then-hide) |
| `python:3.12-slim` | language runtime | debian-slim | clean ✓ | **1 HIGH** (planted-exec) | **2 HIGH** (planted-exec, add-then-hide) |
| `node:20-alpine` | language runtime | alpine | clean ✓ | **1 HIGH** (planted-exec) | **2 HIGH** (planted-exec, add-then-hide) |
| `golang:1.22-alpine` | language runtime | alpine | clean ✓ | **1 HIGH** (planted-exec) | **2 HIGH** (planted-exec, add-then-hide) |

**Detection:** 12/12 malicious variants flagged (plain+stego across all bases). **False positives:** 0/6 clean bases flagged.
