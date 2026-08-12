#!/usr/bin/env bash
# Build clean/plain/stego variants across a spread of base images and scan each
# with the static detector. See docs/generalization.md.
set -uo pipefail

ROOT=$(cd "$(dirname "$0")/../.." && pwd)
GEN="$ROOT/experiments/generalize"
SCANNER="$ROOT/static/layer_scanner.py"
OUT="$ROOT/results/generalize"
SCRATCH="${TMPDIR:-/tmp}/genmatrix"
mkdir -p "$SCRATCH" "$OUT"
cp "$ROOT/dynamic/payload" "$GEN/payload"

ROWS=(
  "postgres:latest|database|debian"
  "redis:alpine|database|alpine"
  "mariadb:latest|database|ubuntu"
  "python:3.12-slim|language runtime|debian-slim"
  "node:20-alpine|language runtime|alpine"
  "golang:1.22-alpine|language runtime|alpine"
)

verdict() {
  local out n
  out=$(python3 "$SCANNER" "$1" 2>&1)
  echo "$out" > "$2"
  n=$(echo "$out" | sed -nE 's/.*Done\.\s+([0-9]+)\s+HIGH.*/\1/p')
  if [ "${n:-0}" -gt 0 ] 2>/dev/null; then echo "$n HIGH"; else echo "clean"; fi
}

for row in "${ROWS[@]}"; do
  IFS='|' read -r base role distro <<< "$row"
  echo "=== $base ($role, $distro) ==="
  safe=$(echo "$base" | tr '/:.' '___')
  docker pull "$base" >/dev/null 2>&1 || { echo "  [skip] pull failed"; continue; }
  docker build -q -f "$GEN/docker/Dockerfile.plain" --build-arg BASE="$base" -t "exp_plain:$safe" "$GEN" >/dev/null 2>&1 || { echo "  [skip] plain build failed"; continue; }
  docker build -q -f "$GEN/docker/Dockerfile.stego" --build-arg BASE="$base" -t "exp_stego:$safe" "$GEN" >/dev/null 2>&1 || { echo "  [skip] stego build failed"; continue; }

  docker save "$base"           -o "$SCRATCH/clean.tar"
  docker save "exp_plain:$safe" -o "$SCRATCH/plain.tar"
  docker save "exp_stego:$safe" -o "$SCRATCH/stego.tar"

  vc=$(verdict "$SCRATCH/clean.tar" "$OUT/${safe}_clean.txt")
  vp=$(verdict "$SCRATCH/plain.tar" "$OUT/${safe}_plain.txt")
  vs=$(verdict "$SCRATCH/stego.tar" "$OUT/${safe}_stego.txt")
  echo "  clean=$vc  plain=$vp  stego=$vs"

  rm -f "$SCRATCH"/*.tar
  docker rmi "exp_plain:$safe" "exp_stego:$safe" >/dev/null 2>&1
done

rm -f "$GEN/payload"
python3 "$GEN/summarize.py"
echo "ALL DONE"
