#!/usr/bin/env bash
# One-shot, resumable driver for the whole corpus evaluation:
#   stego factorial (positives) -> clean corpus (FPR) -> aggregate report.
# Both harnesses skip anything already in results/corpus/*.csv, so this is safe
# to stop (Ctrl-C / kill) and re-run; it picks up where it left off.
# Runs unattended in the background:  nohup bash experiments/corpus/run_all.sh &
# Progress:  tail -f results/corpus/run.log   (or watch results/corpus/*.csv)
set -uo pipefail

ROOT=$(cd "$(dirname "$0")/../.." && pwd)
cd "$ROOT"
LOG="$ROOT/results/corpus/run.log"
mkdir -p "$ROOT/results/corpus"

echo "=== [$(date '+%F %T')] stego factorial (bases.txt) ===" | tee -a "$LOG"
python3 experiments/corpus/gen_stego.py 2>&1 | grep -E '^===|variants scanned|skip|\[=\]' | tee -a "$LOG"

echo "=== [$(date '+%F %T')] clean corpus (images.txt) ===" | tee -a "$LOG"
python3 experiments/corpus/run_clean.py 2>&1 | grep -E '^\[[0-9]+\]|FALSE POSITIVE|skip|\[=\]' | tee -a "$LOG"

echo "=== [$(date '+%F %T')] aggregate ===" | tee -a "$LOG"
python3 experiments/corpus/analyze.py > /dev/null 2>&1
sv=$(( $(grep -c . results/corpus/stego_verdicts.csv) - 1 ))
cv=$(( $(grep -c . results/corpus/clean_verdicts.csv) - 1 ))
echo "=== [$(date '+%F %T')] DONE  stego=$sv  clean=$cv  -> results/corpus/report.md ===" | tee -a "$LOG"
