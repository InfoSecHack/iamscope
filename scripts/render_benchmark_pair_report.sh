#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"
source .venv/bin/activate

SNAPSHOT_DIR="benchmarks/snapshots/phase0-20260509-env27"
JSON_OUT="benchmarks/pair-reports/phase0-20260509-env27-mutation-pairs.json"
MARKDOWN_OUT="benchmarks/pair-reports/phase0-20260509-env27-mutation-pairs.md"

while [[ $# -gt 0 ]]; do
  case "$1" in
    --snapshot-dir)
      SNAPSHOT_DIR="$2"
      shift 2
      ;;
    --json-out)
      JSON_OUT="$2"
      shift 2
      ;;
    --markdown-out)
      MARKDOWN_OUT="$2"
      shift 2
      ;;
    *)
      echo "unknown argument: $1" >&2
      exit 2
      ;;
  esac
done

python -m benchmarks.reporting.mutation_pairs \
  --snapshot-dir "$SNAPSHOT_DIR" \
  --json-out "$JSON_OUT" \
  --markdown-out "$MARKDOWN_OUT"

echo "pair_report_json=$(realpath "$JSON_OUT")"
echo "pair_report_markdown=$(realpath "$MARKDOWN_OUT")"
