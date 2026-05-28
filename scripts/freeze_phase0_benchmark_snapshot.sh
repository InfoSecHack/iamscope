#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"
source .venv/bin/activate

RUNS_DIR=""
CORPUS_DIR=""
SNAPSHOT_ID=""
OUT_ROOT="benchmarks/snapshots"

while [[ $# -gt 0 ]]; do
  case "$1" in
    --runs-dir)
      RUNS_DIR="$2"
      shift 2
      ;;
    --corpus-dir)
      CORPUS_DIR="$2"
      shift 2
      ;;
    --snapshot-id)
      SNAPSHOT_ID="$2"
      shift 2
      ;;
    --out-root)
      OUT_ROOT="$2"
      shift 2
      ;;
    *)
      echo "unknown argument: $1" >&2
      exit 2
      ;;
  esac
done

if [[ -z "$RUNS_DIR" || -z "$CORPUS_DIR" || -z "$SNAPSHOT_ID" ]]; then
  echo "--runs-dir, --corpus-dir, and --snapshot-id are required" >&2
  exit 2
fi
if [[ ! -d "$RUNS_DIR" ]]; then
  echo "runs dir not found: $RUNS_DIR" >&2
  exit 1
fi
if [[ ! -d "$CORPUS_DIR" ]]; then
  echo "corpus dir not found: $CORPUS_DIR" >&2
  exit 1
fi

SNAPSHOT_DIR="${OUT_ROOT}/${SNAPSHOT_ID}"
RUNS_OUT="${SNAPSHOT_DIR}/runs"
CORPUS_OUT="${SNAPSHOT_DIR}/corpus"
mkdir -p "$RUNS_OUT" "$CORPUS_OUT"

required_corpus_files=(corpus_summary.json promotion_decision.json corpus_report.md)
for filename in "${required_corpus_files[@]}"; do
  if [[ ! -f "$CORPUS_DIR/$filename" ]]; then
    echo "missing required corpus file: $CORPUS_DIR/$filename" >&2
    exit 1
  fi
done

copied_run_count=0
included_lines=()
while IFS= read -r -d '' run_dir; do
  run_basename="$(basename "$run_dir")"
  run_out_dir="${RUNS_OUT}/${run_basename}"
  mkdir -p "$run_out_dir"

  for filename in run_manifest.json scorer_result.json gate_result.json; do
    if [[ ! -f "$run_dir/$filename" ]]; then
      echo "missing required run file: $run_dir/$filename" >&2
      exit 1
    fi
    cp "$run_dir/$filename" "$run_out_dir/$filename"
  done
  if [[ -f "$run_dir/report.md" ]]; then
    cp "$run_dir/report.md" "$run_out_dir/report.md"
  else
    echo "warning: missing optional report.md for run dir $run_dir" >&2
  fi

  case_id="$(python - <<'PY' "$run_dir/run_manifest.json"
import json, sys
from pathlib import Path
payload = json.loads(Path(sys.argv[1]).read_text())
print(payload["case_id"])
PY
)"
  run_id="$(python - <<'PY' "$run_dir/run_manifest.json"
import json, sys
from pathlib import Path
payload = json.loads(Path(sys.argv[1]).read_text())
print(payload["run_id"])
PY
)"
  included_lines+=("${case_id} / ${run_id} -> runs/${run_basename}")
  copied_run_count=$((copied_run_count + 1))
done < <(find "$RUNS_DIR" -mindepth 1 -maxdepth 1 -type d -print0)

if [[ "$copied_run_count" -eq 0 ]]; then
  echo "no run directories found under $RUNS_DIR" >&2
  exit 1
fi

for filename in "${required_corpus_files[@]}"; do
  cp "$CORPUS_DIR/$filename" "$CORPUS_OUT/$filename"
done

if find "$SNAPSHOT_DIR" \( -name '.terraform' -o -name 'terraform.tfstate' -o -name 'terraform.tfstate.backup' -o -name 'providers' -o -path '*/.terraform/*' -o -path '*/providers/*' \) | grep -q .; then
  echo "forbidden terraform/provider artifact detected in snapshot output" >&2
  exit 1
fi

created_at="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
readme_path="${SNAPSHOT_DIR}/README.md"
python - <<'PY' "$CORPUS_OUT/corpus_summary.json" "$CORPUS_OUT/promotion_decision.json" "$readme_path" "$SNAPSHOT_ID" "$created_at" "$RUNS_DIR" "$CORPUS_DIR" "${included_lines[@]}"
import json
import sys
from pathlib import Path

corpus_summary = json.loads(Path(sys.argv[1]).read_text())
promotion_decision = json.loads(Path(sys.argv[2]).read_text())
readme_path = Path(sys.argv[3])
snapshot_id = sys.argv[4]
created_at = sys.argv[5]
source_runs_dir = sys.argv[6]
source_corpus_dir = sys.argv[7]
included_items = sys.argv[8:]
lines = [
    f"# Phase 0 Benchmark Snapshot: {snapshot_id}",
    "",
    f"- snapshot_id: `{snapshot_id}`",
    f"- created_at: `{created_at}`",
    f"- source runs dir: `{source_runs_dir}`",
    f"- source corpus dir: `{source_corpus_dir}`",
    f"- corpus decision: `{promotion_decision['decision']}`",
    "",
    "## Included Cases / Runs",
]
lines.extend([f"- {item}" for item in included_items] or ["- None"])
lines.extend([
    "",
    "## Directly Proven",
])
lines.extend([f"- {item}" for item in corpus_summary["evidence_boundaries"].get("directly_proven", [])] or ["- None"])
lines.extend([
    "",
    "## Only Implied",
])
lines.extend([f"- {item}" for item in corpus_summary["evidence_boundaries"].get("only_implied", [])] or ["- None"])
lines.extend([
    "",
    "## Still Unknown",
])
lines.extend([f"- {item}" for item in corpus_summary["evidence_boundaries"].get("still_unknown", [])] or ["- None"])
readme_path.write_text("\n".join(lines) + "\n")
PY

echo "snapshot_path=$(realpath "$SNAPSHOT_DIR")"
echo "snapshot_readme=$(realpath "$SNAPSHOT_DIR/README.md")"
echo "snapshot_runs=$(realpath "$RUNS_OUT")"
echo "snapshot_corpus=$(realpath "$CORPUS_OUT")"