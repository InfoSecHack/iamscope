#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"

source "$PROJECT_ROOT/.venv/bin/activate"

python -m benchmarks.reporting.render \
  --repo-root "$PROJECT_ROOT" \
  --case "$PROJECT_ROOT/benchmarks/cases/env03_identity_deny_group_escalation.json" \
  --run "$PROJECT_ROOT/benchmarks/samples/env03_live_sample_run.json" \
  --gates "$PROJECT_ROOT/benchmarks/scoring/promotion_gates_phase0.json" \
  --output "$PROJECT_ROOT/benchmarks/samples/env03_dry_run_report.md"
