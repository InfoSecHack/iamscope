#!/usr/bin/env bash
set -Eeuo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
ENV_DIR="$PROJECT_ROOT/acceptance/env03_cc1_identity_deny"
EXPECTED_JSON="$ENV_DIR/expected_findings.json"
RUN_ID="${RUN_ID:-$(date -u +%Y%m%dT%H%M%SZ)}"
WORK_DIR="${IAMSCOPE_ENV03_WORKDIR:-/tmp/iamscope-env03-benchmark-$RUN_ID}"
ARTIFACT_DIR="${IAMSCOPE_BENCHMARK_OUT:-/tmp/iamscope-benchmark-env03-$RUN_ID}"
COLLECT_DIR="$ARTIFACT_DIR/collect"
RUN_LOG="$ARTIFACT_DIR/run.log"
VALIDATE_LOG="$ARTIFACT_DIR/scenario_validate.txt"
FINDINGS_JSON="$COLLECT_DIR/findings.json"

source "$PROJECT_ROOT/.venv/bin/activate"

mkdir -p "$WORK_DIR" "$ARTIFACT_DIR"
rm -rf "$WORK_DIR"
mkdir -p "$WORK_DIR"
cp -a "$ENV_DIR/." "$WORK_DIR/"
rm -rf "$WORK_DIR/.terraform"
rm -f "$WORK_DIR"/*.tfstate "$WORK_DIR"/*.tfstate.*
rm -rf "$COLLECT_DIR"
mkdir -p "$COLLECT_DIR"

set +e
PROJECT_ROOT_OVERRIDE="$PROJECT_ROOT" OUTPUT_DIR="$COLLECT_DIR" bash "$WORK_DIR/run.sh" 2>&1 | tee "$RUN_LOG"
pipe_status=("${PIPESTATUS[@]}")
raw_rc="${pipe_status[0]:-1}"
set -e

cmd_rc=1
if [[ "$raw_rc" =~ ^[0-9]+$ ]]; then
  cmd_rc="$raw_rc"
else
  echo "WARNING: non-numeric exit code from Env03 run: [$raw_rc]" | tee -a "$RUN_LOG" >&2
fi

if [[ -f "$EXPECTED_JSON" ]]; then
  cp "$EXPECTED_JSON" "$ARTIFACT_DIR/expected_findings.json"
fi

if [[ -f "$COLLECT_DIR/scenario.json" ]]; then
  if iamscope validate "$COLLECT_DIR/scenario.json" >"$VALIDATE_LOG" 2>&1; then
    echo "scenario validation: PASS" >>"$RUN_LOG"
  else
    echo "scenario validation: FAIL (see $VALIDATE_LOG)" >>"$RUN_LOG"
  fi
fi

benchmark_rc="$cmd_rc"
if [[ ! -f "$FINDINGS_JSON" ]]; then
  echo "benchmark semantic assertion: SKIP (missing $FINDINGS_JSON)" | tee -a "$RUN_LOG"
elif [[ ! -f "$EXPECTED_JSON" ]]; then
  echo "benchmark semantic assertion: FAIL (missing $EXPECTED_JSON)" | tee -a "$RUN_LOG"
  benchmark_rc=1
else
  target_pattern=$(jq -r '.benchmark_contract.target_pattern_id' "$EXPECTED_JSON")
  expected_blocked=$(jq -r '.benchmark_contract.expected_counts.blocked' "$EXPECTED_JSON")
  expected_validated=$(jq -r '.benchmark_contract.expected_counts.validated' "$EXPECTED_JSON")
  blocker_kind=$(jq -r '.benchmark_contract.required_blocker.kind' "$EXPECTED_JSON")
  blocker_min=$(jq -r '.benchmark_contract.required_blocker.min_count' "$EXPECTED_JSON")
  required_check_name=$(jq -r '.benchmark_contract.required_check.name' "$EXPECTED_JSON")
  required_check_state=$(jq -r '.benchmark_contract.required_check.state' "$EXPECTED_JSON")
  required_check_count=$(jq -r '.benchmark_contract.required_check.count' "$EXPECTED_JSON")

  blocked_count=$(jq --arg pat "$target_pattern" '[.findings[] | select(.pattern_id == $pat and .verdict == "blocked")] | length' "$FINDINGS_JSON")
  validated_count=$(jq --arg pat "$target_pattern" '[.findings[] | select(.pattern_id == $pat and .verdict == "validated")] | length' "$FINDINGS_JSON")
  blocker_count=$(jq     --arg pat "$target_pattern"     --arg kind "$blocker_kind"     '[.findings[] | select(.pattern_id == $pat and .verdict == "blocked")
      | .blockers_observed[]? | select(
          .kind == $kind
          and (.constraint_id | type == "string")
          and (.edge_id | type == "string")
      )] | length'     "$FINDINGS_JSON")
  check_fail_count=$(jq     --arg pat "$target_pattern"     --arg check_name "$required_check_name"     --arg check_state "$required_check_state"     '[.findings[] | select(.pattern_id == $pat and .verdict == "blocked")
      | .required_checks[]? | select(
          .name == $check_name
          and .state == $check_state
      )] | length'     "$FINDINGS_JSON")

  echo "semantic assertion counts: ${target_pattern}.blocked=$blocked_count ${target_pattern}.validated=$validated_count ${blocker_kind}.blockers=$blocker_count ${required_check_name}.${required_check_state}=$check_fail_count" | tee -a "$RUN_LOG"

  if (( blocked_count == expected_blocked && validated_count == expected_validated && blocker_count >= blocker_min && check_fail_count == required_check_count )); then
    echo "benchmark semantic assertion: PASS" | tee -a "$RUN_LOG"
    benchmark_rc=0
  else
    echo "benchmark semantic assertion: FAIL" | tee -a "$RUN_LOG"
    benchmark_rc=1
  fi
fi

cat <<EOF
Env03 benchmark pass finished with command exit code: $cmd_rc
Env03 benchmark final result code: $benchmark_rc
Artifacts saved under: $ARTIFACT_DIR
- run log: $RUN_LOG
- expected findings: $ARTIFACT_DIR/expected_findings.json
- collect output: $COLLECT_DIR
EOF

exit "$benchmark_rc"
