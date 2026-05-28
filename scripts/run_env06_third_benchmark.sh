#!/usr/bin/env bash
set -Eeuo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
ENV_DIR="$PROJECT_ROOT/acceptance/env06_ar_validated_admin"
EXPECTED_JSON="$ENV_DIR/expected_findings.json"
RUN_ID="${RUN_ID:-$(date -u +%Y%m%dT%H%M%SZ)}"
WORK_DIR="${IAMSCOPE_ENV06_WORKDIR:-/tmp/iamscope-env06-benchmark-$RUN_ID}"
ARTIFACT_DIR="${IAMSCOPE_BENCHMARK_OUT:-/tmp/iamscope-benchmark-env06-$RUN_ID}"
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
  echo "WARNING: non-numeric exit code from Env06 run: [$raw_rc]" | tee -a "$RUN_LOG" >&2
fi

if [[ -f "$EXPECTED_JSON" ]]; then
  cp "$EXPECTED_JSON" "$ARTIFACT_DIR/expected_findings.json"
fi

scenario_validation_ok=0
if [[ -f "$COLLECT_DIR/scenario.json" ]]; then
  if iamscope validate "$COLLECT_DIR/scenario.json" >"$VALIDATE_LOG" 2>&1; then
    echo "scenario validation: PASS" >>"$RUN_LOG"
    scenario_validation_ok=1
  else
    echo "scenario validation: FAIL (see $VALIDATE_LOG)" >>"$RUN_LOG"
  fi
else
  echo "scenario validation: FAIL (missing $COLLECT_DIR/scenario.json)" >>"$RUN_LOG"
fi

benchmark_rc="$cmd_rc"
if [[ ! -f "$FINDINGS_JSON" ]]; then
  echo "benchmark semantic assertion: SKIP (missing $FINDINGS_JSON)" | tee -a "$RUN_LOG"
elif [[ ! -f "$EXPECTED_JSON" ]]; then
  echo "benchmark semantic assertion: FAIL (missing $EXPECTED_JSON)" | tee -a "$RUN_LOG"
  benchmark_rc=1
else
  source_arn=$(sed -n 's/^  alice_arn  : //p' "$RUN_LOG" | tail -1)
  target_arn=$(sed -n 's/^  admin_arn  : //p' "$RUN_LOG" | tail -1)
  if [[ -z "$source_arn" || -z "$target_arn" ]]; then
    echo "benchmark semantic assertion: FAIL (missing alice_arn/admin_arn in $RUN_LOG)" | tee -a "$RUN_LOG"
    benchmark_rc=1
  else
    target_pattern=$(jq -r '.benchmark_contract.target_pattern_id' "$EXPECTED_JSON")
    validated_min=$(jq -r '.benchmark_contract.expected_counts.validated_min' "$EXPECTED_JSON")
    expected_blocked=$(jq -r '.benchmark_contract.expected_counts.blocked' "$EXPECTED_JSON")
    expected_inconclusive=$(jq -r '.benchmark_contract.expected_counts.inconclusive' "$EXPECTED_JSON")
    expected_blockers=$(jq -r '.benchmark_contract.validated_findings.blockers_observed_total' "$EXPECTED_JSON")

    validated_count=$(jq       --arg pat "$target_pattern"       --arg src "$source_arn"       --arg tgt "$target_arn"       '[.findings[] | select(
          .pattern_id == $pat
          and .source.provider_id == $src
          and .target.provider_id == $tgt
          and .verdict == "validated"
      )] | length'       "$FINDINGS_JSON")
    blocked_count=$(jq       --arg pat "$target_pattern"       --arg src "$source_arn"       --arg tgt "$target_arn"       '[.findings[] | select(
          .pattern_id == $pat
          and .source.provider_id == $src
          and .target.provider_id == $tgt
          and .verdict == "blocked"
      )] | length'       "$FINDINGS_JSON")
    inconclusive_count=$(jq       --arg pat "$target_pattern"       --arg src "$source_arn"       --arg tgt "$target_arn"       '[.findings[] | select(
          .pattern_id == $pat
          and .source.provider_id == $src
          and .target.provider_id == $tgt
          and .verdict == "inconclusive"
      )] | length'       "$FINDINGS_JSON")
    blocker_count=$(jq       --arg pat "$target_pattern"       --arg src "$source_arn"       --arg tgt "$target_arn"       '[.findings[] | select(
          .pattern_id == $pat
          and .source.provider_id == $src
          and .target.provider_id == $tgt
          and .verdict == "validated"
      ) | .blockers_observed[]?] | length'       "$FINDINGS_JSON")

    echo "semantic assertion counts: ${target_pattern}.validated=$validated_count ${target_pattern}.blocked=$blocked_count ${target_pattern}.inconclusive=$inconclusive_count validated.blockers=$blocker_count scenario.validation=$scenario_validation_ok" | tee -a "$RUN_LOG"

    if (( scenario_validation_ok == 1 && validated_count >= validated_min && blocked_count == expected_blocked && inconclusive_count == expected_inconclusive && blocker_count == expected_blockers )); then
      echo "benchmark semantic assertion: PASS" | tee -a "$RUN_LOG"
      benchmark_rc=0
    else
      echo "benchmark semantic assertion: FAIL" | tee -a "$RUN_LOG"
      benchmark_rc=1
    fi
  fi
fi

cat <<EOF
Env06 benchmark pass finished with command exit code: $cmd_rc
Env06 benchmark final result code: $benchmark_rc
Artifacts saved under: $ARTIFACT_DIR
- run log: $RUN_LOG
- expected findings: $ARTIFACT_DIR/expected_findings.json
- collect output: $COLLECT_DIR
EOF

exit "$benchmark_rc"
