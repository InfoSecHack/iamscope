#!/usr/bin/env bash
set -Eeuo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
ENV_DIR="$PROJECT_ROOT/acceptance/env19_env18_passedtoservice_scoped_away"
EXPECTED_JSON="$ENV_DIR/expected_findings.json"
RUN_ID="${RUN_ID:-$(date -u +%Y%m%dT%H%M%SZ)}"
WORK_DIR="${IAMSCOPE_ENV19_WORKDIR:-/tmp/iamscope-env19-benchmark-$RUN_ID}"
ARTIFACT_DIR="${IAMSCOPE_BENCHMARK_OUT:-/tmp/iamscope-benchmark-env19-$RUN_ID}"
COLLECT_DIR="$ARTIFACT_DIR/collect"
RUN_LOG="$ARTIFACT_DIR/run.log"
VALIDATE_LOG="$ARTIFACT_DIR/scenario_validate.txt"
SCENARIO_JSON="$COLLECT_DIR/scenario.json"
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
  echo "WARNING: non-numeric exit code from Env19 run: [$raw_rc]" | tee -a "$RUN_LOG" >&2
fi

cp "$EXPECTED_JSON" "$ARTIFACT_DIR/expected_findings.json"

scenario_validation_ok=0
if [[ -f "$SCENARIO_JSON" ]]; then
  if iamscope validate "$SCENARIO_JSON" >"$VALIDATE_LOG" 2>&1; then
    echo "scenario validation: PASS" >>"$RUN_LOG"
    scenario_validation_ok=1
  else
    echo "scenario validation: FAIL (see $VALIDATE_LOG)" >>"$RUN_LOG"
  fi
else
  echo "scenario validation: FAIL (missing $SCENARIO_JSON)" >>"$RUN_LOG"
fi

benchmark_rc="$cmd_rc"
if [[ ! -f "$SCENARIO_JSON" || ! -f "$FINDINGS_JSON" ]]; then
  echo "benchmark semantic assertion: SKIP (missing scenario.json or findings.json)" | tee -a "$RUN_LOG"
elif [[ "$scenario_validation_ok" != "1" ]]; then
  echo "benchmark semantic assertion: FAIL (scenario validation did not pass)" | tee -a "$RUN_LOG"
  benchmark_rc=1
else
  source_arn=$(sed -n 's/^  alice_arn[[:space:]]*: //p' "$RUN_LOG" | tail -1)
  target_arn=$(sed -n 's/^  lambda_admin_role_arn[[:space:]]*: //p' "$RUN_LOG" | tail -1)
  if [[ -z "$source_arn" || -z "$target_arn" ]]; then
    echo "benchmark semantic assertion: FAIL (missing alice_arn/lambda_admin_role_arn in $RUN_LOG)" | tee -a "$RUN_LOG"
    benchmark_rc=1
  else
    lambda_create_edge_type=$(jq -r '.benchmark_contract.required_scenario_edges.lambda_create_edge_type' "$EXPECTED_JSON")
    passrole_edge_type=$(jq -r '.benchmark_contract.required_scenario_edges.passrole_edge_type' "$EXPECTED_JSON")
    lambda_trust_edge_type=$(jq -r '.benchmark_contract.required_scenario_edges.lambda_trust_edge_type' "$EXPECTED_JSON")
    min_edge_count=$(jq -r '.benchmark_contract.required_scenario_edges.min_count_each' "$EXPECTED_JSON")
    condition_key=$(jq -r '.benchmark_contract.required_condition.condition_key' "$EXPECTED_JSON")
    condition_value=$(jq -r '.benchmark_contract.required_condition.condition_value' "$EXPECTED_JSON")
    condition_min=$(jq -r '.benchmark_contract.required_condition.min_count' "$EXPECTED_JSON")
    validated_expected=$(jq -r '.benchmark_contract.passrole_lambda.validated' "$EXPECTED_JSON")
    blocked_expected=$(jq -r '.benchmark_contract.passrole_lambda.blocked' "$EXPECTED_JSON")
    inconclusive_expected=$(jq -r '.benchmark_contract.passrole_lambda.inconclusive' "$EXPECTED_JSON")
    precondition_only_min=$(jq -r '.benchmark_contract.passrole_lambda.precondition_only_min' "$EXPECTED_JSON")
    passed_to_service_blockers_min=$(jq -r '.benchmark_contract.passrole_lambda.passed_to_service_blockers_min' "$EXPECTED_JSON")
    precondition_severity=$(jq -r '.benchmark_contract.passrole_lambda.precondition_severity' "$EXPECTED_JSON")

    lambda_create_edge_count=$(jq --arg typ "$lambda_create_edge_type" --arg src "$source_arn" '[.edges[] | select(.edge_type == $typ and .src.provider_id == $src and (.features.has_conditions // false | not) and (.features.is_wildcard_resource // false | not))] | length' "$SCENARIO_JSON")
    passrole_edge_count=$(jq --arg typ "$passrole_edge_type" --arg src "$source_arn" --arg tgt "$target_arn" '[.edges[] | select(.edge_type == $typ and .src.provider_id == $src and .dst.provider_id == $tgt)] | length' "$SCENARIO_JSON")
    lambda_trust_edge_count=$(jq --arg typ "$lambda_trust_edge_type" --arg tgt "$target_arn" '[.edges[] | select(.edge_type == $typ and .src.provider_id == "lambda.amazonaws.com" and .dst.provider_id == $tgt)] | length' "$SCENARIO_JSON")
    passed_to_service_condition_count=$(jq --arg typ "$passrole_edge_type" --arg src "$source_arn" --arg tgt "$target_arn" --arg key "$condition_key" --arg value "$condition_value" '
      [.edges[] | select(.edge_type == $typ and .src.provider_id == $src and .dst.provider_id == $tgt)
        | .features.raw_conditions? // {}
        | .. | objects
        | select(has($key) and ((.[$key] == $value) or ((.[$key] | type) == "array" and (.[$key] | index($value)))))
      ] | length
    ' "$SCENARIO_JSON")
    validated_count=$(jq --arg src "$source_arn" --arg tgt "$target_arn" '[.findings[] | select(.pattern_id == "passrole_lambda" and .source.provider_id == $src and .target.provider_id == $tgt and .verdict == "validated")] | length' "$FINDINGS_JSON")
    blocked_count=$(jq --arg src "$source_arn" --arg tgt "$target_arn" '[.findings[] | select(.pattern_id == "passrole_lambda" and .source.provider_id == $src and .target.provider_id == $tgt and .verdict == "blocked")] | length' "$FINDINGS_JSON")
    inconclusive_count=$(jq --arg src "$source_arn" --arg tgt "$target_arn" '[.findings[] | select(.pattern_id == "passrole_lambda" and .source.provider_id == $src and .target.provider_id == $tgt and .verdict == "inconclusive")] | length' "$FINDINGS_JSON")
    precondition_only_count=$(jq --arg src "$source_arn" --arg tgt "$target_arn" --arg severity "$precondition_severity" '[.findings[] | select(.pattern_id == "passrole_lambda" and .source.provider_id == $src and .target.provider_id == $tgt and .verdict == "precondition_only" and .severity == $severity)] | length' "$FINDINGS_JSON")
    passed_to_service_blockers_count=$(jq --arg src "$source_arn" --arg tgt "$target_arn" '[.findings[] | select(
        .pattern_id == "passrole_lambda"
        and .source.provider_id == $src
        and .target.provider_id == $tgt
      ) | .blockers_observed[]? | select(.kind == "passed_to_service")] | length' "$FINDINGS_JSON")
    condition_fail_check_count=$(jq --arg src "$source_arn" --arg tgt "$target_arn" '[.findings[] | select(
        .pattern_id == "passrole_lambda"
        and .source.provider_id == $src
        and .target.provider_id == $tgt
        and .verdict == "precondition_only"
      ) | .required_checks[]? | select(.name == "passrole_condition_scoped_to_lambda_or_absent" and .state == "fail")] | length' "$FINDINGS_JSON")

    echo "semantic assertion counts: scenario.lambda_create_edges=$lambda_create_edge_count scenario.passrole_edges=$passrole_edge_count scenario.lambda_trust_edges=$lambda_trust_edge_count scenario.passed_to_service_ec2_conditions=$passed_to_service_condition_count passrole_lambda.validated=$validated_count passrole_lambda.blocked=$blocked_count passrole_lambda.inconclusive=$inconclusive_count passrole_lambda.precondition_only=$precondition_only_count passed_to_service.blockers=$passed_to_service_blockers_count passed_to_service.fail_checks=$condition_fail_check_count scenario.validation=$scenario_validation_ok" | tee -a "$RUN_LOG"

    if (( lambda_create_edge_count >= min_edge_count && passrole_edge_count >= min_edge_count && lambda_trust_edge_count >= min_edge_count && passed_to_service_condition_count >= condition_min && validated_count == validated_expected && blocked_count == blocked_expected && inconclusive_count == inconclusive_expected && precondition_only_count >= precondition_only_min && passed_to_service_blockers_count >= passed_to_service_blockers_min && condition_fail_check_count >= 1 )); then
      echo "benchmark semantic assertion: PASS" | tee -a "$RUN_LOG"
      benchmark_rc=0
    else
      echo "benchmark semantic assertion: FAIL" | tee -a "$RUN_LOG"
      benchmark_rc=1
    fi
  fi
fi

cat <<EOF
Env19 benchmark pass finished with command exit code: $cmd_rc
Env19 benchmark final result code: $benchmark_rc
Artifacts saved under: $ARTIFACT_DIR
- run log: $RUN_LOG
- expected findings: $ARTIFACT_DIR/expected_findings.json
- collect output: $COLLECT_DIR
EOF

exit "$benchmark_rc"
