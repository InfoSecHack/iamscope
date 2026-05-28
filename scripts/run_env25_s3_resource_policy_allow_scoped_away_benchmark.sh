#!/usr/bin/env bash
set -Eeuo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
ENV_DIR="$PROJECT_ROOT/acceptance/env25_env24_resource_policy_allow_scoped_away"
EXPECTED_JSON="$ENV_DIR/expected_findings.json"
RUN_ID="${RUN_ID:-$(date -u +%Y%m%dT%H%M%SZ)}"
WORK_DIR="${IAMSCOPE_ENV25_WORKDIR:-/tmp/iamscope-env25-benchmark-$RUN_ID}"
ARTIFACT_DIR="${IAMSCOPE_BENCHMARK_OUT:-/tmp/iamscope-benchmark-env25-$RUN_ID}"
COLLECT_DIR="$ARTIFACT_DIR/collect"
RUN_LOG="$ARTIFACT_DIR/run.log"
VALIDATE_LOG="$ARTIFACT_DIR/scenario_validate.txt"
SCENARIO_JSON="$COLLECT_DIR/scenario.json"
FINDINGS_JSON="$COLLECT_DIR/findings.json"

source "$PROJECT_ROOT/.venv/bin/activate"
export PYTHONPATH="$PROJECT_ROOT${PYTHONPATH:+:$PYTHONPATH}"

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
  echo "WARNING: non-numeric exit code from Env25 run: [$raw_rc]" | tee -a "$RUN_LOG" >&2
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
  reader_arn=$(sed -n 's/^  reader_arn[[:space:]]*: //p' "$RUN_LOG" | tail -1)
  decoy_arn=$(sed -n 's/^  decoy_arn[[:space:]]*: //p' "$RUN_LOG" | tail -1)
  bucket_arn=$(sed -n 's/^  bucket_arn[[:space:]]*: //p' "$RUN_LOG" | tail -1)
  if [[ -z "$reader_arn" || -z "$decoy_arn" || -z "$bucket_arn" ]]; then
    echo "benchmark semantic assertion: FAIL (missing reader_arn/decoy_arn/bucket_arn in $RUN_LOG)" | tee -a "$RUN_LOG"
    benchmark_rc=1
  else
    decoy_edge_type=$(jq -r '.benchmark_contract.decoy_resource_policy_allow_edge.edge_type' "$EXPECTED_JSON")
    decoy_min_count=$(jq -r '.benchmark_contract.decoy_resource_policy_allow_edge.min_count' "$EXPECTED_JSON")
    rp_permission_source=$(jq -r '.benchmark_contract.decoy_resource_policy_allow_edge.permission_source' "$EXPECTED_JSON")
    rp_layer=$(jq -r '.benchmark_contract.decoy_resource_policy_allow_edge.layer' "$EXPECTED_JSON")
    reader_edge_type=$(jq -r '.benchmark_contract.reader_resource_policy_allow_edge.edge_type' "$EXPECTED_JSON")
    reader_edge_expected_count=$(jq -r '.benchmark_contract.reader_resource_policy_allow_edge.expected_count' "$EXPECTED_JSON")
    identity_edge_type=$(jq -r '.benchmark_contract.reader_identity_permission_edge.edge_type' "$EXPECTED_JSON")
    identity_expected_count=$(jq -r '.benchmark_contract.reader_identity_permission_edge.expected_count' "$EXPECTED_JSON")
    condition_constraints_expected=$(jq -r '.benchmark_contract.resource_policy_condition_constraints' "$EXPECTED_JSON")
    deny_constraints_expected=$(jq -r '.benchmark_contract.resource_policy_deny_constraints' "$EXPECTED_JSON")

    reader_node_count=$(jq --arg arn "$reader_arn" '[.nodes[] | select(.node_type == "IAMUser" and .provider_id == $arn)] | length' "$SCENARIO_JSON")
    decoy_node_count=$(jq --arg arn "$decoy_arn" '[.nodes[] | select(.node_type == "IAMUser" and .provider_id == $arn)] | length' "$SCENARIO_JSON")
    bucket_node_count=$(jq --arg arn "$bucket_arn" '[.nodes[] | select(.node_type == "S3Bucket" and .provider_id == $arn)] | length' "$SCENARIO_JSON")
    decoy_rp_edge_count=$(jq --arg typ "$decoy_edge_type" --arg src "$decoy_arn" --arg tgt "$bucket_arn" --arg permission_source "$rp_permission_source" --arg layer "$rp_layer" '[.edges[] | select(
        .edge_type == $typ
        and .src.provider_id == $src
        and .dst.provider_id == $tgt
        and (.features.permission_source // "") == $permission_source
        and (.features.layer // "") == $layer
        and (.features.has_conditions // false | not)
        and ((.features.allow_controls // []) | length >= 1)
      )] | length' "$SCENARIO_JSON")
    reader_rp_edge_count=$(jq --arg typ "$reader_edge_type" --arg src "$reader_arn" --arg tgt "$bucket_arn" '[.edges[] | select(.edge_type == $typ and .src.provider_id == $src and .dst.provider_id == $tgt)] | length' "$SCENARIO_JSON")
    reader_identity_edge_count=$(jq --arg typ "$identity_edge_type" --arg src "$reader_arn" --arg tgt "$bucket_arn" '[.edges[] | select(.edge_type == $typ and .src.provider_id == $src and .dst.provider_id == $tgt)] | length' "$SCENARIO_JSON")
    condition_constraint_count=$(jq --arg tgt "$bucket_arn" '[.constraints[] | select(.constraint_type == "RESOURCE_POLICY_CONDITION" and (.scope_id == $tgt or .properties.target_arn == $tgt))] | length' "$SCENARIO_JSON")
    deny_constraint_count=$(jq '[.constraints[] | select(.constraint_type == "RESOURCE_POLICY_DENY")] | length' "$SCENARIO_JSON")

    echo "semantic assertion counts: scenario.reader_nodes=$reader_node_count scenario.decoy_nodes=$decoy_node_count scenario.bucket_nodes=$bucket_node_count scenario.decoy_resource_policy_edges=$decoy_rp_edge_count scenario.reader_resource_policy_edges=$reader_rp_edge_count scenario.reader_identity_permission_edges=$reader_identity_edge_count scenario.resource_policy_condition_constraints=$condition_constraint_count scenario.resource_policy_deny_constraints=$deny_constraint_count scenario.validation=$scenario_validation_ok" | tee -a "$RUN_LOG"

    if (( reader_node_count >= 1 && decoy_node_count >= 1 && bucket_node_count >= 1 && decoy_rp_edge_count >= decoy_min_count && reader_rp_edge_count == reader_edge_expected_count && reader_identity_edge_count == identity_expected_count && condition_constraint_count == condition_constraints_expected && deny_constraint_count == deny_constraints_expected )); then
      echo "benchmark semantic assertion: PASS" | tee -a "$RUN_LOG"
      benchmark_rc=0
    else
      echo "benchmark semantic assertion: FAIL" | tee -a "$RUN_LOG"
      benchmark_rc=1
    fi
  fi
fi

cat <<EOF
Env25 benchmark pass finished with command exit code: $cmd_rc
Env25 benchmark final result code: $benchmark_rc
Artifacts saved under: $ARTIFACT_DIR
- run log: $RUN_LOG
- expected findings: $ARTIFACT_DIR/expected_findings.json
- collect output: $COLLECT_DIR
EOF

exit "$benchmark_rc"
