#!/usr/bin/env bash
set -Eeuo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
ENV_DIR="$PROJECT_ROOT/acceptance/env27_env26_multihop_trust_scoped_away"
EXPECTED_JSON="$ENV_DIR/expected_findings.json"
RUN_ID="${RUN_ID:-$(date -u +%Y%m%dT%H%M%SZ)}"
WORK_DIR="${IAMSCOPE_ENV27_WORKDIR:-/tmp/iamscope-env27-benchmark-$RUN_ID}"
ARTIFACT_DIR="${IAMSCOPE_BENCHMARK_OUT:-/tmp/iamscope-benchmark-env27-$RUN_ID}"
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
  echo "WARNING: non-numeric exit code from Env27 run: [$raw_rc]" | tee -a "$RUN_LOG" >&2
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
  alice_arn=$(sed -n 's/^  alice_arn[[:space:]]*: //p' "$RUN_LOG" | tail -1)
  decoy_arn=$(sed -n 's/^  decoy_arn[[:space:]]*: //p' "$RUN_LOG" | tail -1)
  hop1_arn=$(sed -n 's/^  hop1_arn[[:space:]]*: //p' "$RUN_LOG" | tail -1)
  hop2_arn=$(sed -n 's/^  hop2_arn[[:space:]]*: //p' "$RUN_LOG" | tail -1)
  admin_arn=$(sed -n 's/^  admin_arn[[:space:]]*: //p' "$RUN_LOG" | tail -1)
  if [[ -z "$alice_arn" || -z "$decoy_arn" || -z "$hop1_arn" || -z "$hop2_arn" || -z "$admin_arn" ]]; then
    echo "benchmark semantic assertion: FAIL (missing alice_arn/decoy_arn/hop1_arn/hop2_arn/admin_arn in $RUN_LOG)" | tee -a "$RUN_LOG"
    benchmark_rc=1
  else
    permission_edge_type=$(jq -r '.benchmark_contract.required_scenario_edges.permission_edge_type' "$EXPECTED_JSON")
    trust_edge_type=$(jq -r '.benchmark_contract.required_scenario_edges.trust_edge_type' "$EXPECTED_JSON")
    min_edge_count=$(jq -r '.benchmark_contract.required_scenario_edges.min_count_each' "$EXPECTED_JSON")
    arc_validated_expected=$(jq -r '.benchmark_contract.assume_role_chain.validated' "$EXPECTED_JSON")
    ar_validated_expected=$(jq -r '.benchmark_contract.admin_reachability.validated' "$EXPECTED_JSON")

    alice_node_count=$(jq --arg arn "$alice_arn" '[.nodes[] | select(.node_type == "IAMUser" and .provider_id == $arn)] | length' "$SCENARIO_JSON")
    decoy_node_count=$(jq --arg arn "$decoy_arn" '[.nodes[] | select(.node_type == "IAMUser" and .provider_id == $arn)] | length' "$SCENARIO_JSON")
    hop1_node_count=$(jq --arg arn "$hop1_arn" '[.nodes[] | select(.node_type == "IAMRole" and .provider_id == $arn)] | length' "$SCENARIO_JSON")
    hop2_node_count=$(jq --arg arn "$hop2_arn" '[.nodes[] | select(.node_type == "IAMRole" and .provider_id == $arn)] | length' "$SCENARIO_JSON")
    admin_node_count=$(jq --arg arn "$admin_arn" '[.nodes[] | select(.node_type == "IAMRole" and .provider_id == $arn)] | length' "$SCENARIO_JSON")
    permission_edge_1_count=$(jq --arg typ "$permission_edge_type" --arg src "$alice_arn" --arg tgt "$hop1_arn" '[.edges[] | select(.edge_type == $typ and .src.provider_id == $src and .dst.provider_id == $tgt and (.features.has_conditions // false | not) and (.features.is_wildcard_resource // false | not))] | length' "$SCENARIO_JSON")
    trust_edge_1_count=$(jq --arg typ "$trust_edge_type" --arg src "$alice_arn" --arg tgt "$hop1_arn" '[.edges[] | select(.edge_type == $typ and .src.provider_id == $src and .dst.provider_id == $tgt and (.features.has_conditions // false | not) and (.features.is_wildcard_principal // false | not))] | length' "$SCENARIO_JSON")
    permission_edge_2_count=$(jq --arg typ "$permission_edge_type" --arg src "$hop1_arn" --arg tgt "$hop2_arn" '[.edges[] | select(.edge_type == $typ and .src.provider_id == $src and .dst.provider_id == $tgt and (.features.has_conditions // false | not) and (.features.is_wildcard_resource // false | not))] | length' "$SCENARIO_JSON")
    matching_trust_edge_2_count=$(jq --arg typ "$trust_edge_type" --arg src "$hop1_arn" --arg tgt "$hop2_arn" '[.edges[] | select(.edge_type == $typ and .src.provider_id == $src and .dst.provider_id == $tgt and (.features.has_conditions // false | not) and (.features.is_wildcard_principal // false | not))] | length' "$SCENARIO_JSON")
    decoy_trust_edge_count=$(jq --arg typ "$trust_edge_type" --arg src "$decoy_arn" --arg tgt "$hop2_arn" '[.edges[] | select(.edge_type == $typ and .src.provider_id == $src and .dst.provider_id == $tgt and (.features.has_conditions // false | not) and (.features.is_wildcard_principal // false | not))] | length' "$SCENARIO_JSON")
    permission_edge_3_count=$(jq --arg typ "$permission_edge_type" --arg src "$hop2_arn" --arg tgt "$admin_arn" '[.edges[] | select(.edge_type == $typ and .src.provider_id == $src and .dst.provider_id == $tgt and (.features.has_conditions // false | not) and (.features.is_wildcard_resource // false | not))] | length' "$SCENARIO_JSON")
    trust_edge_3_count=$(jq --arg typ "$trust_edge_type" --arg src "$hop2_arn" --arg tgt "$admin_arn" '[.edges[] | select(.edge_type == $typ and .src.provider_id == $src and .dst.provider_id == $tgt and (.features.has_conditions // false | not) and (.features.is_wildcard_principal // false | not))] | length' "$SCENARIO_JSON")
    arc_validated_count=$(jq --arg src "$alice_arn" --arg tgt "$admin_arn" '[.findings[] | select(.pattern_id == "assume_role_chain" and .source.provider_id == $src and .target.provider_id == $tgt and .verdict == "validated")] | length' "$FINDINGS_JSON")
    ar_validated_count=$(jq --arg src "$alice_arn" --arg tgt "$admin_arn" '[.findings[] | select(.pattern_id == "admin_reachability" and .source.provider_id == $src and .target.provider_id == $tgt and .verdict == "validated")] | length' "$FINDINGS_JSON")

    echo "semantic assertion counts: scenario.alice_nodes=$alice_node_count scenario.decoy_nodes=$decoy_node_count scenario.hop1_nodes=$hop1_node_count scenario.hop2_nodes=$hop2_node_count scenario.admin_nodes=$admin_node_count scenario.first_permission_edges=$permission_edge_1_count scenario.first_trust_edges=$trust_edge_1_count scenario.second_permission_edges=$permission_edge_2_count scenario.matching_second_trust_edges=$matching_trust_edge_2_count scenario.decoy_trust_edges=$decoy_trust_edge_count scenario.downstream_permission_edges=$permission_edge_3_count scenario.downstream_trust_edges=$trust_edge_3_count assume_role_chain.validated=$arc_validated_count admin_reachability.validated=$ar_validated_count scenario.validation=$scenario_validation_ok" | tee -a "$RUN_LOG"

    if (( alice_node_count >= 1 && decoy_node_count >= 1 && hop1_node_count >= 1 && hop2_node_count >= 1 && admin_node_count >= 1 && permission_edge_1_count >= min_edge_count && trust_edge_1_count >= min_edge_count && permission_edge_2_count >= min_edge_count && matching_trust_edge_2_count == 0 && decoy_trust_edge_count >= min_edge_count && permission_edge_3_count >= min_edge_count && trust_edge_3_count >= min_edge_count && arc_validated_count == arc_validated_expected && ar_validated_count == ar_validated_expected )); then
      echo "benchmark semantic assertion: PASS" | tee -a "$RUN_LOG"
      benchmark_rc=0
    else
      echo "benchmark semantic assertion: FAIL" | tee -a "$RUN_LOG"
      benchmark_rc=1
    fi
  fi
fi

cat <<EOF
Env27 benchmark pass finished with command exit code: $cmd_rc
Env27 benchmark final result code: $benchmark_rc
Artifacts saved under: $ARTIFACT_DIR
- run log: $RUN_LOG
- expected findings: $ARTIFACT_DIR/expected_findings.json
- collect output: $COLLECT_DIR
EOF

exit "$benchmark_rc"
