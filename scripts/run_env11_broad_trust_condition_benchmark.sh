#!/usr/bin/env bash
set -Eeuo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
ENV_DIR="$PROJECT_ROOT/acceptance/env11_broad_trust_condition_blocked_admin"
EXPECTED_JSON="$ENV_DIR/expected_findings.json"
RUN_ID="${RUN_ID:-$(date -u +%Y%m%dT%H%M%SZ)}"
WORK_DIR="${IAMSCOPE_ENV11_WORKDIR:-/tmp/iamscope-env11-benchmark-$RUN_ID}"
ARTIFACT_DIR="${IAMSCOPE_BENCHMARK_OUT:-/tmp/iamscope-benchmark-env11-$RUN_ID}"
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
  echo "WARNING: non-numeric exit code from Env11 run: [$raw_rc]" | tee -a "$RUN_LOG" >&2
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
elif [[ ! -f "$EXPECTED_JSON" ]]; then
  echo "benchmark semantic assertion: FAIL (missing $EXPECTED_JSON)" | tee -a "$RUN_LOG"
  benchmark_rc=1
else
  source_arn=$(sed -n 's/^  alice_arn                  : //p' "$RUN_LOG" | tail -1)
  target_arn=$(sed -n 's/^  broad_conditioned_admin_arn: //p' "$RUN_LOG" | tail -1)
  if [[ -z "$source_arn" || -z "$target_arn" ]]; then
    echo "benchmark semantic assertion: FAIL (missing alice_arn/broad_conditioned_admin_arn in $RUN_LOG)" | tee -a "$RUN_LOG"
    benchmark_rc=1
  else
    perm_edge_type=$(jq -r '.benchmark_contract.required_scenario_edges.permission_edge_type' "$EXPECTED_JSON")
    trust_edge_type=$(jq -r '.benchmark_contract.required_scenario_edges.trust_edge_type' "$EXPECTED_JSON")
    min_edge_count=$(jq -r '.benchmark_contract.required_scenario_edges.min_count_each' "$EXPECTED_JSON")
    trust_constraint_type=$(jq -r '.benchmark_contract.required_trust_condition.constraint_type' "$EXPECTED_JSON")
    trust_condition_key=$(jq -r '.benchmark_contract.required_trust_condition.condition_key' "$EXPECTED_JSON")
    min_constraints=$(jq -r '.benchmark_contract.required_trust_condition.min_constraints' "$EXPECTED_JSON")
    min_bindings=$(jq -r '.benchmark_contract.required_trust_condition.min_edge_bindings' "$EXPECTED_JSON")
    ar_validated_max=$(jq -r '.benchmark_contract.admin_reachability.validated_max' "$EXPECTED_JSON")

    perm_edge_count=$(jq --arg typ "$perm_edge_type" --arg src "$source_arn" --arg tgt "$target_arn" '[.edges[] | select(.edge_type == $typ and .src.provider_id == $src and .dst.provider_id == $tgt)] | length' "$SCENARIO_JSON")
    trust_edge_count=$(jq --arg typ "$trust_edge_type" --arg tgt "$target_arn" '[.edges[] | select(.edge_type == $typ and .dst.provider_id == $tgt)] | length' "$SCENARIO_JSON")
    trust_edge_ids_json=$(jq -c --arg typ "$trust_edge_type" --arg tgt "$target_arn" '[.edges[] | select(.edge_type == $typ and .dst.provider_id == $tgt) | .edge_id]' "$SCENARIO_JSON")
    trust_constraint_ids_json=$(jq -c --arg ctype "$trust_constraint_type" --arg tgt "$target_arn" --arg ckey "$trust_condition_key" '[.constraints[] | select(.constraint_type == $ctype and .scope_id == $tgt and (.properties.condition_keys // [] | index($ckey))) | .constraint_id]' "$SCENARIO_JSON")
    trust_condition_count=$(jq --arg ctype "$trust_constraint_type" --arg tgt "$target_arn" --arg ckey "$trust_condition_key" '[.constraints[] | select(.constraint_type == $ctype and .scope_id == $tgt and (.properties.condition_keys // [] | index($ckey)))] | length' "$SCENARIO_JSON")
    trust_binding_count=$(jq --argjson edge_ids "$trust_edge_ids_json" --argjson constraint_ids "$trust_constraint_ids_json" '[.edge_constraints[] | select((.edge_id as $e | $edge_ids | index($e)) != null and (.constraint_id as $c | $constraint_ids | index($c)) != null)] | length' "$SCENARIO_JSON")

    ar_validated_count=$(jq --arg src "$source_arn" --arg tgt "$target_arn" '[.findings[] | select(.pattern_id == "admin_reachability" and .source.provider_id == $src and .target.provider_id == $tgt and .verdict == "validated")] | length' "$FINDINGS_JSON")
    ar_blocked_count=$(jq --arg src "$source_arn" --arg tgt "$target_arn" '[.findings[] | select(.pattern_id == "admin_reachability" and .source.provider_id == $src and .target.provider_id == $tgt and .verdict == "blocked")] | length' "$FINDINGS_JSON")
    ar_inconclusive_count=$(jq --arg src "$source_arn" --arg tgt "$target_arn" '[.findings[] | select(.pattern_id == "admin_reachability" and .source.provider_id == $src and .target.provider_id == $tgt and .verdict == "inconclusive")] | length' "$FINDINGS_JSON")

    echo "semantic assertion counts: scenario.permission_edges=$perm_edge_count scenario.trust_edges=$trust_edge_count scenario.trust_condition_constraints=$trust_condition_count scenario.trust_condition_bindings=$trust_binding_count admin_reachability.validated=$ar_validated_count admin_reachability.blocked=$ar_blocked_count admin_reachability.inconclusive=$ar_inconclusive_count scenario.validation=$scenario_validation_ok" | tee -a "$RUN_LOG"

    if (( scenario_validation_ok == 1 && perm_edge_count >= min_edge_count && trust_edge_count >= min_edge_count && trust_condition_count >= min_constraints && trust_binding_count >= min_bindings && ar_validated_count <= ar_validated_max )); then
      echo "benchmark semantic assertion: PASS" | tee -a "$RUN_LOG"
      benchmark_rc=0
    else
      echo "benchmark semantic assertion: FAIL" | tee -a "$RUN_LOG"
      benchmark_rc=1
    fi
  fi
fi

cat <<EOF
Env11 benchmark pass finished with command exit code: $cmd_rc
Env11 benchmark final result code: $benchmark_rc
Artifacts saved under: $ARTIFACT_DIR
- run log: $RUN_LOG
- expected findings: $ARTIFACT_DIR/expected_findings.json
- collect output: $COLLECT_DIR
EOF

exit "$benchmark_rc"
