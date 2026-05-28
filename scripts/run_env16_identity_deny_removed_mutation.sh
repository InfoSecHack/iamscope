#!/usr/bin/env bash
set -Eeuo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
ENV_DIR="$PROJECT_ROOT/acceptance/env16_env03_identity_deny_removed"
EXPECTED_JSON="$ENV_DIR/expected_findings.json"
RUN_ID="${RUN_ID:-$(date -u +%Y%m%dT%H%M%SZ)}"
WORK_DIR="${IAMSCOPE_ENV16_WORKDIR:-/tmp/iamscope-env16-benchmark-$RUN_ID}"
ARTIFACT_DIR="${IAMSCOPE_BENCHMARK_OUT:-/tmp/iamscope-benchmark-env16-$RUN_ID}"
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
  echo "WARNING: non-numeric exit code from Env16 run: [$raw_rc]" | tee -a "$RUN_LOG" >&2
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
  source_arn=$(sed -n 's/^  alice_arn  : //p' "$RUN_LOG" | tail -1)
  target_arn=$(sed -n 's/^  admins_arn : //p' "$RUN_LOG" | tail -1)
  if [[ -z "$source_arn" || -z "$target_arn" ]]; then
    echo "benchmark semantic assertion: FAIL (missing alice_arn/admins_arn in $RUN_LOG)" | tee -a "$RUN_LOG"
    benchmark_rc=1
  else
    igme_validated_min=$(jq -r '.benchmark_contract.iam_group_membership_escalation.validated_min' "$EXPECTED_JSON")
    igme_blocked_expected=$(jq -r '.benchmark_contract.iam_group_membership_escalation.blocked' "$EXPECTED_JSON")
    igme_inconclusive_expected=$(jq -r '.benchmark_contract.iam_group_membership_escalation.inconclusive' "$EXPECTED_JSON")
    validated_with_blockers_expected=$(jq -r '.benchmark_contract.iam_group_membership_escalation.validated_with_blockers' "$EXPECTED_JSON")
    identity_deny_blockers_expected=$(jq -r '.benchmark_contract.iam_group_membership_escalation.identity_deny_blockers' "$EXPECTED_JSON")
    identity_deny_check_pass_min=$(jq -r '.benchmark_contract.iam_group_membership_escalation.identity_deny_check_pass_min' "$EXPECTED_JSON")

    igme_validated_count=$(jq --arg src "$source_arn" --arg tgt "$target_arn" '[.findings[] | select(.pattern_id == "iam_group_membership_escalation" and .source.provider_id == $src and .target.provider_id == $tgt and .verdict == "validated")] | length' "$FINDINGS_JSON")
    igme_blocked_count=$(jq --arg src "$source_arn" --arg tgt "$target_arn" '[.findings[] | select(.pattern_id == "iam_group_membership_escalation" and .source.provider_id == $src and .target.provider_id == $tgt and .verdict == "blocked")] | length' "$FINDINGS_JSON")
    igme_inconclusive_count=$(jq --arg src "$source_arn" --arg tgt "$target_arn" '[.findings[] | select(.pattern_id == "iam_group_membership_escalation" and .source.provider_id == $src and .target.provider_id == $tgt and .verdict == "inconclusive")] | length' "$FINDINGS_JSON")
    validated_with_blockers_count=$(jq --arg src "$source_arn" --arg tgt "$target_arn" '[.findings[] | select(
        .pattern_id == "iam_group_membership_escalation"
        and .source.provider_id == $src
        and .target.provider_id == $tgt
        and .verdict == "validated"
        and ((.blockers_observed // []) | length > 0)
      )] | length' "$FINDINGS_JSON")
    identity_deny_blockers_count=$(jq --arg src "$source_arn" --arg tgt "$target_arn" '[.findings[] | select(
        .pattern_id == "iam_group_membership_escalation"
        and .source.provider_id == $src
        and .target.provider_id == $tgt
      ) | .blockers_observed[]? | select(.kind == "identity_deny")] | length' "$FINDINGS_JSON")
    identity_deny_check_pass_count=$(jq --arg src "$source_arn" --arg tgt "$target_arn" '[.findings[] | select(
        .pattern_id == "iam_group_membership_escalation"
        and .source.provider_id == $src
        and .target.provider_id == $tgt
        and .verdict == "validated"
      ) | .required_checks[]? | select(
        .name == "no_identity_deny_blocks_add_user_to_group"
        and .state == "pass"
      )] | length' "$FINDINGS_JSON")

    echo "semantic assertion counts: iam_group_membership_escalation.validated=$igme_validated_count iam_group_membership_escalation.blocked=$igme_blocked_count iam_group_membership_escalation.inconclusive=$igme_inconclusive_count validated_with_blockers=$validated_with_blockers_count identity_deny.blockers=$identity_deny_blockers_count no_identity_deny_blocks_add_user_to_group.pass=$identity_deny_check_pass_count scenario.validation=$scenario_validation_ok" | tee -a "$RUN_LOG"

    if (( igme_validated_count >= igme_validated_min && igme_blocked_count == igme_blocked_expected && igme_inconclusive_count == igme_inconclusive_expected && validated_with_blockers_count == validated_with_blockers_expected && identity_deny_blockers_count == identity_deny_blockers_expected && identity_deny_check_pass_count >= identity_deny_check_pass_min )); then
      echo "benchmark semantic assertion: PASS" | tee -a "$RUN_LOG"
      benchmark_rc=0
    else
      echo "benchmark semantic assertion: FAIL" | tee -a "$RUN_LOG"
      benchmark_rc=1
    fi
  fi
fi

cat <<EOF
Env16 benchmark pass finished with command exit code: $cmd_rc
Env16 benchmark final result code: $benchmark_rc
Artifacts saved under: $ARTIFACT_DIR
- run log: $RUN_LOG
- expected findings: $ARTIFACT_DIR/expected_findings.json
- collect output: $COLLECT_DIR
EOF

exit "$benchmark_rc"
