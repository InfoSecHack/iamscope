#!/usr/bin/env bash
set -euo pipefail

if [[ "${IAMSCOPE_ACCEPTANCE_LIVE_CONFIRM:-}" != "YES" ]]; then
  echo "ERROR: set IAMSCOPE_ACCEPTANCE_LIVE_CONFIRM=YES to acknowledge this acceptance script can create, modify, collect from, and destroy test AWS resources" >&2
  echo "This script is not part of the default public quickstart; use only with an explicitly scoped test account/profile." >&2
  exit 2
fi

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="${PROJECT_ROOT_OVERRIDE:-$(cd "$SCRIPT_DIR/../.." && pwd)}"
OUTPUT_DIR="${OUTPUT_DIR:-/tmp/env09-output}"

source "$PROJECT_ROOT/.venv/bin/activate"
cd "$SCRIPT_DIR"
trap '''echo ""; echo "--- cleaning up: terraform destroy ---"; terraform destroy -auto-approve''' EXIT

echo "--- terraform init ---"
terraform init -input=false

echo ""
echo "--- terraform apply ---"
terraform apply -auto-approve

echo ""
echo "Waiting 30s for IAM eventual consistency..."
sleep 30

ALICE_ARN=$(terraform output -raw alice_arn)
DEVOPS_ARN=$(terraform output -raw devops_arn)
ADMIN_ARN=$(terraform output -raw admin_arn)
ACCOUNT_ID=$(terraform output -raw account_id)

echo ""
echo "Resources deployed:"
echo "  alice_arn  : $ALICE_ARN"
echo "  devops_arn : $DEVOPS_ARN"
echo "  admin_arn  : $ADMIN_ARN"
echo "  account_id : $ACCOUNT_ID"

rm -rf "$OUTPUT_DIR"
mkdir -p "$OUTPUT_DIR"

echo ""
echo "--- iamscope collect ---"
iamscope collect   --profile iamscope-test   --region us-east-1   --standalone   --output "$OUTPUT_DIR"

FINDINGS_JSON="$OUTPUT_DIR/findings.json"
if [ ! -f "$FINDINGS_JSON" ]; then
  echo "FAIL: findings.json not found at $FINDINGS_JSON"
  exit 1
fi

echo ""
echo "findings.json written to $FINDINGS_JSON"

echo ""
echo "--- assertion 1: admin_reachability VALIDATED (alice -> admin) ---"
AR_VALIDATED_COUNT=$(jq   --arg src "$ALICE_ARN"   --arg tgt "$ADMIN_ARN"   '[.findings[] | select(
      .pattern_id == "admin_reachability"
      and .source.provider_id == $src
      and .target.provider_id == $tgt
      and .verdict == "validated"
  )] | length'   "$FINDINGS_JSON")

if [ "$AR_VALIDATED_COUNT" -lt 1 ]; then
  echo "FAIL: assertion 1 - expected at least 1 validated admin_reachability finding for alice->admin, got $AR_VALIDATED_COUNT"
  exit 1
fi
echo "PASS: assertion 1 - admin_reachability VALIDATED for alice->admin (count=$AR_VALIDATED_COUNT)"

echo ""
echo "--- assertion 2: no BLOCKED or INCONCLUSIVE admin_reachability (alice -> admin) ---"
AR_NONVALIDATED_COUNT=$(jq   --arg src "$ALICE_ARN"   --arg tgt "$ADMIN_ARN"   '[.findings[] | select(
      .pattern_id == "admin_reachability"
      and .source.provider_id == $src
      and .target.provider_id == $tgt
      and (.verdict == "blocked" or .verdict == "inconclusive")
  )] | length'   "$FINDINGS_JSON")

if [ "$AR_NONVALIDATED_COUNT" -ne 0 ]; then
  echo "FAIL: assertion 2 - expected 0 blocked/inconclusive admin_reachability findings for alice->admin, got $AR_NONVALIDATED_COUNT"
  exit 1
fi
echo "PASS: assertion 2 - no blocked/inconclusive admin_reachability findings for alice->admin"

echo ""
echo "--- assertion 3: validated admin_reachability has no blockers_observed ---"
AR_BLOCKER_COUNT=$(jq   --arg src "$ALICE_ARN"   --arg tgt "$ADMIN_ARN"   '[.findings[] | select(
      .pattern_id == "admin_reachability"
      and .source.provider_id == $src
      and .target.provider_id == $tgt
      and .verdict == "validated"
  ) | .blockers_observed[]?] | length'   "$FINDINGS_JSON")

if [ "$AR_BLOCKER_COUNT" -ne 0 ]; then
  echo "FAIL: assertion 3 - expected 0 blockers_observed on validated admin_reachability findings for alice->admin, got $AR_BLOCKER_COUNT"
  exit 1
fi
echo "PASS: assertion 3 - validated admin_reachability has no blockers_observed"

echo ""
echo "--- observation: assume_role_chain counts (alice -> admin) ---"
ARC_VALIDATED_COUNT=$(jq   --arg src "$ALICE_ARN"   --arg tgt "$ADMIN_ARN"   '[.findings[] | select(
      .pattern_id == "assume_role_chain"
      and .source.provider_id == $src
      and .target.provider_id == $tgt
      and .verdict == "validated"
  )] | length'   "$FINDINGS_JSON")
ARC_BLOCKED_COUNT=$(jq   --arg src "$ALICE_ARN"   --arg tgt "$ADMIN_ARN"   '[.findings[] | select(
      .pattern_id == "assume_role_chain"
      and .source.provider_id == $src
      and .target.provider_id == $tgt
      and .verdict == "blocked"
  )] | length'   "$FINDINGS_JSON")
echo "OBSERVE: assume_role_chain.validated=$ARC_VALIDATED_COUNT assume_role_chain.blocked=$ARC_BLOCKED_COUNT"

echo ""
echo "============================================================"
echo "PASS: all required assertions passed - Env 9 mutation benchmark PASS"
echo "============================================================"
