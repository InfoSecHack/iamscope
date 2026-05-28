#!/usr/bin/env bash
# Env 3 acceptance test - CC-1: explicit identity-policy Deny overrides Allow.
#
# Usage: bash acceptance/env03_cc1_identity_deny/run.sh
#
# Prerequisites:
#   - Terraform >= 1.5 in PATH
#   - jq in PATH
#   - iamscope venv at ../../.venv (script activates it)
#   - AWS profiles iamscope-admin (deploy) and iamscope-test (scan) configured
#
# What this does:
#   1. Deploys env03 IAM resources via terraform apply
#   2. Runs iamscope collect against the sandbox account
#   3. Asserts four structural properties on findings.json (see below)
#   4. Destroys all created resources on exit (pass or fail)
#
# Assertions:
#   1. Exactly one iam_group_membership_escalation finding for alice->admins
#      has verdict=blocked.
#   2. Zero iam_group_membership_escalation findings for alice->admins have
#      verdict=validated.
#   3. The blocked finding has an identity_deny blocker with string
#      constraint_id and edge_id.
#   4. The blocked finding has required check
#      no_identity_deny_blocks_add_user_to_group with state=fail.
#
# Exit 0 = PASS. Exit 1 = FAIL (failed assertion printed before exit).
# terraform destroy runs unconditionally on EXIT via trap.

set -euo pipefail

if [[ "${IAMSCOPE_ACCEPTANCE_LIVE_CONFIRM:-}" != "YES" ]]; then
  echo "ERROR: set IAMSCOPE_ACCEPTANCE_LIVE_CONFIRM=YES to acknowledge this acceptance script can create, modify, collect from, and destroy test AWS resources" >&2
  echo "This script is not part of the default public quickstart; use only with an explicitly scoped test account/profile." >&2
  exit 2
fi

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="${PROJECT_ROOT_OVERRIDE:-$(cd "$SCRIPT_DIR/../.." && pwd)}"
OUTPUT_DIR="${OUTPUT_DIR:-/tmp/env03-cc1-output}"

# --- Activate iamscope venv ------------------------------------------------
source "$PROJECT_ROOT/.venv/bin/activate"

# --- Work from the Terraform directory -------------------------------------
cd "$SCRIPT_DIR"

# --- Cleanup trap: destroy on any exit (pass, fail, or interrupt) ----------
trap 'echo ""; echo "--- cleaning up: terraform destroy ---"; terraform destroy -auto-approve' EXIT

# --- Deploy ----------------------------------------------------------------
echo "--- terraform init ---"
terraform init -input=false

echo ""
echo "--- terraform apply ---"
terraform apply -auto-approve

# --- IAM eventual consistency ---------------------------------------------
echo ""
echo "Waiting 30s for IAM eventual consistency..."
sleep 30

# --- Capture Terraform outputs --------------------------------------------
ALICE_ARN=$(terraform output -raw alice_arn)
ADMINS_ARN=$(terraform output -raw admins_arn)
ACCOUNT_ID=$(terraform output -raw account_id)

echo ""
echo "Resources deployed:"
echo "  alice_arn  : $ALICE_ARN"
echo "  admins_arn : $ADMINS_ARN"
echo "  account_id : $ACCOUNT_ID"

# --- iamscope collect -----------------------------------------------------
# --standalone: single-account mode, skips Organizations SCP collection.
# iamscope-test profile has ReadOnlyAccess; no Organizations permissions needed.
# Clean output dir so a re-run never picks up stale findings.
rm -rf "$OUTPUT_DIR"
mkdir -p "$OUTPUT_DIR"

echo ""
echo "--- iamscope collect ---"
iamscope collect   --profile    iamscope-test   --region     us-east-1   --standalone   --output     "$OUTPUT_DIR"

FINDINGS_JSON="$OUTPUT_DIR/findings.json"

if [ ! -f "$FINDINGS_JSON" ]; then
  echo "FAIL: findings.json not found at $FINDINGS_JSON"
  exit 1
fi

echo ""
echo "findings.json written to $FINDINGS_JSON"

# --- Assertion 1: iam_group_membership_escalation BLOCKED ------------------
echo ""
echo "--- assertion 1: iam_group_membership_escalation BLOCKED (alice -> admins) ---"
IGME_BLOCKED_COUNT=$(jq   --arg src "$ALICE_ARN"   --arg tgt "$ADMINS_ARN"   '[.findings[] | select(
      .pattern_id       == "iam_group_membership_escalation"
      and .source.provider_id == $src
      and .target.provider_id == $tgt
      and .verdict      == "blocked"
  )] | length'   "$FINDINGS_JSON")

if [ "$IGME_BLOCKED_COUNT" -ne 1 ]; then
  echo "FAIL: assertion 1 - expected 1 blocked iam_group_membership_escalation finding for alice->admins, got $IGME_BLOCKED_COUNT"
  exit 1
fi
echo "PASS: assertion 1 - iam_group_membership_escalation BLOCKED for alice->admins (count=$IGME_BLOCKED_COUNT)"

# --- Assertion 2: no false-positive VALIDATED finding ----------------------
echo ""
echo "--- assertion 2: no VALIDATED iam_group_membership_escalation finding (alice -> admins) ---"
IGME_VALIDATED_COUNT=$(jq   --arg src "$ALICE_ARN"   --arg tgt "$ADMINS_ARN"   '[.findings[] | select(
      .pattern_id       == "iam_group_membership_escalation"
      and .source.provider_id == $src
      and .target.provider_id == $tgt
      and .verdict      == "validated"
  )] | length'   "$FINDINGS_JSON")

if [ "$IGME_VALIDATED_COUNT" -ne 0 ]; then
  echo "FAIL: assertion 2 - expected 0 validated iam_group_membership_escalation findings for alice->admins, got $IGME_VALIDATED_COUNT"
  exit 1
fi
echo "PASS: assertion 2 - no false-positive VALIDATED finding for alice->admins"

# --- Assertion 3: identity_deny blocker present ----------------------------
echo ""
echo "--- assertion 3: identity_deny blocker present with constraint and edge refs ---"
IDENTITY_DENY_BLOCKER_COUNT=$(jq   --arg src "$ALICE_ARN"   --arg tgt "$ADMINS_ARN"   '[.findings[] | select(
      .pattern_id       == "iam_group_membership_escalation"
      and .source.provider_id == $src
      and .target.provider_id == $tgt
      and .verdict      == "blocked"
  ) | .blockers_observed[]? | select(
      .kind == "identity_deny"
      and (.constraint_id | type == "string")
      and (.edge_id | type == "string")
  )] | length'   "$FINDINGS_JSON")

if [ "$IDENTITY_DENY_BLOCKER_COUNT" -lt 1 ]; then
  echo "FAIL: assertion 3 - expected blocked finding to have identity_deny blocker with string constraint_id and edge_id, got $IDENTITY_DENY_BLOCKER_COUNT"
  exit 1
fi
echo "PASS: assertion 3 - identity_deny blocker present (count=$IDENTITY_DENY_BLOCKER_COUNT)"

# --- Assertion 4: identity-deny required check failed ----------------------
echo ""
echo "--- assertion 4: no_identity_deny_blocks_add_user_to_group check FAIL ---"
IDENTITY_DENY_CHECK_FAIL_COUNT=$(jq   --arg src "$ALICE_ARN"   --arg tgt "$ADMINS_ARN"   '[.findings[] | select(
      .pattern_id       == "iam_group_membership_escalation"
      and .source.provider_id == $src
      and .target.provider_id == $tgt
      and .verdict      == "blocked"
  ) | .required_checks[]? | select(
      .name == "no_identity_deny_blocks_add_user_to_group"
      and .state == "fail"
  )] | length'   "$FINDINGS_JSON")

if [ "$IDENTITY_DENY_CHECK_FAIL_COUNT" -ne 1 ]; then
  echo "FAIL: assertion 4 - expected identity-deny required check to fail exactly once, got $IDENTITY_DENY_CHECK_FAIL_COUNT"
  exit 1
fi
echo "PASS: assertion 4 - identity-deny required check failed exactly once"

# --- All assertions passed ------------------------------------------------
echo ""
echo "============================================================"
echo "PASS: all 4 assertions passed - Env 3 CC-1 acceptance test PASS"
echo "============================================================"
