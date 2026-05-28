#!/usr/bin/env bash
# Env 5 acceptance test — AR-1 regression: permission boundary blocks chain hop 2.
#
# Usage: bash acceptance/env05_ar1_blocked_chain/run.sh
#
# Prerequisites:
#   - Terraform >= 1.5 in PATH
#   - jq in PATH
#   - iamscope venv activated OR run from the project root (script activates it)
#   - AWS profiles iamscope-admin (deploy) and iamscope-test (scan) configured
#
# What this does:
#   1. Deploys env05 IAM resources via terraform apply
#   2. Runs iamscope collect against the sandbox account
#   3. Asserts three structural properties on findings.json (see below)
#   4. Destroys all created resources on exit (pass or fail)
#
# Assertions:
#   1. Exactly one assume_role_chain finding: alice->admin, verdict=blocked
#   2. Exactly one admin_reachability finding: alice->admin, verdict=inconclusive
#   3. That admin_reachability finding has a cross_reasoner_blocked blocker
#      with constraint_id=null (Phase 2 AR-1 fix signal)
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
OUTPUT_DIR="${OUTPUT_DIR:-/tmp/env05-output}"

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
DEVOPS_ARN=$(terraform output -raw devops_arn)
ADMIN_ARN=$(terraform output -raw admin_arn)
ACCOUNT_ID=$(terraform output -raw account_id)

echo ""
echo "Resources deployed:"
echo "  alice_arn  : $ALICE_ARN"
echo "  devops_arn : $DEVOPS_ARN"
echo "  admin_arn  : $ADMIN_ARN"
echo "  account_id : $ACCOUNT_ID"

# --- iamscope collect -----------------------------------------------------
# --standalone: single-account mode, skips Organizations SCP collection.
# iamscope-test profile has ReadOnlyAccess; no Organizations permissions needed.
# Clean output dir so a re-run never picks up stale findings.
rm -rf "$OUTPUT_DIR"
mkdir -p "$OUTPUT_DIR"

echo ""
echo "--- iamscope collect ---"
iamscope collect \
  --profile    iamscope-test \
  --region     us-east-1 \
  --standalone \
  --output     "$OUTPUT_DIR"

FINDINGS_JSON="$OUTPUT_DIR/findings.json"

if [ ! -f "$FINDINGS_JSON" ]; then
  echo "FAIL: findings.json not found at $FINDINGS_JSON"
  exit 1
fi

echo ""
echo "findings.json written to $FINDINGS_JSON"

# --- Assertion 1: assume_role_chain BLOCKED --------------------------------
echo ""
echo "--- assertion 1: assume_role_chain BLOCKED (alice -> admin) ---"
ARC_COUNT=$(jq \
  --arg src "$ALICE_ARN" \
  --arg tgt "$ADMIN_ARN" \
  '[.findings[] | select(
      .pattern_id       == "assume_role_chain"
      and .source.provider_id == $src
      and .target.provider_id == $tgt
      and .verdict      == "blocked"
  )] | length' \
  "$FINDINGS_JSON")

if [ "$ARC_COUNT" -ne 1 ]; then
  echo "FAIL: assertion 1 — expected 1 assume_role_chain blocked finding for alice->admin, got $ARC_COUNT"
  exit 1
fi
echo "PASS: assertion 1 — assume_role_chain BLOCKED for alice->admin (count=$ARC_COUNT)"

# --- Assertion 2: admin_reachability INCONCLUSIVE -------------------------
echo ""
echo "--- assertion 2: admin_reachability INCONCLUSIVE (alice -> admin) ---"
AR_COUNT=$(jq \
  --arg src "$ALICE_ARN" \
  --arg tgt "$ADMIN_ARN" \
  '[.findings[] | select(
      .pattern_id       == "admin_reachability"
      and .source.provider_id == $src
      and .target.provider_id == $tgt
      and .verdict      == "inconclusive"
  )] | length' \
  "$FINDINGS_JSON")

if [ "$AR_COUNT" -ne 1 ]; then
  echo "FAIL: assertion 2 — expected 1 admin_reachability inconclusive finding for alice->admin, got $AR_COUNT"
  exit 1
fi
echo "PASS: assertion 2 — admin_reachability INCONCLUSIVE for alice->admin (count=$AR_COUNT)"

# --- Assertion 3: cross_reasoner_blocked blocker with null constraint_id --
echo ""
echo "--- assertion 3: cross_reasoner_blocked blocker with null constraint_id ---"
BLOCKER_COUNT=$(jq \
  --arg src "$ALICE_ARN" \
  --arg tgt "$ADMIN_ARN" \
  '[.findings[] | select(
      .pattern_id       == "admin_reachability"
      and .source.provider_id == $src
      and .target.provider_id == $tgt
  ) | .blockers_observed[] | select(
      .kind          == "cross_reasoner_blocked"
      and .constraint_id == null
  )] | length' \
  "$FINDINGS_JSON")

if [ "$BLOCKER_COUNT" -lt 1 ]; then
  echo "FAIL: assertion 3 — expected admin_reachability finding to have cross_reasoner_blocked blocker with null constraint_id, got $BLOCKER_COUNT"
  exit 1
fi
echo "PASS: assertion 3 — cross_reasoner_blocked blocker with null constraint_id present (count=$BLOCKER_COUNT)"

# --- All assertions passed ------------------------------------------------
echo ""
echo "============================================================"
echo "PASS: all 3 assertions passed — Env 5 acceptance test PASS"
echo "============================================================"
