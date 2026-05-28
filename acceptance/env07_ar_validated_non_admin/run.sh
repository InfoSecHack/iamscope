#!/usr/bin/env bash
set -euo pipefail

if [[ "${IAMSCOPE_ACCEPTANCE_LIVE_CONFIRM:-}" != "YES" ]]; then
  echo "ERROR: set IAMSCOPE_ACCEPTANCE_LIVE_CONFIRM=YES to acknowledge this acceptance script can create, modify, collect from, and destroy test AWS resources" >&2
  echo "This script is not part of the default public quickstart; use only with an explicitly scoped test account/profile." >&2
  exit 2
fi

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="${PROJECT_ROOT_OVERRIDE:-$(cd "$SCRIPT_DIR/../.." && pwd)}"
OUTPUT_DIR="${OUTPUT_DIR:-/tmp/env07-ar-output}"

source "$PROJECT_ROOT/.venv/bin/activate"
cd "$SCRIPT_DIR"
trap 'echo ""; echo "--- cleaning up: terraform destroy ---"; terraform destroy -auto-approve' EXIT

echo "--- terraform init ---"
terraform init -input=false

echo ""
echo "--- terraform apply ---"
terraform apply -auto-approve

echo ""
echo "Waiting 30s for IAM eventual consistency..."
sleep 30

ALICE_ARN=$(terraform output -raw alice_arn)
READER_ARN=$(terraform output -raw reader_arn)
ACCOUNT_ID=$(terraform output -raw account_id)

echo ""
echo "Resources deployed:"
echo "  alice_arn  : $ALICE_ARN"
echo "  reader_arn : $READER_ARN"
echo "  account_id : $ACCOUNT_ID"

rm -rf "$OUTPUT_DIR"
mkdir -p "$OUTPUT_DIR"

echo ""
echo "--- iamscope collect ---"
iamscope collect \
  --profile iamscope-test \
  --region us-east-1 \
  --standalone \
  --output "$OUTPUT_DIR"

FINDINGS_JSON="$OUTPUT_DIR/findings.json"
if [[ ! -f "$FINDINGS_JSON" ]]; then
  echo "FAIL: findings.json not found at $FINDINGS_JSON"
  exit 1
fi

echo ""
echo "findings.json written to $FINDINGS_JSON"