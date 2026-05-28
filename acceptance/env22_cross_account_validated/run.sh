#!/usr/bin/env bash
set -Eeuo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="${PROJECT_ROOT_OVERRIDE:-$(cd "$SCRIPT_DIR/../.." && pwd)}"
OUTPUT_DIR="${OUTPUT_DIR:-/tmp/env22-cross-account-output}"
COLLECTION_ROLE_NAME="${COLLECTION_ROLE_NAME:-env22-iamscope-reader}"

required_env=(
  MANAGEMENT_PROFILE
  CALLER_PROFILE
  TARGET_PROFILE
  CALLER_ACCOUNT_ID
  TARGET_ACCOUNT_ID
  AWS_REGION
)

missing_env=()
for name in "${required_env[@]}"; do
  if [[ -z "${!name:-}" ]]; then
    missing_env+=("$name")
  fi
done

if [[ ${#missing_env[@]} -gt 0 ]]; then
  echo "FAIL: missing required environment variable(s): ${missing_env[*]}" >&2
  exit 2
fi

if [[ "${CONFIRM_ENV22_CROSS_ACCOUNT_MUTATION:-}" != "YES" ]]; then
  echo "FAIL: set CONFIRM_ENV22_CROSS_ACCOUNT_MUTATION=YES to run Env22 Terraform setup" >&2
  exit 2
fi

if [[ "$CALLER_ACCOUNT_ID" == "$TARGET_ACCOUNT_ID" ]]; then
  echo "FAIL: caller and target account IDs must be different" >&2
  exit 2
fi

for cli in aws terraform jq; do
  if ! command -v "$cli" >/dev/null 2>&1; then
    echo "FAIL: required CLI not found: $cli" >&2
    exit 2
  fi
done

source "$PROJECT_ROOT/.venv/bin/activate"
export PYTHONPATH="$PROJECT_ROOT${PYTHONPATH:+:$PYTHONPATH}"
cd "$SCRIPT_DIR"

terraform_destroy() {
  echo ""
  echo "--- cleaning up: terraform destroy ---"
  terraform destroy -auto-approve \
    -var "aws_region=$AWS_REGION" \
    -var "caller_profile=$CALLER_PROFILE" \
    -var "target_profile=$TARGET_PROFILE" \
    -var "caller_account_id=$CALLER_ACCOUNT_ID" \
    -var "target_account_id=$TARGET_ACCOUNT_ID" \
    -var "management_account_id=${MANAGEMENT_ACCOUNT_ID:-000000000000}" \
    -var "collection_role_name=$COLLECTION_ROLE_NAME"
}
trap terraform_destroy EXIT

echo "--- Env22 cross-account preflight ---"
"$PROJECT_ROOT/scripts/check_env22_cross_account_prereqs.sh" \
  --management-profile "$MANAGEMENT_PROFILE" \
  --caller-profile "$CALLER_PROFILE" \
  --target-profile "$TARGET_PROFILE" \
  --caller-account-id "$CALLER_ACCOUNT_ID" \
  --target-account-id "$TARGET_ACCOUNT_ID" \
  --region "$AWS_REGION"

MANAGEMENT_IDENTITY_JSON="$(aws --profile "$MANAGEMENT_PROFILE" --region "$AWS_REGION" sts get-caller-identity --output json)"
MANAGEMENT_ACCOUNT_ID="$(jq -r '.Account' <<<"$MANAGEMENT_IDENTITY_JSON")"
MANAGEMENT_CALLER_ARN="$(jq -r '.Arn' <<<"$MANAGEMENT_IDENTITY_JSON")"

echo ""
echo "Confirmed setup identities:"
echo "  management_profile      : $MANAGEMENT_PROFILE"
echo "  management_account_id   : $MANAGEMENT_ACCOUNT_ID"
echo "  management_caller_arn   : $MANAGEMENT_CALLER_ARN"
echo "  caller_profile          : $CALLER_PROFILE"
echo "  target_profile          : $TARGET_PROFILE"
echo "  caller_account_id       : $CALLER_ACCOUNT_ID"
echo "  target_account_id       : $TARGET_ACCOUNT_ID"
echo "  aws_region              : $AWS_REGION"

echo ""
echo "--- terraform init ---"
terraform init -input=false

echo ""
echo "--- terraform apply ---"
terraform apply -auto-approve \
  -var "aws_region=$AWS_REGION" \
  -var "caller_profile=$CALLER_PROFILE" \
  -var "target_profile=$TARGET_PROFILE" \
  -var "caller_account_id=$CALLER_ACCOUNT_ID" \
  -var "target_account_id=$TARGET_ACCOUNT_ID" \
  -var "management_account_id=$MANAGEMENT_ACCOUNT_ID" \
  -var "collection_role_name=$COLLECTION_ROLE_NAME"

echo ""
echo "Waiting 30s for IAM eventual consistency..."
sleep 30

CALLER_ACTUAL_ACCOUNT_ID="$(terraform output -raw caller_account_id)"
TARGET_ACTUAL_ACCOUNT_ID="$(terraform output -raw target_account_id)"
ALICE_ARN="$(terraform output -raw alice_arn)"
ADMIN_ARN="$(terraform output -raw admin_arn)"
CALLER_COLLECTION_ROLE_ARN="$(terraform output -raw caller_collection_role_arn)"
TARGET_COLLECTION_ROLE_ARN="$(terraform output -raw target_collection_role_arn)"

if [[ "$CALLER_ACTUAL_ACCOUNT_ID" != "$CALLER_ACCOUNT_ID" ]]; then
  echo "FAIL: caller profile resolved to $CALLER_ACTUAL_ACCOUNT_ID, expected $CALLER_ACCOUNT_ID" >&2
  exit 1
fi
if [[ "$TARGET_ACTUAL_ACCOUNT_ID" != "$TARGET_ACCOUNT_ID" ]]; then
  echo "FAIL: target profile resolved to $TARGET_ACTUAL_ACCOUNT_ID, expected $TARGET_ACCOUNT_ID" >&2
  exit 1
fi

echo ""
echo "--- collection-role assume checks ---"
aws --profile "$MANAGEMENT_PROFILE" --region "$AWS_REGION" sts assume-role \
  --role-arn "$CALLER_COLLECTION_ROLE_ARN" \
  --role-session-name env22-caller-precollect-check \
  --output json >/dev/null
aws --profile "$MANAGEMENT_PROFILE" --region "$AWS_REGION" sts assume-role \
  --role-arn "$TARGET_COLLECTION_ROLE_ARN" \
  --role-session-name env22-target-precollect-check \
  --output json >/dev/null

echo ""
echo "Resources deployed:"
echo "  alice_arn                : $ALICE_ARN"
echo "  admin_arn                : $ADMIN_ARN"
echo "  caller_account_id        : $CALLER_ACTUAL_ACCOUNT_ID"
echo "  target_account_id        : $TARGET_ACTUAL_ACCOUNT_ID"
echo "  collection_role_name     : $COLLECTION_ROLE_NAME"
echo "  caller_collection_role   : $CALLER_COLLECTION_ROLE_ARN"
echo "  target_collection_role   : $TARGET_COLLECTION_ROLE_ARN"

rm -rf "$OUTPUT_DIR"
mkdir -p "$OUTPUT_DIR"

echo ""
echo "--- iamscope collect ---"
iamscope collect \
  --profile "$MANAGEMENT_PROFILE" \
  --region "$AWS_REGION" \
  --accounts "$CALLER_ACCOUNT_ID,$TARGET_ACCOUNT_ID" \
  --role-name "$COLLECTION_ROLE_NAME" \
  --output "$OUTPUT_DIR"

FINDINGS_JSON="$OUTPUT_DIR/findings.json"
if [[ ! -f "$FINDINGS_JSON" ]]; then
  echo "FAIL: findings.json not found at $FINDINGS_JSON"
  exit 1
fi

echo ""
echo "findings.json written to $FINDINGS_JSON"
