#!/usr/bin/env bash
set -Eeuo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="${PROJECT_ROOT_OVERRIDE:-$(cd "$SCRIPT_DIR/../.." && pwd)}"
OUTPUT_DIR="${OUTPUT_DIR:-/tmp/env13-scp-output}"
RUN_ID="${RUN_ID:-$(date -u +%Y%m%dT%H%M%SZ)}"
COLLECTION_ROLE_NAME="${COLLECTION_ROLE_NAME:-env13-iamscope-reader}"

require_env() {
  local name="$1"
  if [[ -z "${!name:-}" ]]; then
    echo "ERROR: $name is required; Env13 must not use default AWS credentials silently" >&2
    exit 2
  fi
}

require_cli() {
  local name="$1"
  if ! command -v "$name" >/dev/null 2>&1; then
    echo "ERROR: required CLI not found: $name" >&2
    exit 2
  fi
}

assume_collection_role() {
  local session_name="$1"
  aws --profile "$MANAGEMENT_PROFILE" --region "$AWS_REGION" sts assume-role \
    --role-arn "$COLLECTION_ROLE_ARN" \
    --role-session-name "$session_name" >/dev/null
}

require_env MANAGEMENT_PROFILE
require_env MEMBER_PROFILE
require_env AWS_REGION

if [[ "${CONFIRM_ENV13_SCP_MUTATION:-}" != "YES" ]]; then
  echo "ERROR: set CONFIRM_ENV13_SCP_MUTATION=YES to acknowledge Env13 creates and attaches one SCP to the member account" >&2
  exit 2
fi

source "$PROJECT_ROOT/.venv/bin/activate"

require_cli aws
require_cli terraform
require_cli jq

cd "$SCRIPT_DIR"

SCP_POLICY_ID=""
SCP_ATTACHED="0"
MEMBER_ACCOUNT_ID=""
MANAGEMENT_ACCOUNT_ID=""
MANAGEMENT_CALLER_ARN=""
SCP_POLICY_NAME="env13-deny-assumerole-except-collector-${RUN_ID}"
SCP_CONTENT_FILE="$SCRIPT_DIR/env13-scp-policy-${RUN_ID}.json"

cleanup() {
  local rc=$?
  set +e
  echo ""
  echo "--- cleanup: Env13 SCP and Terraform fixture ---"

  if [[ "$SCP_ATTACHED" == "1" && -n "$SCP_POLICY_ID" && -n "$MEMBER_ACCOUNT_ID" ]]; then
    echo "detaching SCP $SCP_POLICY_ID from member account $MEMBER_ACCOUNT_ID"
    for attempt in 1 2 3; do
      if aws --profile "$MANAGEMENT_PROFILE" --region "$AWS_REGION" organizations detach-policy \
        --policy-id "$SCP_POLICY_ID" \
        --target-id "$MEMBER_ACCOUNT_ID"; then
        SCP_ATTACHED="0"
        break
      fi
      echo "detach attempt $attempt failed; retrying in 10s"
      sleep 10
    done
  fi

  if [[ -n "$SCP_POLICY_ID" ]]; then
    echo "deleting SCP $SCP_POLICY_ID"
    for attempt in 1 2 3 4 5 6; do
      if aws --profile "$MANAGEMENT_PROFILE" --region "$AWS_REGION" organizations delete-policy \
        --policy-id "$SCP_POLICY_ID"; then
        break
      fi
      echo "delete attempt $attempt failed; retrying in 10s"
      sleep 10
    done
  fi

  rm -f "$SCP_CONTENT_FILE"

  echo "terraform destroy member IAM fixture"
  terraform destroy -auto-approve \
    -var "aws_region=$AWS_REGION" \
    -var "member_profile=$MEMBER_PROFILE" \
    -var "management_account_id=${MANAGEMENT_ACCOUNT_ID:-000000000000}" \
    -var "collection_role_name=$COLLECTION_ROLE_NAME"

  exit "$rc"
}
trap cleanup EXIT

echo "============================================================"
echo "WARNING: Env13 performs live AWS Organizations mutation."
echo "It creates one Env13-specific SCP and attaches it directly to"
echo "the dedicated member account, then detaches/deletes it on cleanup."
echo "The SCP denies sts:AssumeRole on Resource * except the management"
echo "collection caller principal."
echo "No accounts are created or closed."
echo "============================================================"
echo "management_profile=$MANAGEMENT_PROFILE"
echo "member_profile=$MEMBER_PROFILE"
echo "aws_region=$AWS_REGION"
echo "collection_role_name=$COLLECTION_ROLE_NAME"
echo "scp_policy_name=$SCP_POLICY_NAME"
echo

echo "--- Env13 prerequisite check ---"
"$PROJECT_ROOT/scripts/check_env12_scp_prereqs.sh" \
  --management-profile "$MANAGEMENT_PROFILE" \
  --member-profile "$MEMBER_PROFILE" \
  --region "$AWS_REGION"

MANAGEMENT_ACCOUNT_ID="$(aws --profile "$MANAGEMENT_PROFILE" --region "$AWS_REGION" sts get-caller-identity --query Account --output text)"
MANAGEMENT_CALLER_ARN="$(aws --profile "$MANAGEMENT_PROFILE" --region "$AWS_REGION" sts get-caller-identity --query Arn --output text)"
MEMBER_ACCOUNT_ID="$(aws --profile "$MEMBER_PROFILE" --region "$AWS_REGION" sts get-caller-identity --query Account --output text)"

echo ""
echo "--- terraform init ---"
terraform init -input=false

echo ""
echo "--- terraform apply member IAM fixture ---"
terraform apply -auto-approve \
  -var "aws_region=$AWS_REGION" \
  -var "member_profile=$MEMBER_PROFILE" \
  -var "management_account_id=$MANAGEMENT_ACCOUNT_ID" \
  -var "collection_role_name=$COLLECTION_ROLE_NAME"

echo ""
echo "Waiting 30s for IAM eventual consistency before SCP attachment..."
sleep 30

ALICE_ARN="$(terraform output -raw alice_arn)"
ADMIN_ARN="$(terraform output -raw admin_arn)"
COLLECTION_ROLE_ARN="$(terraform output -raw collection_role_arn)"
COLLECTION_ROLE_ASSUME_NAME="${COLLECTION_ROLE_ARN#*:role/}"

if [[ "$ADMIN_ARN" == "$COLLECTION_ROLE_ARN" ]]; then
  echo "FAIL: Env13 admin role ARN unexpectedly equals collection role ARN; refusing SCP attach" >&2
  exit 1
fi
if [[ -z "$COLLECTION_ROLE_ASSUME_NAME" || "$COLLECTION_ROLE_ASSUME_NAME" == "$COLLECTION_ROLE_ARN" ]]; then
  echo "FAIL: could not derive IAMScope --role-name value from collection_role_arn=$COLLECTION_ROLE_ARN" >&2
  exit 1
fi

echo ""
echo "--- preflight: management profile can assume collection role before SCP attach ---"
echo "collection_role_arn=$COLLECTION_ROLE_ARN"
echo "collection_role_assume_name=$COLLECTION_ROLE_ASSUME_NAME"
assume_preflight_ok=0
assume_preflight_output=""
for attempt in 1 2 3 4 5 6; do
  if assume_preflight_output="$(assume_collection_role env13-preflight-collection 2>&1)"; then
    assume_preflight_ok=1
    break
  fi
  echo "collection role preflight attempt $attempt failed before SCP attach: $assume_preflight_output"
  sleep 10
done
if [[ "$assume_preflight_ok" != "1" ]]; then
  echo "FAIL: management profile cannot assume $COLLECTION_ROLE_ARN before SCP attach; refusing to create or attach Env13 SCP" >&2
  exit 1
fi
echo "PASS: collection role assumption works before SCP attach"

echo ""
echo "--- build Env13 SCP carveout principal list ---"
carveout_json="$(jq -n --arg caller "$MANAGEMENT_CALLER_ARN" --arg management_account "$MANAGEMENT_ACCOUNT_ID" '
  [$caller, ("arn:aws:iam::" + $management_account + ":root")]
')"
if [[ "$MANAGEMENT_CALLER_ARN" =~ ^arn:aws:sts::([0-9]{12}):assumed-role/(.+)/[^/]+$ ]]; then
  assumed_account="${BASH_REMATCH[1]}"
  assumed_role_name="${BASH_REMATCH[2]}"
  assumed_role_arn="arn:aws:iam::${assumed_account}:role/${assumed_role_name}"
  assumed_role_session_pattern="arn:aws:sts::${assumed_account}:assumed-role/${assumed_role_name}/*"
  carveout_json="$(jq -c --argjson existing "$carveout_json" --arg role "$assumed_role_arn" --arg session "$assumed_role_session_pattern" '$existing + [$role, $session] | unique' <<<"{}")"
else
  carveout_json="$(jq -c 'unique' <<<"$carveout_json")"
fi

echo "management_caller_arn: $MANAGEMENT_CALLER_ARN"
echo "collection_principal_carveouts: $carveout_json"

jq -n --argjson carveouts "$carveout_json" '{
  Version: "2012-10-17",
  Statement: [
    {
      Sid: "Env13DenyAssumeRoleExceptCollector",
      Effect: "Deny",
      Action: "sts:AssumeRole",
      Resource: "*",
      Condition: {
        ArnNotLike: {
          "aws:PrincipalArn": $carveouts
        }
      }
    }
  ]
}' >"$SCP_CONTENT_FILE"

echo ""
echo "Env13 SCP content:"
cat "$SCP_CONTENT_FILE"

echo ""
echo "--- create Env13 SCP ---"
SCP_CREATE_JSON="$(aws --profile "$MANAGEMENT_PROFILE" --region "$AWS_REGION" organizations create-policy \
  --name "$SCP_POLICY_NAME" \
  --description "IAMScope Env13 benchmark SCP: complete sts:AssumeRole deny with collection caller carveout" \
  --type SERVICE_CONTROL_POLICY \
  --content "file://$SCP_CONTENT_FILE")"
SCP_POLICY_ID="$(printf '%s' "$SCP_CREATE_JSON" | jq -r '.Policy.PolicySummary.Id')"
if [[ -z "$SCP_POLICY_ID" || "$SCP_POLICY_ID" == "null" ]]; then
  echo "FAIL: could not parse created SCP policy ID" >&2
  exit 1
fi

echo ""
echo "--- attach Env13 SCP to member account ---"
aws --profile "$MANAGEMENT_PROFILE" --region "$AWS_REGION" organizations attach-policy \
  --policy-id "$SCP_POLICY_ID" \
  --target-id "$MEMBER_ACCOUNT_ID"
SCP_ATTACHED="1"

echo ""
echo "Waiting 30s for Organizations SCP propagation..."
sleep 30

echo ""
echo "--- preflight: management profile can still assume collection role after SCP attach ---"
assume_postflight_ok=0
assume_postflight_output=""
for attempt in 1 2 3 4 5 6; do
  if assume_postflight_output="$(assume_collection_role env13-postflight-collection 2>&1)"; then
    assume_postflight_ok=1
    break
  fi
  echo "collection role post-attach preflight attempt $attempt failed: $assume_postflight_output"
  sleep 10
done
if [[ "$assume_postflight_ok" != "1" ]]; then
  echo "FAIL: management profile cannot assume $COLLECTION_ROLE_ARN after Env13 SCP attach; refusing IAMScope collection" >&2
  exit 1
fi
echo "PASS: collection role assumption works after SCP attach"

echo ""
echo "Resources deployed:"
echo "  management_account_id : $MANAGEMENT_ACCOUNT_ID"
echo "  management_caller_arn : $MANAGEMENT_CALLER_ARN"
echo "  member_account_id     : $MEMBER_ACCOUNT_ID"
echo "  alice_arn             : $ALICE_ARN"
echo "  admin_arn             : $ADMIN_ARN"
echo "  collection_role_arn   : $COLLECTION_ROLE_ARN"
echo "  collection_role_name  : $COLLECTION_ROLE_NAME"
echo "  collection_role_assume_name: $COLLECTION_ROLE_ASSUME_NAME"
echo "  collection_principal_carveouts: $carveout_json"
echo "  scp_policy_id         : $SCP_POLICY_ID"
echo "  scp_policy_name       : $SCP_POLICY_NAME"

rm -rf "$OUTPUT_DIR"
mkdir -p "$OUTPUT_DIR"

echo ""
echo "--- iamscope collect with Organizations/SCP collection enabled ---"
iamscope collect \
  --profile "$MANAGEMENT_PROFILE" \
  --region "$AWS_REGION" \
  --accounts "$MEMBER_ACCOUNT_ID" \
  --role-name "$COLLECTION_ROLE_ASSUME_NAME" \
  --output "$OUTPUT_DIR"

FINDINGS_JSON="$OUTPUT_DIR/findings.json"
SCENARIO_JSON="$OUTPUT_DIR/scenario.json"
BINDING_METADATA_JSON="$OUTPUT_DIR/binding_metadata.json"
if [[ ! -f "$FINDINGS_JSON" || ! -f "$SCENARIO_JSON" || ! -f "$BINDING_METADATA_JSON" ]]; then
  echo "FAIL: expected collect artifacts missing under $OUTPUT_DIR" >&2
  exit 1
fi

ACCOUNTS_COLLECTED="$(jq -r '.metadata.accounts_collected // 0' "$SCENARIO_JSON")"
if [[ ! "$ACCOUNTS_COLLECTED" =~ ^[0-9]+$ || "$ACCOUNTS_COLLECTED" -le 0 ]]; then
  echo "FAIL: Env13 collection did not collect the member IAM graph (accounts_collected=$ACCOUNTS_COLLECTED)" >&2
  exit 1
fi

echo ""
echo "scenario.json written to $SCENARIO_JSON"
echo "binding_metadata.json written to $BINDING_METADATA_JSON"
echo "findings.json written to $FINDINGS_JSON"
echo "accounts_collected=$ACCOUNTS_COLLECTED"
