#!/usr/bin/env bash
set -u

usage() {
  cat <<'EOF'
Usage:
  scripts/check_env22_cross_account_prereqs.sh \
    --management-profile PROFILE \
    --caller-profile PROFILE \
    --target-profile PROFILE \
    --caller-account-id ACCOUNT_ID \
    --target-account-id ACCOUNT_ID \
    --region REGION

Read-only preflight for the Env22/Env23 cross-account trust benchmark
family. This script does not create IAM resources, run Terraform apply,
attach SCPs, or run IAMScope collection.

Arguments may also be provided through environment variables:
  MANAGEMENT_PROFILE, CALLER_PROFILE, TARGET_PROFILE,
  CALLER_ACCOUNT_ID, TARGET_ACCOUNT_ID, AWS_REGION
EOF
}

MANAGEMENT_PROFILE="${MANAGEMENT_PROFILE:-}"
CALLER_PROFILE="${CALLER_PROFILE:-}"
TARGET_PROFILE="${TARGET_PROFILE:-}"
CALLER_ACCOUNT_ID="${CALLER_ACCOUNT_ID:-}"
TARGET_ACCOUNT_ID="${TARGET_ACCOUNT_ID:-}"
REGION="${AWS_REGION:-}"

while [[ $# -gt 0 ]]; do
  case "$1" in
    --management-profile)
      if [[ $# -lt 2 ]]; then
        echo "ERROR: --management-profile requires a value" >&2
        exit 2
      fi
      MANAGEMENT_PROFILE="${2:-}"
      shift 2
      ;;
    --caller-profile)
      if [[ $# -lt 2 ]]; then
        echo "ERROR: --caller-profile requires a value" >&2
        exit 2
      fi
      CALLER_PROFILE="${2:-}"
      shift 2
      ;;
    --target-profile)
      if [[ $# -lt 2 ]]; then
        echo "ERROR: --target-profile requires a value" >&2
        exit 2
      fi
      TARGET_PROFILE="${2:-}"
      shift 2
      ;;
    --caller-account-id)
      if [[ $# -lt 2 ]]; then
        echo "ERROR: --caller-account-id requires a value" >&2
        exit 2
      fi
      CALLER_ACCOUNT_ID="${2:-}"
      shift 2
      ;;
    --target-account-id)
      if [[ $# -lt 2 ]]; then
        echo "ERROR: --target-account-id requires a value" >&2
        exit 2
      fi
      TARGET_ACCOUNT_ID="${2:-}"
      shift 2
      ;;
    --region)
      if [[ $# -lt 2 ]]; then
        echo "ERROR: --region requires a value" >&2
        exit 2
      fi
      REGION="${2:-}"
      shift 2
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    *)
      echo "ERROR: unknown argument: $1" >&2
      usage >&2
      exit 2
      ;;
  esac
done

missing_args=()
[[ -n "$MANAGEMENT_PROFILE" ]] || missing_args+=("--management-profile or MANAGEMENT_PROFILE")
[[ -n "$CALLER_PROFILE" ]] || missing_args+=("--caller-profile or CALLER_PROFILE")
[[ -n "$TARGET_PROFILE" ]] || missing_args+=("--target-profile or TARGET_PROFILE")
[[ -n "$CALLER_ACCOUNT_ID" ]] || missing_args+=("--caller-account-id or CALLER_ACCOUNT_ID")
[[ -n "$TARGET_ACCOUNT_ID" ]] || missing_args+=("--target-account-id or TARGET_ACCOUNT_ID")
[[ -n "$REGION" ]] || missing_args+=("--region or AWS_REGION")

if [[ ${#missing_args[@]} -gt 0 ]]; then
  echo "ERROR: missing required argument(s): ${missing_args[*]}" >&2
  usage >&2
  exit 2
fi

missing_prereqs=()
PYTHON_BIN=""

require_cli() {
  local name="$1"
  if ! command -v "$name" >/dev/null 2>&1; then
    missing_prereqs+=("required CLI not found: $name")
    return 1
  fi
}

valid_account_id() {
  [[ "$1" =~ ^[0-9]{12}$ ]]
}

extract_json_field() {
  local field="$1"
  "$PYTHON_BIN" -c '
import json
import sys

field = sys.argv[1]
try:
    data = json.load(sys.stdin)
except json.JSONDecodeError:
    sys.exit(1)

value = data
for part in field.split("."):
    if isinstance(value, dict) and part in value:
        value = value[part]
    else:
        sys.exit(1)
print(value)
' "$field"
}

aws_json() {
  aws --profile "$1" --region "$REGION" "${@:2}" --output json 2>&1
}

account_visible_and_active() {
  local accounts_json="$1"
  local account_id="$2"
  "$PYTHON_BIN" -c '
import json
import sys

account_id = sys.argv[1]
data = json.load(sys.stdin)
accounts = data.get("Accounts", [])
for account in accounts:
    if str(account.get("Id")) == account_id:
        sys.exit(0 if account.get("Status") == "ACTIVE" else 2)
sys.exit(1)
' "$account_id" <<<"$accounts_json"
}

echo "Env22 cross-account benchmark prerequisite check"
echo "management_profile=$MANAGEMENT_PROFILE"
echo "caller_profile=$CALLER_PROFILE"
echo "target_profile=$TARGET_PROFILE"
echo "caller_account_id_expected=$CALLER_ACCOUNT_ID"
echo "target_account_id_expected=$TARGET_ACCOUNT_ID"
echo "region=$REGION"
echo

require_cli aws || true
require_cli terraform || true
if command -v python >/dev/null 2>&1; then
  PYTHON_BIN="python"
elif command -v python3 >/dev/null 2>&1; then
  PYTHON_BIN="python3"
else
  missing_prereqs+=("required CLI not found: python or python3")
fi

valid_account_id "$CALLER_ACCOUNT_ID" || missing_prereqs+=("caller account ID must be 12 digits: $CALLER_ACCOUNT_ID")
valid_account_id "$TARGET_ACCOUNT_ID" || missing_prereqs+=("target account ID must be 12 digits: $TARGET_ACCOUNT_ID")
if [[ "$CALLER_ACCOUNT_ID" == "$TARGET_ACCOUNT_ID" ]]; then
  missing_prereqs+=("caller and target account IDs must be different")
fi

MANAGEMENT_ACCOUNT_ID=""
MANAGEMENT_CALLER_ARN=""
CALLER_PROFILE_ACCOUNT_ID=""
CALLER_PROFILE_ARN=""
TARGET_PROFILE_ACCOUNT_ID=""
TARGET_PROFILE_ARN=""
ORG_ID=""
CALLER_VISIBLE_IN_ORG="false"
TARGET_VISIBLE_IN_ORG="false"
CALLER_IAM_READABLE="false"
TARGET_IAM_READABLE="false"

if command -v aws >/dev/null 2>&1 && [[ -n "$PYTHON_BIN" ]]; then
  mgmt_identity="$(aws_json "$MANAGEMENT_PROFILE" sts get-caller-identity)"
  if [[ $? -eq 0 ]]; then
    MANAGEMENT_ACCOUNT_ID="$(printf '%s' "$mgmt_identity" | extract_json_field Account || true)"
    MANAGEMENT_CALLER_ARN="$(printf '%s' "$mgmt_identity" | extract_json_field Arn || true)"
    [[ -n "$MANAGEMENT_ACCOUNT_ID" ]] || missing_prereqs+=("management profile returned an unparseable caller account ID")
    [[ -n "$MANAGEMENT_CALLER_ARN" ]] || missing_prereqs+=("management profile returned an unparseable caller ARN")
  else
    missing_prereqs+=("management profile cannot call sts get-caller-identity: $mgmt_identity")
  fi

  caller_identity="$(aws_json "$CALLER_PROFILE" sts get-caller-identity)"
  if [[ $? -eq 0 ]]; then
    CALLER_PROFILE_ACCOUNT_ID="$(printf '%s' "$caller_identity" | extract_json_field Account || true)"
    CALLER_PROFILE_ARN="$(printf '%s' "$caller_identity" | extract_json_field Arn || true)"
    [[ -n "$CALLER_PROFILE_ACCOUNT_ID" ]] || missing_prereqs+=("caller profile returned an unparseable caller account ID")
    [[ -n "$CALLER_PROFILE_ARN" ]] || missing_prereqs+=("caller profile returned an unparseable caller ARN")
  else
    missing_prereqs+=("caller profile cannot call sts get-caller-identity: $caller_identity")
  fi

  target_identity="$(aws_json "$TARGET_PROFILE" sts get-caller-identity)"
  if [[ $? -eq 0 ]]; then
    TARGET_PROFILE_ACCOUNT_ID="$(printf '%s' "$target_identity" | extract_json_field Account || true)"
    TARGET_PROFILE_ARN="$(printf '%s' "$target_identity" | extract_json_field Arn || true)"
    [[ -n "$TARGET_PROFILE_ACCOUNT_ID" ]] || missing_prereqs+=("target profile returned an unparseable caller account ID")
    [[ -n "$TARGET_PROFILE_ARN" ]] || missing_prereqs+=("target profile returned an unparseable caller ARN")
  else
    missing_prereqs+=("target profile cannot call sts get-caller-identity: $target_identity")
  fi

  if [[ -n "$CALLER_PROFILE_ACCOUNT_ID" && "$CALLER_PROFILE_ACCOUNT_ID" != "$CALLER_ACCOUNT_ID" ]]; then
    missing_prereqs+=("caller profile resolves to $CALLER_PROFILE_ACCOUNT_ID, expected $CALLER_ACCOUNT_ID")
  fi
  if [[ -n "$TARGET_PROFILE_ACCOUNT_ID" && "$TARGET_PROFILE_ACCOUNT_ID" != "$TARGET_ACCOUNT_ID" ]]; then
    missing_prereqs+=("target profile resolves to $TARGET_PROFILE_ACCOUNT_ID, expected $TARGET_ACCOUNT_ID")
  fi
  if [[ -n "$CALLER_PROFILE_ACCOUNT_ID" && -n "$TARGET_PROFILE_ACCOUNT_ID" && "$CALLER_PROFILE_ACCOUNT_ID" == "$TARGET_PROFILE_ACCOUNT_ID" ]]; then
    missing_prereqs+=("caller and target profiles resolve to the same account; Env22 requires two accounts")
  fi

  org_desc="$(aws_json "$MANAGEMENT_PROFILE" organizations describe-organization)"
  if [[ $? -eq 0 ]]; then
    ORG_ID="$(printf '%s' "$org_desc" | extract_json_field Organization.Id || true)"
    [[ -n "$ORG_ID" ]] || missing_prereqs+=("management profile returned an unparseable organization ID")
  else
    missing_prereqs+=("management profile cannot call organizations describe-organization: $org_desc")
  fi

  accounts_json="$(aws_json "$MANAGEMENT_PROFILE" organizations list-accounts)"
  if [[ $? -eq 0 ]]; then
    if account_visible_and_active "$accounts_json" "$CALLER_ACCOUNT_ID"; then
      CALLER_VISIBLE_IN_ORG="true"
    else
      rc=$?
      if [[ $rc -eq 2 ]]; then
        missing_prereqs+=("caller account $CALLER_ACCOUNT_ID is visible in Organizations but is not ACTIVE")
      else
        missing_prereqs+=("caller account $CALLER_ACCOUNT_ID is not visible in organizations list-accounts")
      fi
    fi

    if account_visible_and_active "$accounts_json" "$TARGET_ACCOUNT_ID"; then
      TARGET_VISIBLE_IN_ORG="true"
    else
      rc=$?
      if [[ $rc -eq 2 ]]; then
        missing_prereqs+=("target account $TARGET_ACCOUNT_ID is visible in Organizations but is not ACTIVE")
      else
        missing_prereqs+=("target account $TARGET_ACCOUNT_ID is not visible in organizations list-accounts")
      fi
    fi
  else
    missing_prereqs+=("management profile cannot call organizations list-accounts: $accounts_json")
  fi

  caller_iam_summary="$(aws_json "$CALLER_PROFILE" iam get-account-summary)"
  if [[ $? -eq 0 ]]; then
    CALLER_IAM_READABLE="true"
  else
    missing_prereqs+=("caller profile cannot call iam get-account-summary; caller-side IAM setup/read readiness is unproven: $caller_iam_summary")
  fi

  target_iam_summary="$(aws_json "$TARGET_PROFILE" iam get-account-summary)"
  if [[ $? -eq 0 ]]; then
    TARGET_IAM_READABLE="true"
  else
    missing_prereqs+=("target profile cannot call iam get-account-summary; target-side IAM setup/read readiness is unproven: $target_iam_summary")
  fi
elif command -v aws >/dev/null 2>&1; then
  missing_prereqs+=("cannot parse AWS CLI JSON without python or python3")
fi

echo "management_account_id=${MANAGEMENT_ACCOUNT_ID:-UNKNOWN}"
echo "management_caller_arn=${MANAGEMENT_CALLER_ARN:-UNKNOWN}"
echo "caller_profile_account_id=${CALLER_PROFILE_ACCOUNT_ID:-UNKNOWN}"
echo "caller_profile_arn=${CALLER_PROFILE_ARN:-UNKNOWN}"
echo "target_profile_account_id=${TARGET_PROFILE_ACCOUNT_ID:-UNKNOWN}"
echo "target_profile_arn=${TARGET_PROFILE_ARN:-UNKNOWN}"
echo "organization_id=${ORG_ID:-UNKNOWN}"
echo "caller_account_visible_and_active_in_org=$CALLER_VISIBLE_IN_ORG"
echo "target_account_visible_and_active_in_org=$TARGET_VISIBLE_IN_ORG"
echo "caller_iam_readable=$CALLER_IAM_READABLE"
echo "target_iam_readable=$TARGET_IAM_READABLE"
echo

if [[ ${#missing_prereqs[@]} -eq 0 ]]; then
  echo "Env22 cross-account benchmark readiness: SAFE_TO_BUILD"
  echo "Read-only evidence is sufficient to start the Env22 build pass."
  exit 0
fi

echo "Env22 cross-account benchmark readiness: NOT_READY"
echo "Missing prerequisites:"
for prereq in "${missing_prereqs[@]}"; do
  echo "- $prereq"
done
exit 1
