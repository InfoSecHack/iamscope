#!/usr/bin/env bash
set -u

usage() {
  cat <<'EOF'
Usage:
  scripts/check_env12_scp_prereqs.sh \
    --management-profile PROFILE \
    --member-profile PROFILE \
    --region REGION

Read-only preflight for the Env12 SCP benchmark. This script does not create,
attach, detach, or delete any AWS Organizations/IAM resources.
EOF
}

MANAGEMENT_PROFILE=""
MEMBER_PROFILE=""
REGION=""

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
    --member-profile)
      if [[ $# -lt 2 ]]; then
        echo "ERROR: --member-profile requires a value" >&2
        exit 2
      fi
      MEMBER_PROFILE="${2:-}"
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

missing=()
[[ -n "$MANAGEMENT_PROFILE" ]] || missing+=("--management-profile")
[[ -n "$MEMBER_PROFILE" ]] || missing+=("--member-profile")
[[ -n "$REGION" ]] || missing+=("--region")

if [[ ${#missing[@]} -gt 0 ]]; then
  echo "ERROR: missing required argument(s): ${missing[*]}" >&2
  usage >&2
  exit 2
fi

missing_prereqs=()
warnings=()
PYTHON_BIN=""

require_cli() {
  local name="$1"
  if ! command -v "$name" >/dev/null 2>&1; then
    missing_prereqs+=("required CLI not found: $name")
    return 1
  fi
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

echo "Env12 SCP benchmark prerequisite check"
echo "management_profile=$MANAGEMENT_PROFILE"
echo "member_profile=$MEMBER_PROFILE"
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

MANAGEMENT_ACCOUNT_ID=""
MEMBER_ACCOUNT_ID=""
ORG_ID=""
MEMBER_IN_ORG="false"
SCP_LIST_READABLE="false"
MEMBER_IAM_READABLE="false"

if command -v aws >/dev/null 2>&1 && [[ -n "$PYTHON_BIN" ]]; then
  mgmt_identity="$(aws_json "$MANAGEMENT_PROFILE" sts get-caller-identity)"
  if [[ $? -eq 0 ]]; then
    MANAGEMENT_ACCOUNT_ID="$(printf '%s' "$mgmt_identity" | extract_json_field Account || true)"
    [[ -n "$MANAGEMENT_ACCOUNT_ID" ]] || missing_prereqs+=("management profile returned an unparseable caller account ID")
  else
    missing_prereqs+=("management profile cannot call sts get-caller-identity: $mgmt_identity")
  fi

  member_identity="$(aws_json "$MEMBER_PROFILE" sts get-caller-identity)"
  if [[ $? -eq 0 ]]; then
    MEMBER_ACCOUNT_ID="$(printf '%s' "$member_identity" | extract_json_field Account || true)"
    [[ -n "$MEMBER_ACCOUNT_ID" ]] || missing_prereqs+=("member profile returned an unparseable caller account ID")
  else
    missing_prereqs+=("member profile cannot call sts get-caller-identity: $member_identity")
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
    if [[ -n "$MEMBER_ACCOUNT_ID" ]]; then
      if printf '%s' "$accounts_json" | "$PYTHON_BIN" -c '
import json
import sys

member_account_id = sys.argv[1]
data = json.load(sys.stdin)
accounts = data.get("Accounts", [])
sys.exit(0 if any(str(a.get("Id")) == member_account_id for a in accounts) else 1)
' "$MEMBER_ACCOUNT_ID"
      then
        MEMBER_IN_ORG="true"
      else
        missing_prereqs+=("member account is not visible in organizations list-accounts")
      fi
    fi
  else
    missing_prereqs+=("management profile cannot call organizations list-accounts: $accounts_json")
  fi

  scp_json="$(aws_json "$MANAGEMENT_PROFILE" organizations list-policies --filter SERVICE_CONTROL_POLICY)"
  if [[ $? -eq 0 ]]; then
    SCP_LIST_READABLE="true"
  else
    missing_prereqs+=("management profile cannot call organizations list-policies --filter SERVICE_CONTROL_POLICY: $scp_json")
  fi

  iam_summary="$(aws_json "$MEMBER_PROFILE" iam get-account-summary)"
  if [[ $? -eq 0 ]]; then
    MEMBER_IAM_READABLE="true"
  else
    missing_prereqs+=("member profile cannot call iam get-account-summary; Env12 member IAM build readiness is unproven: $iam_summary")
  fi
elif command -v aws >/dev/null 2>&1; then
  missing_prereqs+=("cannot parse AWS CLI JSON without python or python3")
fi

if [[ -n "$MANAGEMENT_ACCOUNT_ID" && -n "$MEMBER_ACCOUNT_ID" && "$MANAGEMENT_ACCOUNT_ID" == "$MEMBER_ACCOUNT_ID" ]]; then
  missing_prereqs+=("member profile resolves to the same account as management profile; Env12 requires a distinct dedicated member account")
fi

echo "management_account_id=${MANAGEMENT_ACCOUNT_ID:-UNKNOWN}"
echo "member_account_id=${MEMBER_ACCOUNT_ID:-UNKNOWN}"
echo "organization_id=${ORG_ID:-UNKNOWN}"
echo "member_account_visible_in_org=$MEMBER_IN_ORG"
echo "scp_policy_listing_readable=$SCP_LIST_READABLE"
echo "member_iam_readable=$MEMBER_IAM_READABLE"
echo

if [[ ${#warnings[@]} -gt 0 ]]; then
  echo "WARNINGS:"
  for warning in "${warnings[@]}"; do
    echo "- $warning"
  done
  echo
fi

if [[ ${#missing_prereqs[@]} -eq 0 ]]; then
  echo "Env12 live benchmark readiness: SAFE_TO_BUILD"
  echo "Read-only evidence is sufficient to start the Env12 build pass."
  exit 0
fi

echo "Env12 live benchmark readiness: NOT_READY"
echo "Missing prerequisites:"
for prereq in "${missing_prereqs[@]}"; do
  echo "- $prereq"
done
exit 1
