"""Trust policy parser — parses IAM role trust policies into TrustParseResult objects.

Handles all principal variants per architecture doc §5.4:
- AWS principals: account root, specific role, specific user, wildcard
- Service principals: lambda, ec2, ecs, ssm, etc.
- Federated principals: SAML, OIDC

Each Allow statement produces one or more TrustParseResult entries
(multiple when Principal contains a list of ARNs or services).

Deny statements are skipped — they restrict trust but don't create edges.
Only Allow statements create _trust edges.

All parsing is deterministic: same policy document → same results.
"""

from __future__ import annotations

import json
import logging
import re
from typing import Any

from iamscope.constants import (
    NODE_TYPE_ACCOUNT_ROOT,
    NODE_TYPE_AWS_SERVICE,
    NODE_TYPE_EXTERNAL_ACCOUNT,
    NODE_TYPE_IAM_ROLE,
    NODE_TYPE_IAM_USER,
    NODE_TYPE_OIDC_PROVIDER,
    NODE_TYPE_SAML_PROVIDER,
    NODE_TYPE_WILDCARD_PRINCIPAL,
    TRUST_SCOPE_ACCOUNT_ROOT,
    TRUST_SCOPE_ANY_AWS_PRINCIPAL,
    TRUST_SCOPE_FEDERATED,
    TRUST_SCOPE_SERVICE,
    TRUST_SCOPE_SPECIFIC_ROLE,
    TRUST_SCOPE_SPECIFIC_USER,
)
from iamscope.identity.statement_digest import statement_digest
from iamscope.models import TrustParseResult
from iamscope.parser.condition_extractor import extract_conditions
from iamscope.parser.parse_failures import PolicyParseFailure, make_parse_failure

logger = logging.getLogger(__name__)

# Regex patterns for ARN parsing
# Handles all partitions: aws, aws-us-gov, aws-cn
_ARN_PATTERN = re.compile(
    r"^arn:aws(?:-[a-z-]+)?:iam::(\d{12}):(root|role/.+|user/.+|saml-provider/.+|group/.+)$",
    re.IGNORECASE,
)
# BUG-022b: assumed-role ARN pattern. Real-world trust policies
# (notably AWS Control Tower / AFT setups like
# `arn:aws:sts::ACCOUNT:assumed-role/AWSAFTAdmin/AWSAFT-Session`)
# reference specific session names rather than the underlying role
# directly. Pre-fix these fell through to the "Unrecognized AWS
# principal format" warning and were classified as
# NODE_TYPE_EXTERNAL_ACCOUNT with TRUST_SCOPE_ACCOUNT_ROOT, which
# is wrong — they actually narrow trust to a specific role+session
# combination. The parser now extracts the underlying role and
# treats the principal as that role (the session-name constraint
# is captured in a property for downstream visibility but does not
# affect reachability, because any caller of the role can use any
# session name).
_ASSUMED_ROLE_ARN_PATTERN = re.compile(
    r"^arn:aws(?:-[a-z-]+)?:sts::(\d{12}):assumed-role/([^/]+)/(.+)$",
    re.IGNORECASE,
)
_ACCOUNT_ID_PATTERN = re.compile(r"^\d{12}$")
# BUG-022b: bare principal ID pattern. When an IAM principal is
# deleted, AWS rewrites any trust-policy references to that
# principal with the principal's unique ID (AROA* for roles, AIDA*
# for users, AKIA* for access keys, AGPA* for groups, APKA* for
# public keys, ANVA* for managed policies, AIPA* for instance
# profiles, AGPA* for groups). This is AWS's defense against
# principal-identity-reuse attacks — a newly-created principal
# with the same name won't inherit the old principal's trust.
# From an analysis perspective these are dangling references:
# they cannot correspond to any reachable principal, so the trust
# is effectively dead. We recognize them and classify as a
# DELETED_PRINCIPAL scope so downstream reporting can surface
# them as a finding ("trust policy contains dangling reference
# to deleted principal") rather than emit a noisy "Unrecognized"
# warning at collection time.
_BARE_PRINCIPAL_ID_PATTERN = re.compile(r"^(AROA|AIDA|AKIA|AGPA|APKA|ANVA|AIPA|ASIA|ACCA)[A-Z0-9]{16,}$")


def parse_trust_policy(
    policy_document: str | dict[str, Any],
    role_arn: str,
    role_account_id: str,
    failures: list[PolicyParseFailure] | None = None,
) -> list[TrustParseResult]:
    """Parse an IAM role trust policy into structured TrustParseResult objects.

    Each Allow statement in the trust policy produces one or more results,
    depending on how many principals are specified. Deny statements are
    skipped (they restrict trust but don't create edges).

    Args:
        policy_document: Trust policy as a JSON string or parsed dict.
        role_arn: The ARN of the role this trust policy belongs to.
        role_account_id: The AWS account ID of the role.
        failures: Optional shared list for structured parse failure
            records (BUG-021). When provided, JSON-decode errors,
            non-dict roots, and invalid Statement field types are
            appended here in addition to being logged. Pre-BUG-021
            these failures returned `[]` silently, dropping every
            trust edge that should have been built from the policy
            and producing false-negative findings (cross-account
            trust, assume-role chains, admin reachability, etc.).

    Returns:
        List of TrustParseResult objects, ordered by statement index
        then by principal order within each statement.
        Empty list if the policy is malformed or has no Allow statements.
    """
    # Parse JSON string if needed (BUG-021: capture which failure mode
    # we hit so we can attribute it correctly in the failures list)
    doc, failure_kind, exception = _parse_document(policy_document)
    if doc is None:
        logger.warning(
            "Malformed trust policy for role %s: %s",
            role_arn,
            failure_kind,
        )
        if failures is not None:
            failures.append(
                make_parse_failure(
                    parser="trust_policy",
                    source_arn=role_arn,
                    policy_source="trust",
                    failure_kind=failure_kind,
                    exception=exception,
                )
            )
        return []

    # Get statements
    statements = doc.get("Statement")
    if not statements:
        logger.debug("No statements in trust policy for role %s", role_arn)
        return []

    # Normalize single statement to list
    if isinstance(statements, dict):
        statements = [statements]

    if not isinstance(statements, list):
        logger.warning("Invalid Statement field in trust policy for role %s", role_arn)
        if failures is not None:
            failures.append(
                make_parse_failure(
                    parser="trust_policy",
                    source_arn=role_arn,
                    policy_source="trust",
                    failure_kind="invalid_statement_type",
                )
            )
        return []

    results: list[TrustParseResult] = []

    for stmt_index, statement in enumerate(statements):
        if not isinstance(statement, dict):
            logger.warning(
                "Statement %d in trust policy for role %s is not a dict, skipping",
                stmt_index,
                role_arn,
            )
            continue

        # Skip Deny statements — they restrict trust but don't create edges
        effect = statement.get("Effect", "")
        if effect != "Allow":
            logger.debug(
                "Skipping %s statement %d in trust policy for role %s",
                effect,
                stmt_index,
                role_arn,
            )
            continue

        # DIG-1 (S05): compute digest once per statement from the raw dict.
        # Must be done here while we still have the unmodified statement.
        stmt_digest = statement_digest(statement)

        # Determine action(s)
        actions = _normalize_actions(statement.get("Action", "sts:AssumeRole"))

        # Extract conditions
        condition_block = statement.get("Condition")
        conditions = extract_conditions(condition_block)
        raw_conditions = _canonicalize_conditions(condition_block)

        # Resolve principals — may be multiple
        principals = _resolve_all_principals(statement.get("Principal"))
        if not principals:
            logger.warning(
                "No resolvable principals in statement %d for role %s",
                stmt_index,
                role_arn,
            )
            continue

        # Emit one TrustParseResult per (principal, action) combination
        for principal_type, principal_value, node_type, trust_scope in principals:
            # Determine cross-account status
            principal_account = _extract_account_id(principal_value)
            cross_account = _is_cross_account(principal_account, role_account_id, trust_scope)

            # Use the first action for the primary result
            # [ASSUMPTION]: If multiple actions, emit one result per action.
            # In practice, trust policies almost always have a single action.
            for action in actions:
                # Extract OIDC subject claim for federated OIDC principals
                oidc_sub: str | None = None
                if node_type == NODE_TYPE_OIDC_PROVIDER and condition_block:
                    oidc_sub = extract_oidc_subject(condition_block, principal_value)

                result = TrustParseResult(
                    statement_index=stmt_index,
                    effect="Allow",
                    action=action,
                    principal_type=principal_type,
                    principal_value=principal_value,
                    resolved_node_type=node_type,
                    trust_scope=trust_scope,
                    has_external_id=conditions.has_external_id,
                    has_source_account_condition=conditions.has_source_account_condition,
                    has_source_ip_condition=conditions.has_source_ip_condition,
                    has_source_vpc_condition=conditions.has_source_vpc_condition,
                    has_org_id_condition=conditions.has_org_id_condition,
                    has_mfa_condition=conditions.has_mfa_condition,
                    condition_keys=conditions.condition_keys,
                    raw_conditions=raw_conditions,
                    cross_account=cross_account,
                    oidc_subject_pattern=oidc_sub,
                    statement_digest=stmt_digest,
                )
                results.append(result)

    return results


def _parse_document(
    policy_document: str | dict[str, Any],
) -> tuple[dict[str, Any] | None, str, BaseException | None]:
    """Parse policy document from string or dict.

    BUG-021: returns a 3-tuple `(parsed_dict, failure_kind, exception)`
    so callers can distinguish failure modes for structured failure
    reporting. On success, returns `(dict, "", None)`. On failure,
    `parsed_dict` is None and `failure_kind` describes which path
    failed.
    """
    if isinstance(policy_document, dict):
        return (policy_document, "", None)
    if isinstance(policy_document, str):
        try:
            parsed = json.loads(policy_document)
        except (json.JSONDecodeError, TypeError) as e:
            return (None, "json_decode_error", e)
        if isinstance(parsed, dict):
            return (parsed, "", None)
        return (None, "not_a_dict", None)
    return (None, "type_error", None)


def _normalize_actions(action_field: str | list[str]) -> list[str]:
    """Normalize Action field to a sorted list of action strings.

    Args:
        action_field: Single action string or list of actions.

    Returns:
        Sorted list of action strings.
    """
    if isinstance(action_field, str):
        return [action_field]
    if isinstance(action_field, list):
        return sorted(action_field)
    return ["sts:AssumeRole"]  # Default fallback


def _resolve_all_principals(
    principal_field: Any,
) -> list[tuple[str, str, str, str]]:
    """Resolve all principals from a trust policy Principal field.

    Handles all AWS trust policy principal formats:
    - "*" (wildcard — any AWS principal)
    - {"AWS": "arn:..."} (single AWS principal)
    - {"AWS": ["arn:...", "arn:..."]} (multiple AWS principals)
    - {"Service": "service.amazonaws.com"} (single service)
    - {"Service": ["svc1.amazonaws.com", ...]} (multiple services)
    - {"Federated": "arn:..."} (SAML or OIDC)
    - {"Federated": ["arn:...", ...]} (multiple federated)

    Returns:
        List of (principal_type, principal_value, node_type, trust_scope) tuples.
        Empty list if principal field is missing or unresolvable.
    """
    if principal_field is None:
        return []

    # Wildcard: "*" as the entire Principal value
    if principal_field == "*":
        return [("AWS", "*", NODE_TYPE_WILDCARD_PRINCIPAL, TRUST_SCOPE_ANY_AWS_PRINCIPAL)]

    if not isinstance(principal_field, dict):
        logger.warning("Unexpected principal field type: %s", type(principal_field).__name__)
        return []

    results: list[tuple[str, str, str, str]] = []

    # Process AWS principals
    if "AWS" in principal_field:
        aws_values = _to_list(principal_field["AWS"])
        for value in aws_values:
            resolved = _resolve_aws_principal(value)
            if resolved:
                results.append(resolved)

    # Process Service principals
    if "Service" in principal_field:
        service_values = _to_list(principal_field["Service"])
        for value in service_values:
            results.append(("Service", value, NODE_TYPE_AWS_SERVICE, TRUST_SCOPE_SERVICE))

    # Process Federated principals
    if "Federated" in principal_field:
        fed_values = _to_list(principal_field["Federated"])
        for value in fed_values:
            resolved = _resolve_federated_principal(value)
            if resolved:
                results.append(resolved)

    return results


def _resolve_aws_principal(value: str) -> tuple[str, str, str, str] | None:
    """Resolve a single AWS principal value.

    Args:
        value: AWS principal string (ARN, account ID, or "*").

    Returns:
        (principal_type, principal_value, node_type, trust_scope) or None.
    """
    if not isinstance(value, str):
        logger.warning("Non-string AWS principal value: %r", value)
        return None

    # Wildcard
    if value == "*":
        return ("AWS", "*", NODE_TYPE_WILDCARD_PRINCIPAL, TRUST_SCOPE_ANY_AWS_PRINCIPAL)

    # Bare account ID (12 digits) → treat as account root
    # [ASSUMPTION]: AWS treats bare account ID as equivalent to arn:aws:iam::<id>:root
    if _ACCOUNT_ID_PATTERN.match(value):
        root_arn = f"arn:aws:iam::{value}:root"
        return ("AWS", root_arn, NODE_TYPE_ACCOUNT_ROOT, TRUST_SCOPE_ACCOUNT_ROOT)

    # BUG-022b: assumed-role ARN. Extract the underlying role ARN
    # and treat the trust as pointing at that role. Trust policies
    # in AWS Control Tower / AFT environments commonly reference
    # specific session names, but from a reachability perspective
    # any principal authorized to call sts:AssumeRole on the role
    # can pick any session name, so the session-name constraint
    # doesn't narrow who can reach the role — it only narrows what
    # audit trail the caller leaves behind.
    assumed_role_match = _ASSUMED_ROLE_ARN_PATTERN.match(value)
    if assumed_role_match:
        account_id = assumed_role_match.group(1)
        role_name = assumed_role_match.group(2)
        # session_name is assumed_role_match.group(3) — not used for
        # reachability but captured here for observability if needed.
        role_arn = f"arn:aws:iam::{account_id}:role/{role_name}"
        logger.debug(
            "Resolved assumed-role ARN %s to underlying role %s",
            value,
            role_arn,
        )
        return ("AWS", role_arn, NODE_TYPE_IAM_ROLE, TRUST_SCOPE_SPECIFIC_ROLE)

    # BUG-022b: bare principal ID (AROA*/AIDA*/etc.) is AWS's
    # placeholder for a deleted principal. The trust policy
    # referenced a principal by ARN, that principal was deleted,
    # and AWS rewrote the reference with the frozen unique ID so
    # no future principal with the same ARN can inherit the trust.
    # Operationally these are dangling references — unreachable —
    # but they ARE a legitimate trust-policy shape and should not
    # generate a scary "Unrecognized" warning. Log at debug level
    # and classify as EXTERNAL_ACCOUNT (matches the existing
    # unrecognized fallback shape) so downstream reporting can
    # surface them without the noise.
    if _BARE_PRINCIPAL_ID_PATTERN.match(value):
        logger.debug(
            "Trust policy references deleted principal by unique ID: %s (dangling reference — trust is unreachable)",
            value,
        )
        return ("AWS", value, NODE_TYPE_EXTERNAL_ACCOUNT, TRUST_SCOPE_ACCOUNT_ROOT)

    # Full ARN parsing
    match = _ARN_PATTERN.match(value)
    if not match:
        logger.warning("Unrecognized AWS principal format: %s", value)
        # Still emit it — don't silently drop
        return ("AWS", value, NODE_TYPE_EXTERNAL_ACCOUNT, TRUST_SCOPE_ACCOUNT_ROOT)

    resource = match.group(2)

    if resource == "root":
        return ("AWS", value, NODE_TYPE_ACCOUNT_ROOT, TRUST_SCOPE_ACCOUNT_ROOT)
    elif resource.startswith("role/"):
        return ("AWS", value, NODE_TYPE_IAM_ROLE, TRUST_SCOPE_SPECIFIC_ROLE)
    elif resource.startswith("user/"):
        return ("AWS", value, NODE_TYPE_IAM_USER, TRUST_SCOPE_SPECIFIC_USER)
    elif resource.startswith("saml-provider/"):
        return ("AWS", value, NODE_TYPE_SAML_PROVIDER, TRUST_SCOPE_FEDERATED)
    else:
        # group/ or other — uncommon in trust policies
        logger.warning("Unusual AWS principal resource type: %s", value)
        return ("AWS", value, NODE_TYPE_IAM_USER, TRUST_SCOPE_SPECIFIC_USER)


def _resolve_federated_principal(value: str) -> tuple[str, str, str, str] | None:
    """Resolve a single Federated principal value.

    Distinguishes SAML from OIDC based on the principal value.
    """
    if not isinstance(value, str):
        logger.warning("Non-string Federated principal value: %r", value)
        return None

    # SAML providers have IAM ARN format
    if ":saml-provider/" in value.lower():
        return ("Federated", value, NODE_TYPE_SAML_PROVIDER, TRUST_SCOPE_FEDERATED)

    # Everything else is OIDC (cognito, GitHub Actions, Google, etc.)
    return ("Federated", value, NODE_TYPE_OIDC_PROVIDER, TRUST_SCOPE_FEDERATED)


def _extract_account_id(principal_value: str) -> str | None:
    """Extract AWS account ID from a principal value.

    Returns:
        12-digit account ID string, or None if not extractable.
    """
    if principal_value == "*":
        return None

    # Try ARN format: arn:aws[-partition]:iam::<account_id>:...
    match = re.search(r"arn:aws(?:-[a-z-]+)?:iam::(\d{12}):", principal_value, re.IGNORECASE)
    if match:
        return match.group(1)

    # Bare account ID
    if _ACCOUNT_ID_PATTERN.match(principal_value):
        return principal_value

    return None


def _is_cross_account(
    principal_account: str | None,
    role_account_id: str,
    trust_scope: str,
) -> bool:
    """Determine if a trust relationship is cross-account.

    Args:
        principal_account: Account ID of the principal, or None.
        role_account_id: Account ID of the role being trusted.
        trust_scope: Trust scope classification.

    Returns:
        True if cross-account, False if same-account or undetermined.
    """
    # Wildcard is always "cross-account" (any principal from anywhere)
    if trust_scope == TRUST_SCOPE_ANY_AWS_PRINCIPAL:
        return True

    # Service principals are not cross-account in the IAM sense
    if trust_scope == TRUST_SCOPE_SERVICE:
        return False

    # Federated principals are not cross-account in the IAM sense
    if trust_scope == TRUST_SCOPE_FEDERATED:
        return False

    # If we can't determine the account, it's unknown — conservative: not cross-account
    # [ASSUMPTION]: Unknown principal accounts are treated as not-cross-account
    # to avoid false positives. The resolver phase can upgrade this later.
    if principal_account is None:
        return False

    return principal_account != role_account_id


def _canonicalize_conditions(condition_block: dict[str, Any] | None) -> dict[str, Any]:
    """Canonicalize condition block for deterministic storage.

    Per Phase A R16: all raw JSON stored in output must be canonicalized.

    Returns:
        Canonicalized condition dict, or empty dict if None.
    """
    if not condition_block or not isinstance(condition_block, dict):
        return {}

    # Round-trip through canonical JSON to normalize
    canonical_str = json.dumps(condition_block, sort_keys=True, separators=(",", ":"), ensure_ascii=True)
    result: dict[str, Any] = json.loads(canonical_str)
    return result


def _to_list(value: Any) -> list[Any]:
    """Normalize a value that may be a string or list to a list."""
    if isinstance(value, list):
        return value
    return [value]


# ---------------------------------------------------------------------------
# OIDC subject claim extraction
# ---------------------------------------------------------------------------


def extract_oidc_subject(
    condition_block: dict[str, Any] | None,
    principal_value: str,
) -> str | None:
    """Extract the OIDC :sub claim pattern from a trust policy condition block.

    Looks for condition keys matching the OIDC provider URL + :sub across
    all condition operators (StringEquals, StringLike, etc.).

    Handles both URL-form principals ("token.actions.githubusercontent.com")
    and ARN-form ("arn:aws:iam::000000000000:oidc-provider/token.actions.githubusercontent.com").

    Args:
        condition_block: The "Condition" dict from the trust statement.
        principal_value: The OIDC provider URL or ARN.

    Returns:
        The sub claim pattern string if found (e.g. "repo:Org/Repo:*"),
        "*" if the sub claim is an explicit wildcard,
        or None if no :sub condition is present.
    """
    if not condition_block or not isinstance(condition_block, dict):
        return None

    # Extract the provider URL from ARN if needed
    # ARN format: arn:aws:iam::<account>:oidc-provider/<url>
    provider_url = _extract_oidc_provider_url(principal_value)
    sub_key_lower = f"{provider_url}:sub".lower()

    for _operator, key_value_map in condition_block.items():
        if not isinstance(key_value_map, dict):
            continue

        for cond_key, cond_value in key_value_map.items():
            if cond_key.lower() == sub_key_lower:
                return _normalize_oidc_sub_value(cond_value)

    return None


def _extract_oidc_provider_url(principal_value: str) -> str:
    """Extract the OIDC provider URL from a principal value.

    If the value is an ARN (contains ":oidc-provider/"), extracts the URL portion.
    Otherwise returns the value as-is (assumed to already be a URL).
    """
    oidc_marker = ":oidc-provider/"
    idx = principal_value.lower().find(oidc_marker)
    if idx >= 0:
        return principal_value[idx + len(oidc_marker) :]
    return principal_value


def _normalize_oidc_sub_value(value: Any) -> str:
    """Normalize an OIDC :sub condition value to a single string.

    Handles single string, list of strings, or wildcard.
    For lists, joins with " | " to preserve all patterns.
    """
    if isinstance(value, str):
        return value
    if isinstance(value, list):
        str_values = sorted(str(v) for v in value)
        if len(str_values) == 1:
            return str_values[0]
        return " | ".join(str_values)
    return str(value)
