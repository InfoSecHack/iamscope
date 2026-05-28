"""Condition key extraction and classification from IAM policy conditions.

Extracts structured boolean flags and condition key lists from
IAM policy Condition blocks. Used by trust policy parser and
(future) SCP parser.

Known condition keys are classified into semantic categories.
Unknown keys are preserved in raw form and flagged.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from iamscope.constants import KNOWN_CONDITION_KEYS


@dataclass
class ConditionSet:
    """Structured condition extraction result.

    Boolean flags indicate presence of specific condition key categories.
    condition_keys lists all condition keys found (sorted for determinism).
    unknown_keys lists keys not in KNOWN_CONDITION_KEYS.
    """

    has_external_id: bool = False
    has_source_account_condition: bool = False
    has_source_ip_condition: bool = False
    has_source_vpc_condition: bool = False
    has_org_id_condition: bool = False
    has_mfa_condition: bool = False
    # COND-1 additions: condition keys that distinguish "PassRole to Lambda
    # specifically" from "PassRole to anything." Added in S02 to unblock the
    # passrole_lambda reasoner's check-8 evaluation of iam:PassedToService.
    has_passed_to_service_condition: bool = False
    has_associated_resource_arn_condition: bool = False
    has_principal_tag_condition: bool = False
    has_request_tag_condition: bool = False
    has_resource_account_condition: bool = False
    has_resource_org_id_condition: bool = False
    condition_keys: list[str] = field(default_factory=list)
    unknown_keys: list[str] = field(default_factory=list)


# Mapping from condition key → (attribute_name, flag_value)
# Each entry maps a condition key to the ConditionSet boolean field it sets.
_CONDITION_KEY_FLAGS: dict[str, str] = {
    "sts:ExternalId": "has_external_id",
    "sts:externalid": "has_external_id",
    "aws:SourceAccount": "has_source_account_condition",
    "aws:sourceaccount": "has_source_account_condition",
    "aws:SourceIp": "has_source_ip_condition",
    "aws:sourceip": "has_source_ip_condition",
    "aws:VpcSourceIp": "has_source_ip_condition",
    "aws:vpcsourceip": "has_source_ip_condition",
    "aws:SourceVpc": "has_source_vpc_condition",
    "aws:sourcevpc": "has_source_vpc_condition",
    "aws:SourceVpce": "has_source_vpc_condition",
    "aws:sourcevpce": "has_source_vpc_condition",
    "aws:PrincipalOrgID": "has_org_id_condition",
    "aws:principalorgid": "has_org_id_condition",
    "aws:MultiFactorAuthPresent": "has_mfa_condition",
    "aws:multifactorauthpresent": "has_mfa_condition",
    "aws:MultiFactorAuthAge": "has_mfa_condition",
    "aws:multifactorauthage": "has_mfa_condition",
    # COND-1 additions (S02):
    "iam:PassedToService": "has_passed_to_service_condition",
    "iam:passedtoservice": "has_passed_to_service_condition",
    "iam:AssociatedResourceArn": "has_associated_resource_arn_condition",
    "iam:associatedresourcearn": "has_associated_resource_arn_condition",
    "aws:PrincipalTag": "has_principal_tag_condition",
    "aws:principaltag": "has_principal_tag_condition",
    "aws:RequestTag": "has_request_tag_condition",
    "aws:requesttag": "has_request_tag_condition",
    "aws:ResourceAccount": "has_resource_account_condition",
    "aws:resourceaccount": "has_resource_account_condition",
    "aws:ResourceOrgID": "has_resource_org_id_condition",
    "aws:resourceorgid": "has_resource_org_id_condition",
}

# COND-1 prefix matching: real-world tag condition keys always carry a
# tag-name suffix (aws:PrincipalTag/Team, aws:RequestTag/Environment).
# Keys in this dict are matched case-insensitively via str.startswith()
# against the lowered condition key. Exact-match (bare aws:PrincipalTag)
# is handled by _CONDITION_KEY_FLAGS above.
_CONDITION_KEY_PREFIXES: dict[str, str] = {
    "aws:principaltag/": "has_principal_tag_condition",
    "aws:requesttag/": "has_request_tag_condition",
}

# Condition keys that are known but don't set a boolean flag
# (informational only — logged in condition_keys but no flag)
_KNOWN_INFORMATIONAL_KEYS: set[str] = {
    "sts:RoleSessionName",
    "aws:PrincipalArn",
    "aws:PrincipalTag",
    "aws:RequestedRegion",
    "aws:TokenIssueTime",
    # SAML/OIDC-specific keys — known, no dedicated flag
    "SAML:aud",
    "SAML:iss",
    "SAML:sub",
    "SAML:sub_type",
    "SAML:edupersonorgdn",
    "cognito-identity.amazonaws.com:aud",
    "cognito-identity.amazonaws.com:amr",
    "cognito-identity.amazonaws.com:sub",
    "accounts.google.com:aud",
    "accounts.google.com:sub",
    "graph.facebook.com:id",
    "www.amazon.com:user_id",
    "www.amazon.com:app_id",
    "token.actions.githubusercontent.com:sub",
    "token.actions.githubusercontent.com:aud",
}


def extract_conditions(condition_block: dict[str, Any] | None) -> ConditionSet:
    """Extract structured condition information from an IAM Condition block.

    Processes all condition operators (StringEquals, StringNotEquals,
    ArnLike, ArnNotLike, IpAddress, Bool, etc.) and extracts the
    condition keys used, regardless of operator.

    Args:
        condition_block: The "Condition" dict from an IAM policy statement,
                        or None if no conditions are present.

    Returns:
        ConditionSet with boolean flags set and condition_keys populated.
        If condition_block is None or empty, returns a default ConditionSet
        with all flags False and empty lists.
    """
    result = ConditionSet()

    if not condition_block or not isinstance(condition_block, dict):
        return result

    all_keys: set[str] = set()
    unknown: set[str] = set()

    # Iterate over all condition operators
    for _operator, key_value_map in condition_block.items():
        if not isinstance(key_value_map, dict):
            continue

        for condition_key in key_value_map:
            all_keys.add(condition_key)

            # Check if this key maps to a boolean flag
            flag_name = _CONDITION_KEY_FLAGS.get(condition_key)
            if flag_name is None:
                # Try case-insensitive match
                flag_name = _CONDITION_KEY_FLAGS.get(condition_key.lower())

            # COND-1: tag condition keys use a prefix form in real policies
            # (aws:PrincipalTag/Team, aws:RequestTag/Environment). Match the
            # prefix after exact-match lookup fails so bare and suffixed forms
            # are both recognised.
            if flag_name is None:
                key_lower = condition_key.lower()
                for prefix, prefix_flag in _CONDITION_KEY_PREFIXES.items():
                    if key_lower.startswith(prefix):
                        flag_name = prefix_flag
                        break

            if flag_name is not None:
                setattr(result, flag_name, True)
            elif not _is_known_key(condition_key):
                unknown.add(condition_key)

    result.condition_keys = sorted(all_keys)
    result.unknown_keys = sorted(unknown)

    return result


def _is_known_key(key: str) -> bool:
    """Check if a condition key is known (either flagged or informational).

    Case-insensitive check against both the flag mapping and the
    informational keys set.
    """
    if key in _CONDITION_KEY_FLAGS:
        return True
    if key in KNOWN_CONDITION_KEYS:
        return True

    # Case-insensitive fallback
    key_lower = key.lower()
    if key_lower in _CONDITION_KEY_FLAGS:
        return True

    # Check informational keys (case-insensitive for the aws: prefix ones)
    return any(key_lower == known.lower() for known in _KNOWN_INFORMATIONAL_KEYS)
