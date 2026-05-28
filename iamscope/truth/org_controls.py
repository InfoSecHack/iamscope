"""Effective AWS Organizations control normalization for truth consumers."""

from __future__ import annotations

import fnmatch
import hashlib
from typing import Any

from iamscope.constants import ACTION_CLASS_STS_ASSUME_ROLE, CONSTRAINT_TYPE_SCP
from iamscope.models import Constraint, OrgData


def normalize_effective_org_controls(org_data: OrgData) -> dict[str, list[dict[str, Any]]]:
    """Flatten effective SCP controls per governed account.

    This uses collected SCP constraints and ``ou_account_map``. Relevance is
    heuristic and does not prove request-level denial.
    """
    controls_by_account: dict[str, list[dict[str, Any]]] = {
        account_id: [] for account_id in sorted(org_data.account_ids)
    }

    for constraint in org_data.scp_constraints:
        if constraint.constraint_type != CONSTRAINT_TYPE_SCP:
            continue

        governed_accounts = org_data.ou_account_map.get(constraint.scope_id, set())
        if constraint.scope_type == "ACCOUNT":
            governed_accounts = {constraint.scope_id}

        for account_id in sorted(governed_accounts):
            inherited = not (constraint.scope_type == "ACCOUNT" and constraint.scope_id == account_id)
            controls_by_account.setdefault(account_id, []).append(_control_record(constraint, account_id, inherited))

    for account_id, controls in controls_by_account.items():
        controls_by_account[account_id] = sorted(
            controls,
            key=lambda c: (
                c.get("policy_id", ""),
                c.get("statement_id", ""),
                c.get("scope_id", ""),
            ),
        )
    return controls_by_account


def is_action_relevant(properties: dict[str, Any], action_class: str) -> bool:
    """Heuristically decide whether an SCP statement can govern an action."""
    if action_class != ACTION_CLASS_STS_ASSUME_ROLE:
        return False
    return is_sts_assume_role_relevant(properties)


def is_sts_assume_role_relevant(properties: dict[str, Any]) -> bool:
    """Heuristically decide whether an SCP statement can govern AssumeRole."""
    deny_actions = _as_list(properties.get("deny_actions"))
    if deny_actions:
        return any(_action_pattern_matches(str(pattern), ACTION_CLASS_STS_ASSUME_ROLE) for pattern in deny_actions)

    deny_not_actions = _as_list(properties.get("deny_not_actions"))
    if deny_not_actions:
        return not any(
            _action_pattern_matches(str(pattern), ACTION_CLASS_STS_ASSUME_ROLE) for pattern in deny_not_actions
        )

    return False


def has_broad_action_scope(properties: dict[str, Any], action_class: str) -> bool:
    """Heuristically decide whether resource scope is broad for an action."""
    if action_class != ACTION_CLASS_STS_ASSUME_ROLE:
        return False
    return has_broad_assume_role_scope(properties)


def has_broad_assume_role_scope(properties: dict[str, Any]) -> bool:
    """Heuristically decide whether resource scope is broad for role assumption."""
    patterns = _as_list(properties.get("resource_patterns")) or ["*"]
    broad_patterns = {"*", "arn:aws:iam::*:role/*"}
    for pattern in patterns:
        value = str(pattern)
        if value in broad_patterns:
            return True
        if fnmatch.fnmatchcase("arn:aws:iam::123456789012:role/Example", value):
            return True
    return False


def extract_account_id(arn_or_id: str) -> str | None:
    """Extract a 12-digit AWS account ID from an ARN or raw account ID."""
    if len(arn_or_id) == 12 and arn_or_id.isdigit():
        return arn_or_id
    parts = arn_or_id.split(":")
    if len(parts) >= 5 and len(parts[4]) == 12 and parts[4].isdigit():
        return parts[4]
    return None


def _control_record(
    constraint: Constraint,
    account_id: str,
    inherited: bool,
) -> dict[str, Any]:
    props = constraint.properties
    raw_policy = str(props.get("policy_document_raw", ""))
    content_hash = hashlib.sha256(raw_policy.encode("utf-8")).hexdigest()
    relevant = is_sts_assume_role_relevant(props)
    return {
        "account_id": account_id,
        "policy_id": constraint.policy_id,
        "policy_name": props.get("policy_name", ""),
        "statement_id": constraint.statement_id,
        "constraint_id": constraint.constraint_id,
        "scope_type": constraint.scope_type,
        "scope_id": constraint.scope_id,
        "attachment_level": constraint.scope_type.lower(),
        "inherited": inherited,
        "content_hash": content_hash,
        "relevant_to_sts_assume_role": relevant,
        "relevance_method": "heuristic_action_match",
        "broad_assume_role_scope": has_broad_assume_role_scope(props),
    }


def _action_pattern_matches(pattern: str, action: str) -> bool:
    return fnmatch.fnmatchcase(action.lower(), pattern.lower())


def _as_list(value: Any) -> list[Any]:
    if value is None:
        return []
    if isinstance(value, list):
        return value
    return [value]
