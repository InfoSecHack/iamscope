"""Permission policy parser — extracts security-relevant action grants.

Implements architecture doc §5.7, R08, R10:
- Parses IAM permission policies (inline, managed, group-inherited)
- Extracts grants for actions we care about:
  - sts:AssumeRole, sts:AssumeRoleWithSAML, sts:AssumeRoleWithWebIdentity
  - iam:PassRole
  - lambda:InvokeFunction, lambda:CreateFunction
  - ec2:RunInstances
- Handles wildcard actions: *, sts:*, iam:*, lambda:*, ec2:*
- Handles Resource patterns: specific ARNs vs "*"
- Only processes Allow statements (Deny doesn't create permission edges)
- Extracts conditions (uncommon on permission side but supported)

All operations are deterministic: same input → same output.
"""

from __future__ import annotations

import fnmatch
import json
import logging
from typing import Any

from iamscope.identity.statement_digest import statement_digest
from iamscope.models import PermissionDenyResult, PermissionParseResult
from iamscope.parser.parse_failures import PolicyParseFailure, make_parse_failure

logger = logging.getLogger(__name__)

# Actions that create _permission edges
ASSUME_ACTIONS: set[str] = {
    "sts:assumerole",
    "sts:assumerolewithsaml",
    "sts:assumerolewithwebidentity",
}

PASSROLE_ACTIONS: set[str] = {
    "iam:passrole",
}

LAMBDA_ACTIONS: set[str] = {
    "lambda:invokefunction",
    "lambda:createfunction",
}

EC2_ACTIONS: set[str] = {
    "ec2:runinstances",
}

ECS_ACTIONS: set[str] = {
    "ecs:registertaskdefinition",
    "ecs:runtask",
}

SECRETS_ACTIONS: set[str] = {
    "secretsmanager:getsecretvalue",
}

IAM_GROUP_ACTIONS: set[str] = {
    "iam:addusertogroup",
}

S3_ACTIONS: set[str] = {
    "s3:putbucketpolicy",
}

# All actions we care about
RELEVANT_ACTIONS: set[str] = (
    ASSUME_ACTIONS
    | PASSROLE_ACTIONS
    | LAMBDA_ACTIONS
    | EC2_ACTIONS
    | ECS_ACTIONS
    | SECRETS_ACTIONS
    | IAM_GROUP_ACTIONS
    | S3_ACTIONS
)

# Wildcard patterns that match our relevant actions
WILDCARD_PATTERNS: dict[str, str] = {
    "*": "wildcard_star",
    "sts:*": "wildcard_sts",
    "iam:*": "wildcard_iam",
    "lambda:*": "wildcard_lambda",
    "ec2:*": "wildcard_ec2",
}


def parse_permission_policy(
    policy_document: dict[str, Any] | str | None,
    source_arn: str,
    source_node_type: str,
    source_account_id: str,
    policy_source: str = "inline",
    policy_name: str = "",
    policy_arn: str = "",
    failures: list[PolicyParseFailure] | None = None,
) -> list[PermissionParseResult]:
    """Parse an IAM permission policy to extract relevant action grants.

    Args:
        policy_document: The IAM policy document (dict or JSON string).
        source_arn: ARN of the principal that has this policy.
        source_node_type: Node type of the source principal.
        source_account_id: Account ID of the source principal.
        policy_source: How the policy is attached ("inline", "managed",
                       "group_inline", "group_managed").
        policy_name: Name of the policy.
        policy_arn: ARN of managed policy (if applicable).
        failures: Optional shared list for structured parse failure
            records (BUG-021). When provided, JSON-decode errors and
            non-dict roots are appended here in addition to being
            logged, so callers can detect that the fact graph is
            partial. Pre-BUG-021 these failures returned `[]`
            silently, dropping every edge that should have been
            built from the policy and producing false-negative
            findings downstream.

    Returns:
        List of PermissionParseResult objects, one per (action, resource) pair.
    """
    if policy_document is None:
        return []

    if isinstance(policy_document, str):
        try:
            policy_document = json.loads(policy_document)
        except (json.JSONDecodeError, TypeError) as e:
            logger.warning("Malformed permission policy JSON for %s", source_arn)
            if failures is not None:
                failures.append(
                    make_parse_failure(
                        parser="permission_policy",
                        source_arn=source_arn,
                        policy_source=policy_source,
                        policy_name=policy_name,
                        policy_arn=policy_arn,
                        failure_kind="json_decode_error",
                        exception=e,
                    )
                )
            return []

    if not isinstance(policy_document, dict):
        # JSON parsed (or was passed in) but the root isn't an object.
        # IAM policy documents are always dict-rooted; anything else is
        # malformed and we can't extract anything from it. Pre-BUG-021
        # this returned [] silently with no record.
        if failures is not None:
            failures.append(
                make_parse_failure(
                    parser="permission_policy",
                    source_arn=source_arn,
                    policy_source=policy_source,
                    policy_name=policy_name,
                    policy_arn=policy_arn,
                    failure_kind="not_a_dict",
                )
            )
        return []

    statements = policy_document.get("Statement", [])
    if isinstance(statements, dict):
        statements = [statements]

    results: list[PermissionParseResult] = []

    for stmt_idx, stmt in enumerate(statements):
        if not isinstance(stmt, dict):
            continue

        effect = stmt.get("Effect", "")
        if effect != "Allow":
            continue

        # Extract actions
        matched_actions = _extract_matching_actions(stmt)
        if not matched_actions:
            continue

        # Extract resources
        resources = _extract_resources(stmt)

        # Extract conditions
        condition_block = stmt.get("Condition", {})
        has_conditions = bool(condition_block)

        # DIG-1 (S05): compute digest once per statement from the raw dict.
        stmt_digest = statement_digest(stmt)

        # Emit one result per (action, resource)
        for action, match_via in matched_actions:
            for resource in resources:
                is_wildcard = _is_wildcard_resource(resource)
                results.append(
                    PermissionParseResult(
                        statement_index=stmt_idx,
                        effect="Allow",
                        action=action,
                        resource_pattern=resource,
                        is_wildcard_resource=is_wildcard,
                        source_arn=source_arn,
                        source_node_type=source_node_type,
                        source_account_id=source_account_id,
                        policy_source=policy_source,
                        policy_name=policy_name,
                        policy_arn=policy_arn,
                        has_conditions=has_conditions,
                        raw_conditions=condition_block if has_conditions else {},
                        action_matched_via=match_via,
                        statement_digest=stmt_digest,
                    )
                )

    return results


def parse_permission_denies(
    policy_document: dict[str, Any] | str | None,
    principal_arn: str,
    policy_id: str,
) -> list[PermissionDenyResult]:
    """Parse Deny statements from an identity policy document.

    Returns one PermissionDenyResult per Deny statement. Allow statements
    are skipped. This is deliberately separate from parse_permission_policy
    so the existing Allow parser contract remains unchanged.
    """
    if policy_document is None:
        return []

    if isinstance(policy_document, str):
        try:
            policy_document = json.loads(policy_document)
        except (json.JSONDecodeError, TypeError):
            logger.warning("Malformed permission policy JSON for %s", principal_arn)
            return []

    if not isinstance(policy_document, dict):
        return []

    statements = policy_document.get("Statement", [])
    if isinstance(statements, dict):
        statements = [statements]
    if not isinstance(statements, list):
        return []

    results: list[PermissionDenyResult] = []

    for stmt_idx, stmt in enumerate(statements):
        if not isinstance(stmt, dict):
            continue

        effect = stmt.get("Effect", "Allow")
        if effect != "Deny":
            continue

        statement_id = str(stmt.get("Sid") or f"_stmt{stmt_idx}")
        conditions = stmt.get("Condition") or {}
        has_conditions = bool(conditions)
        raw_conditions = conditions if isinstance(conditions, dict) else {}

        actions_raw = stmt.get("Action")
        not_actions_raw = stmt.get("NotAction")
        parse_status = "complete"

        if actions_raw is not None:
            deny_actions = _normalize_to_list(actions_raw)
        elif not_actions_raw is not None:
            # NotAction in a Deny means deny everything except these actions.
            # CC-4 owns true inversion; for CC-1 this is conservative partial data.
            deny_actions = _normalize_to_list(not_actions_raw)
            parse_status = "partial"
        else:
            deny_actions = []
            parse_status = "unsupported"

        resources_raw = stmt.get("Resource")
        not_resources_raw = stmt.get("NotResource")

        if resources_raw is not None:
            resource_patterns = _normalize_to_list(resources_raw) or ["*"]
        elif not_resources_raw is not None:
            # NotResource inversion is deferred; bind conservatively to all resources.
            resource_patterns = ["*"]
            parse_status = "unsupported"
        else:
            resource_patterns = ["*"]

        results.append(
            PermissionDenyResult(
                principal_arn=principal_arn,
                policy_arn=policy_id,
                statement_id=statement_id,
                deny_actions=deny_actions,
                resource_patterns=resource_patterns,
                has_conditions=has_conditions,
                raw_conditions=raw_conditions,
                parse_status=parse_status,
            )
        )

    return results


def _normalize_to_list(value: Any) -> list[str]:
    """Normalize an IAM scalar-or-list field to a string list."""
    if isinstance(value, str):
        return [value]
    if isinstance(value, list):
        return [item for item in value if isinstance(item, str)]
    return []


def _extract_matching_actions(stmt: dict[str, Any]) -> list[tuple[str, str]]:
    """Extract actions from a statement that match our relevant action set.

    Handles:
    - Exact matches: "sts:AssumeRole" → [("sts:AssumeRole", "exact")]
    - Wildcard star: "*" → all relevant actions with "wildcard_star"
    - Service wildcards: "sts:*" → all sts actions with "wildcard_sts"
    - NotAction: "NotAction: [X]" → everything NOT in X is allowed

    Returns:
        List of (canonical_action, match_via) tuples.
    """
    # Check for Action vs NotAction
    actions_raw = stmt.get("Action", [])
    not_actions_raw = stmt.get("NotAction", [])

    if not_actions_raw:
        return _extract_via_not_action(not_actions_raw)

    if isinstance(actions_raw, str):
        actions_raw = [actions_raw]

    if not isinstance(actions_raw, list):
        return []

    matched: list[tuple[str, str]] = []

    for action_str in actions_raw:
        if not isinstance(action_str, str):
            continue

        action_lower = action_str.lower().strip()

        # Check wildcard patterns first
        for pattern, match_type in WILDCARD_PATTERNS.items():
            if action_lower == pattern.lower():
                # Expand to all relevant actions covered by this wildcard
                for relevant in sorted(RELEVANT_ACTIONS):
                    if fnmatch.fnmatch(relevant, action_lower):
                        canonical = _canonicalize_action(relevant)
                        matched.append((canonical, match_type))
                break
        else:
            # Check exact match against relevant actions
            if action_lower in RELEVANT_ACTIONS:
                canonical = _canonicalize_action(action_lower)
                matched.append((canonical, "exact"))
            # Check fnmatch for other patterns like "sts:Assume*"
            elif "*" in action_str or "?" in action_str:
                for relevant in sorted(RELEVANT_ACTIONS):
                    if fnmatch.fnmatch(relevant, action_lower):
                        canonical = _canonicalize_action(relevant)
                        matched.append((canonical, "wildcard_pattern"))

    return matched


def _extract_via_not_action(not_actions_raw: Any) -> list[tuple[str, str]]:
    """Extract matching actions via NotAction (inverse).

    NotAction: [X, Y] means this policy allows everything EXCEPT X and Y.
    If our relevant actions are NOT in the exception list, they ARE allowed.
    """
    if isinstance(not_actions_raw, str):
        not_actions_raw = [not_actions_raw]

    if not isinstance(not_actions_raw, list):
        return []

    not_action_set = {a.lower().strip() for a in not_actions_raw if isinstance(a, str)}

    matched: list[tuple[str, str]] = []
    for relevant in sorted(RELEVANT_ACTIONS):
        # Check if the relevant action is covered by any NotAction entry
        is_excepted = any(fnmatch.fnmatch(relevant, na) for na in not_action_set)
        if not is_excepted:
            canonical = _canonicalize_action(relevant)
            matched.append((canonical, "not_action"))

    return matched


def _extract_resources(stmt: dict[str, Any]) -> list[str]:
    """Extract resource patterns from a statement.

    Returns:
        List of resource ARN patterns. If no Resource specified, returns ["*"].
    """
    resources = stmt.get("Resource", "*")
    if isinstance(resources, str):
        resources = [resources]
    if not isinstance(resources, list):
        return ["*"]
    return [r for r in resources if isinstance(r, str)] or ["*"]


def _is_wildcard_resource(resource: str) -> bool:
    """Check if a resource pattern is effectively wildcard.

    BUG-022 (real-world validation crash): pre-fix this function only
    returned True for three exact strings — "*", "arn:aws:iam::*:role/*",
    and "arn:*:iam::*:role/*" — missing the vast majority of real-world
    wildcard patterns:

    - `arn:aws:iam::111111111111:role/prod-*` (role prefix wildcard)
    - `arn:aws:lambda:*:123:function:svc-*` (Lambda function wildcard)
    - `arn:aws:s3:::my-bucket/*` (S3 object wildcard)
    - `arn:aws:secretsmanager:*:123:secret:prod-*` (secret wildcard)

    Any of these, pre-fix, were classified as "specific" resources,
    which caused the edge builder to create an edge whose `dst`
    provider_id was the literal pattern string. The scenario.json
    referential-integrity validator then crashed with "Edge dst
    references non-existent node" because no node in the fact graph
    has a provider_id containing `*`.

    The fix detects ANY `*` or `?` in the resource pattern as wildcard.
    These are the only two glob metacharacters AWS IAM supports in
    Resource fields, and they're illegal in actual AWS resource names
    — so a pattern containing them cannot correspond to any concrete
    node and must go through the wildcard-expansion / hyperedge path.

    Non-wildcard literal ARNs continue to flow through the specific
    path unchanged. The separate problem of "literal ARN that doesn't
    match any collected node" (e.g., a dangling reference to a
    deleted resource) is a different bug and is not addressed here —
    see BUG-023 in the followup list.
    """
    if resource == "*":
        return True
    # Any ARN containing a glob metacharacter is effectively wildcard.
    return "*" in resource or "?" in resource


def _canonicalize_action(action_lower: str) -> str:
    """Convert a lowercase action to its canonical form.

    Maps lowercase action names to their canonical casing.
    """
    canonical_map = {
        "sts:assumerole": "sts:AssumeRole",
        "sts:assumerolewithsaml": "sts:AssumeRoleWithSAML",
        "sts:assumerolewithwebidentity": "sts:AssumeRoleWithWebIdentity",
        "iam:passrole": "iam:PassRole",
        "lambda:invokefunction": "lambda:InvokeFunction",
        "lambda:createfunction": "lambda:CreateFunction",
        "ec2:runinstances": "ec2:RunInstances",
        "ecs:registertaskdefinition": "ecs:RegisterTaskDefinition",
        "ecs:runtask": "ecs:RunTask",
        "secretsmanager:getsecretvalue": "secretsmanager:GetSecretValue",
        "iam:addusertogroup": "iam:AddUserToGroup",
        "s3:putbucketpolicy": "s3:PutBucketPolicy",
    }
    return canonical_map.get(action_lower, action_lower)
