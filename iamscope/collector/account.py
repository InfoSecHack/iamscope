"""Account collector — Phase 2 per-account IAM data collection.

Collects IAM data from a single AWS account using GetAccountAuthorizationDetails:
- Roles → Node objects + trust policy parsing + permission policy parsing
- Users → Node objects + permission policy parsing (inline + managed + group-inherited)
- Groups → Node objects + group policy resolution for user permission inheritance

Per architecture doc §5.3 Phase 2, R10 (group-inherited permissions):
- Inline policies on principal
- Managed policies on principal
- For users: inline + managed policies on all groups the user belongs to

Per Invariant #1: READ-ONLY ONLY (Get*, List* only).
Per Invariant #2: Two-layer separation absolute (_trust from trust, _permission from permission).
Per Invariant #18: Pagination exhaustive.
Per Invariant #10: Embedded raw JSON re-serialized canonically.
"""

from __future__ import annotations

import json
import logging
from dataclasses import dataclass, field
from typing import Any

import boto3

from iamscope.auth.session import get_client
from iamscope.constants import (
    NODE_TYPE_IAM_GROUP,
    NODE_TYPE_IAM_ROLE,
    NODE_TYPE_IAM_USER,
    PROVIDER_AWS,
    REGION_GLOBAL,
)
from iamscope.models import (
    Constraint,
    Node,
    PermissionDenyResult,
    PermissionParseResult,
    TrustParseResult,
)
from iamscope.parser.parse_failures import PolicyParseFailure
from iamscope.parser.permission_policy import parse_permission_denies, parse_permission_policy
from iamscope.parser.trust_policy import parse_trust_policy

logger = logging.getLogger(__name__)


@dataclass
class AccountData:
    """Per-account collection output from Phase 2.

    Contains all IAM nodes and parsed trust/permission results
    for a single AWS account. These feed into the resolver pipeline
    (Phase 3+) for edge construction.
    """

    account_id: str
    nodes: list[Node] = field(default_factory=list)
    trust_results: list[tuple[Node, TrustParseResult]] = field(default_factory=list)
    # Each entry: (role_node, trust_parse_result)
    permission_results: list[PermissionParseResult] = field(default_factory=list)
    raw_deny_results: list[PermissionDenyResult] = field(default_factory=list)
    permission_deny_constraints: list[Constraint] = field(default_factory=list)
    role_arns: list[str] = field(default_factory=list)  # For expansion control
    permission_boundary_policies: dict[str, dict] = field(default_factory=dict)  # boundary_arn → policy_doc
    skipped_roles: int = 0
    skipped_users: int = 0
    # BUG-021: structured record of every policy that failed to parse
    # during this account's collection. Pre-BUG-021 these failures
    # were swallowed with a `logger.warning` and a silent `continue`,
    # producing false-negative findings downstream because dropped
    # policies → dropped edges → invisible paths.
    policy_parse_failures: list[PolicyParseFailure] = field(default_factory=list)


def collect_account(
    session: boto3.Session,
    account_id: str,
    region_name: str = "us-east-1",
    include_service_linked: bool = False,
    include_aws_managed: bool = False,
) -> AccountData:
    """Collect all IAM data for a single account — Phase 2 pipeline.

    Uses GetAccountAuthorizationDetails to retrieve roles, users, groups,
    and their policies in a single paginated API call.

    Args:
        session: boto3 Session with IAM read permissions for this account.
        account_id: AWS account ID being collected.
        region_name: Region for the IAM client.
        include_service_linked: Include AWS service-linked roles.
        include_aws_managed: Include AWS-managed roles (path /aws-service-role/).

    Returns:
        AccountData with nodes, trust results, permission results.
    """
    iam_client = get_client(session, "iam", region_name=region_name)
    result = AccountData(account_id=account_id)

    # Fetch all IAM data via GetAccountAuthorizationDetails (paginated)
    roles, users, groups, policies = _fetch_authorization_details(iam_client)
    logger.info(
        "Account %s: %d roles, %d users, %d groups, %d managed policies",
        account_id,
        len(roles),
        len(users),
        len(groups),
        len(policies),
    )

    # AWS does not promise stable ordering for authorization-detail lists.
    # Normalize before parsing so repeated collects over the same account feed
    # the resolver in the same order even when AWS pagination interleaves items.
    roles = sorted(roles, key=lambda r: str(r.get("Arn", "")))
    users = sorted(users, key=lambda u: str(u.get("Arn", "")))
    groups = sorted(groups, key=lambda g: str(g.get("Arn", "")))
    policies = sorted(policies, key=lambda p: str(p.get("Arn", "")))

    # Build managed policy document lookup
    managed_policy_docs = _build_managed_policy_lookup(
        policies,
        iam_client,
        result.policy_parse_failures,
    )

    # Build group policy lookup for user permission inheritance (R10)
    group_policies = _build_group_policy_lookup(
        groups,
        managed_policy_docs,
        result.policy_parse_failures,
    )

    # Process roles
    for role in roles:
        _process_role(role, account_id, result, managed_policy_docs, include_service_linked, include_aws_managed)

    # Process users
    for user in users:
        _process_user(user, account_id, result, managed_policy_docs, group_policies)

    # Process groups (as nodes + group-sourced permission edges)
    for group in groups:
        _process_group(group, account_id, result, group_policies)

    logger.info(
        "Account %s collected: %d nodes, %d trust results, %d permission results, "
        "%d role ARNs, %d skipped roles, %d skipped users",
        account_id,
        len(result.nodes),
        len(result.trust_results),
        len(result.permission_results),
        len(result.role_arns),
        result.skipped_roles,
        result.skipped_users,
    )

    return result


def _fetch_authorization_details(
    iam_client: Any,
) -> tuple[list[dict], list[dict], list[dict], list[dict]]:
    """Fetch all IAM data via GetAccountAuthorizationDetails.

    Per Invariant #18: pagination is exhaustive.

    Returns:
        Tuple of (roles, users, groups, managed_policies).
    """
    roles: list[dict] = []
    users: list[dict] = []
    groups: list[dict] = []
    policies: list[dict] = []

    paginator = iam_client.get_paginator("get_account_authorization_details")
    for page in paginator.paginate():
        roles.extend(page.get("RoleDetailList", []))
        users.extend(page.get("UserDetailList", []))
        groups.extend(page.get("GroupDetailList", []))
        policies.extend(page.get("Policies", []))

    return roles, users, groups, policies


def _build_managed_policy_lookup(
    policies: list[dict],
    iam_client: Any,
    failures: list[PolicyParseFailure],
) -> dict[str, dict]:
    """Build ARN → policy document lookup for managed policies.

    GetAccountAuthorizationDetails includes policy metadata but not
    always the full document. We extract the default version's document.

    BUG-021: takes a `failures` list and appends a structured record
    when a managed policy's default version document fails to parse.
    Pre-fix this branch silently `continue`d, dropping the policy
    entirely from the lookup, which then cascaded into every
    principal that referenced the policy ARN.
    """
    from iamscope.parser.parse_failures import make_parse_failure

    lookup: dict[str, dict] = {}

    for policy in policies:
        arn = policy.get("Arn", "")
        policy_name = policy.get("PolicyName", "")
        # Find the default version document
        for version in policy.get("PolicyVersionList", []):
            if version.get("IsDefaultVersion"):
                doc = version.get("Document")
                if isinstance(doc, str):
                    try:
                        doc = json.loads(doc)
                    except json.JSONDecodeError as e:
                        failures.append(
                            make_parse_failure(
                                parser="managed_policy_lookup",
                                source_arn=arn,
                                policy_source="managed",
                                policy_name=policy_name,
                                policy_arn=arn,
                                failure_kind="json_decode_error",
                                exception=e,
                            )
                        )
                        continue
                if isinstance(doc, dict):
                    lookup[arn] = doc
                else:
                    failures.append(
                        make_parse_failure(
                            parser="managed_policy_lookup",
                            source_arn=arn,
                            policy_source="managed",
                            policy_name=policy_name,
                            policy_arn=arn,
                            failure_kind="not_a_dict",
                        )
                    )
                break

    return lookup


def _build_group_policy_lookup(
    groups: list[dict],
    managed_policy_docs: dict[str, dict],
    failures: list[PolicyParseFailure],
) -> dict[str, list[tuple[str, dict, str]]]:
    """Build group_name → list of (policy_name, policy_doc, source) for R10.

    BUG-021: takes a `failures` list and appends a structured record
    when an inline group policy fails to parse. Pre-fix this branch
    silently `continue`d, dropping the policy entirely from the
    lookup, which cascaded into every user in the group losing
    R10-inherited permissions from that policy.

    Returns:
        Dict mapping group name to list of (policy_name, policy_document, source_type)
        where source_type is "group_inline" or "group_managed".
    """
    from iamscope.parser.parse_failures import make_parse_failure

    lookup: dict[str, list[tuple[str, dict, str]]] = {}

    for group in groups:
        group_name = group.get("GroupName", "")
        group_arn = group.get("Arn", "")
        policies: list[tuple[str, dict, str]] = []

        # Inline group policies
        for gp in group.get("GroupPolicyList", []):
            policy_name = gp.get("PolicyName", "")
            doc = gp.get("PolicyDocument")
            if isinstance(doc, str):
                try:
                    doc = json.loads(doc)
                except json.JSONDecodeError as e:
                    failures.append(
                        make_parse_failure(
                            parser="group_policy_lookup",
                            source_arn=group_arn,
                            policy_source="group_inline",
                            policy_name=policy_name,
                            failure_kind="json_decode_error",
                            exception=e,
                        )
                    )
                    continue
            if isinstance(doc, dict):
                policies.append((policy_name, doc, "group_inline"))
            else:
                failures.append(
                    make_parse_failure(
                        parser="group_policy_lookup",
                        source_arn=group_arn,
                        policy_source="group_inline",
                        policy_name=policy_name,
                        failure_kind="not_a_dict",
                    )
                )

        # Managed policies attached to group
        for mp in group.get("AttachedManagedPolicies", []):
            mp_arn = mp.get("PolicyArn", "")
            doc = managed_policy_docs.get(mp_arn)
            if doc:
                policies.append((mp.get("PolicyName", mp_arn), doc, "group_managed"))

        lookup[group_name] = policies

    return lookup


def _process_role(
    role: dict,
    account_id: str,
    result: AccountData,
    managed_policy_docs: dict[str, dict],
    include_service_linked: bool,
    include_aws_managed: bool,
) -> None:
    """Process a single IAM role: create node + parse trust + parse permissions."""
    role_name = role.get("RoleName", "")
    role_arn = role.get("Arn", "")
    role_path = role.get("Path", "/")

    # Noise filter: skip service-linked roles unless included
    if not include_service_linked and role_path.startswith("/aws-service-role/"):
        logger.debug("Skipping service-linked role: %s", role_name)
        result.skipped_roles += 1
        return

    # Noise filter: skip AWS-managed service roles unless included
    if not include_aws_managed and _is_aws_managed_role(role_path, role_name):
        logger.debug("Skipping AWS-managed role: %s", role_name)
        result.skipped_roles += 1
        return

    # Create node
    perm_boundary_arn = ""
    perm_boundary = role.get("PermissionsBoundary", {})
    if perm_boundary:
        perm_boundary_arn = perm_boundary.get("PermissionsBoundaryArn", "")
        # Capture boundary policy doc for constraint creation
        if perm_boundary_arn and perm_boundary_arn not in result.permission_boundary_policies:
            boundary_doc = managed_policy_docs.get(perm_boundary_arn)
            if boundary_doc:
                result.permission_boundary_policies[perm_boundary_arn] = boundary_doc

    node = Node(
        provider=PROVIDER_AWS,
        node_type=NODE_TYPE_IAM_ROLE,
        provider_id=role_arn,
        region=REGION_GLOBAL,
        properties={
            "account_id": account_id,
            "role_name": role_name,
            "path": role_path,
            "is_synthetic": False,
            "has_permission_boundary": bool(perm_boundary_arn),
            "permission_boundary_arn": perm_boundary_arn,
            "trust_policy_raw": _canonicalize_raw(role.get("AssumeRolePolicyDocument", {})),
        },
    )
    result.nodes.append(node)
    result.role_arns.append(role_arn)

    # Parse trust policy → trust results
    # BUG-021: pass the raw value directly to `parse_trust_policy`,
    # which accepts str OR dict and records JSON-decode failures
    # into `result.policy_parse_failures`. The pre-BUG-021 inline
    # `try: json.loads; except: {}` fallback silently dropped
    # malformed trust policies, producing false-negative cross-
    # account trust and assume-role chain findings.
    trust_doc = role.get("AssumeRolePolicyDocument", {})
    trust_results = parse_trust_policy(
        trust_doc,
        role_arn=role_arn,
        role_account_id=account_id,
        failures=result.policy_parse_failures,
    )
    for tr in trust_results:
        result.trust_results.append((node, tr))

    # Parse permission policies (inline + managed)
    _parse_role_permissions(role, role_arn, account_id, managed_policy_docs, result)


def _process_user(
    user: dict,
    account_id: str,
    result: AccountData,
    managed_policy_docs: dict[str, dict],
    group_policies: dict[str, list[tuple[str, dict, str]]],
) -> None:
    """Process a single IAM user: create node + parse permissions (including group-inherited)."""
    user_name = user.get("UserName", "")
    user_arn = user.get("Arn", "")
    user_path = user.get("Path", "/")

    perm_boundary_arn = ""
    perm_boundary = user.get("PermissionsBoundary", {})
    if perm_boundary:
        perm_boundary_arn = perm_boundary.get("PermissionsBoundaryArn", "")
        if perm_boundary_arn and perm_boundary_arn not in result.permission_boundary_policies:
            boundary_doc = managed_policy_docs.get(perm_boundary_arn)
            if boundary_doc:
                result.permission_boundary_policies[perm_boundary_arn] = boundary_doc

    node = Node(
        provider=PROVIDER_AWS,
        node_type=NODE_TYPE_IAM_USER,
        provider_id=user_arn,
        region=REGION_GLOBAL,
        properties={
            "account_id": account_id,
            "user_name": user_name,
            "path": user_path,
            "is_synthetic": False,
            "has_permission_boundary": bool(perm_boundary_arn),
            "permission_boundary_arn": perm_boundary_arn,
            "group_memberships": sorted(user.get("GroupList", [])),
        },
    )
    result.nodes.append(node)

    # Parse inline permission policies
    # BUG-021: remove the inline json.loads pre-filter and pass the
    # raw value to `parse_permission_policy`, which handles str/dict
    # and records decode failures into result.policy_parse_failures.
    for pol in user.get("UserPolicyList", []):
        prs = parse_permission_policy(
            pol.get("PolicyDocument"),
            source_arn=user_arn,
            source_node_type=NODE_TYPE_IAM_USER,
            source_account_id=account_id,
            policy_source="inline",
            policy_name=pol.get("PolicyName", ""),
            failures=result.policy_parse_failures,
        )
        result.permission_results.extend(prs)
        _record_permission_denies(
            result,
            pol.get("PolicyDocument"),
            principal_arn=user_arn,
            policy_source="inline",
            policy_name=pol.get("PolicyName", ""),
        )

    # Parse managed permission policies
    for mp in user.get("AttachedManagedPolicies", []):
        mp_arn = mp.get("PolicyArn", "")
        doc = managed_policy_docs.get(mp_arn)
        if doc:
            prs = parse_permission_policy(
                doc,
                source_arn=user_arn,
                source_node_type=NODE_TYPE_IAM_USER,
                source_account_id=account_id,
                policy_source="managed",
                policy_name=mp.get("PolicyName", mp_arn),
                policy_arn=mp_arn,
                failures=result.policy_parse_failures,
            )
            result.permission_results.extend(prs)
            _record_permission_denies(
                result,
                doc,
                principal_arn=user_arn,
                policy_source="managed",
                policy_name=mp.get("PolicyName", mp_arn),
                policy_arn=mp_arn,
            )

    # Parse group-inherited permission policies (R10).
    # BUG-021: `doc` here is already a parsed dict (the group policy
    # lookup stores parsed docs), so there's no decode to fail. Still
    # thread `failures=` so any non-dict-root or internal parse issue
    # is attributed to this user-source path rather than dropped.
    for group_name in user.get("GroupList", []):
        for policy_name, doc, source_type in group_policies.get(group_name, []):
            prs = parse_permission_policy(
                doc,
                source_arn=user_arn,
                source_node_type=NODE_TYPE_IAM_USER,
                source_account_id=account_id,
                policy_source=source_type,
                policy_name=policy_name,
                failures=result.policy_parse_failures,
            )
            result.permission_results.extend(prs)
            _record_permission_denies(
                result,
                doc,
                principal_arn=user_arn,
                policy_source=source_type,
                policy_name=policy_name,
            )


def _process_group(
    group: dict,
    account_id: str,
    result: AccountData,
    group_policies: dict[str, list[tuple[str, dict, str]]],
) -> None:
    """Process a single IAM group: create node + group-sourced permission edges.

    In addition to R10 user-inheritance (group policies flow into each
    member user's permission edges via _process_user), we ALSO emit
    permission edges from the IAMGroup node itself. This makes groups
    first-class in the permission graph, enabling reasoners like
    `iam_group_membership_escalation` to walk `facts.edges_from(group)`
    and apply the shared admin-equivalence detection.

    The user-inheritance path is unchanged — user edges and group edges
    carry parallel copies of the same statement digests, which is
    correct: both edges represent real permission paths that a reasoner
    might want to audit separately.
    """
    group_name = group.get("GroupName", "")
    group_arn = group.get("Arn", "")
    group_path = group.get("Path", "/")

    node = Node(
        provider=PROVIDER_AWS,
        node_type=NODE_TYPE_IAM_GROUP,
        provider_id=group_arn,
        region=REGION_GLOBAL,
        properties={
            "account_id": account_id,
            "group_name": group_name,
            "path": group_path,
            "is_synthetic": False,
        },
    )
    result.nodes.append(node)

    # Parse group policies with the group as the source, producing
    # permission_results that downstream edge construction will
    # materialize as edges from the IAMGroup node. Each policy is
    # parsed with source_node_type=NODE_TYPE_IAM_GROUP so the edge
    # builder knows which node type this source is.
    # BUG-021: thread failures= so any non-dict-root or internal
    # parse issue at this site is captured into the structured
    # record rather than dropped.
    for policy_name, doc, source_type in group_policies.get(group_name, []):
        prs = parse_permission_policy(
            doc,
            source_arn=group_arn,
            source_node_type=NODE_TYPE_IAM_GROUP,
            source_account_id=account_id,
            policy_source=source_type,
            policy_name=policy_name,
            failures=result.policy_parse_failures,
        )
        result.permission_results.extend(prs)
        _record_permission_denies(
            result,
            doc,
            principal_arn=group_arn,
            policy_source=source_type,
            policy_name=policy_name,
        )


def _parse_role_permissions(
    role: dict,
    role_arn: str,
    account_id: str,
    managed_policy_docs: dict[str, dict],
    result: AccountData,
) -> None:
    """Parse permission policies for a role (inline + managed).

    BUG-021: every `parse_permission_policy` call in this function
    now threads `failures=result.policy_parse_failures` and passes
    the raw policy value directly (the parser handles str/dict
    internally and records decode failures). Pre-BUG-021 this
    function swallowed `json.JSONDecodeError` at each site with a
    silent `continue`, dropping every edge that would have been
    built from the affected policy.
    """
    # Inline policies
    for pol in role.get("RolePolicyList", []):
        prs = parse_permission_policy(
            pol.get("PolicyDocument"),
            source_arn=role_arn,
            source_node_type=NODE_TYPE_IAM_ROLE,
            source_account_id=account_id,
            policy_source="inline",
            policy_name=pol.get("PolicyName", ""),
            failures=result.policy_parse_failures,
        )
        result.permission_results.extend(prs)
        _record_permission_denies(
            result,
            pol.get("PolicyDocument"),
            principal_arn=role_arn,
            policy_source="inline",
            policy_name=pol.get("PolicyName", ""),
        )

    # Managed policies
    for mp in role.get("AttachedManagedPolicies", []):
        mp_arn = mp.get("PolicyArn", "")
        doc = managed_policy_docs.get(mp_arn)
        if doc:
            prs = parse_permission_policy(
                doc,
                source_arn=role_arn,
                source_node_type=NODE_TYPE_IAM_ROLE,
                source_account_id=account_id,
                policy_source="managed",
                policy_name=mp.get("PolicyName", mp_arn),
                policy_arn=mp_arn,
                failures=result.policy_parse_failures,
            )
            result.permission_results.extend(prs)
            _record_permission_denies(
                result,
                doc,
                principal_arn=role_arn,
                policy_source="managed",
                policy_name=mp.get("PolicyName", mp_arn),
                policy_arn=mp_arn,
            )


def _is_aws_managed_role(path: str, name: str) -> bool:
    """Check if a role is an AWS-managed service role (non-SLR).

    NOTE: Service-linked roles (/aws-service-role/) are handled by the
    separate include_service_linked flag. This function only checks
    for other AWS-managed patterns like /service-role/AWSLambda*.
    """
    # /service-role/ with AWS/Amazon prefix (e.g., AWSLambdaBasicExecutionRole)
    return path.startswith("/service-role/") and name.startswith(("AWS", "Amazon"))


def _permission_policy_id(
    policy_source: str,
    principal_arn: str,
    policy_name: str = "",
    policy_arn: str = "",
) -> str:
    """Return the managed ARN or deterministic synthetic ID for inline policies."""
    if policy_arn:
        return policy_arn
    return f"{policy_source}:{principal_arn}:{policy_name}"


def _record_permission_denies(
    result: AccountData,
    policy_document: Any,
    *,
    principal_arn: str,
    policy_source: str,
    policy_name: str = "",
    policy_arn: str = "",
) -> None:
    policy_id = _permission_policy_id(
        policy_source=policy_source,
        principal_arn=principal_arn,
        policy_name=policy_name,
        policy_arn=policy_arn,
    )
    result.raw_deny_results.extend(
        parse_permission_denies(
            policy_document,
            principal_arn=principal_arn,
            policy_id=policy_id,
        )
    )


def _canonicalize_raw(doc: Any) -> str:
    """Re-serialize a raw document to canonical JSON.

    Per Invariant #10: embedded raw JSON is re-serialized canonically.
    """
    if isinstance(doc, str):
        try:
            doc = json.loads(doc)
        except (json.JSONDecodeError, TypeError):
            return str(doc)
    result: str = json.dumps(doc, sort_keys=True, separators=(",", ":"))
    return result
