"""Organization collector — Phase 1 of the IAMScope pipeline.

Discovers the AWS Organization structure:
- DescribeOrganization → org_id, root_id
- Recursive OU tree walk → full hierarchy with paths
- ListAccounts → all member accounts with OU assignments
- ListPolicies(SCP) → all SCPs, parsed via scp_policy.py
- ListPoliciesForTarget → SCP-to-OU/account bindings
- Compute ou_account_map → recursive account inheritance per scope

Per architecture doc §5.3 Phase 1, R12 (retry/backoff), R14 (statement_id),
Invariant #1 (READ-ONLY), #13 (parse_status never upgraded),
#15 (OU inheritance is recursive downward only), #18 (pagination exhaustive).

All operations use read-only APIs only: Describe*, List*.
"""

from __future__ import annotations

import json
import logging
from typing import Any

import boto3
from botocore.exceptions import ClientError

from iamscope.auth.session import get_client
from iamscope.constants import (
    CONSTRAINT_TYPE_SCP,
    PROVIDER_AWS,
    REGION_GLOBAL,
)
from iamscope.models import (
    AccountInfo,
    Constraint,
    OrgData,
    OUInfo,
)
from iamscope.parser.scp_policy import parse_scp_document

logger = logging.getLogger(__name__)


def collect_organization(
    session: boto3.Session,
    region_name: str = "us-east-1",
) -> OrgData:
    """Collect complete organization structure — Phase 1 pipeline.

    Args:
        session: boto3 Session with organizations:* read permissions.
        region_name: Region for the Organizations API client.

    Returns:
        OrgData with OU tree, accounts, parsed SCPs, and ou_account_map.

    Raises:
        ClientError: If Organizations API calls fail after retries.
    """
    org_client = get_client(session, "organizations", region_name=region_name)

    # Step 1: Describe organization
    org_id, root_id = _describe_organization(org_client)
    logger.info("Organization %s, root %s", org_id, root_id)

    # Step 2: Walk OU tree recursively
    ous = _walk_ou_tree(org_client, root_id, parent_path="/Root")
    logger.info("Discovered %d OUs", len(ous))

    # Step 3: List all accounts and assign to OUs
    accounts = _list_all_accounts(org_client)
    _assign_accounts_to_parents(org_client, accounts, root_id, ous)
    logger.info("Discovered %d accounts", len(accounts))

    # Step 4: Collect and parse SCPs
    scp_constraints = _collect_scps(org_client, ous, accounts, root_id)
    logger.info("Collected %d SCP constraints", len(scp_constraints))

    # Step 5: Compute ou_account_map (recursive inheritance)
    ou_account_map = _compute_ou_account_map(root_id, ous, accounts)
    logger.info("Computed ou_account_map for %d scopes", len(ou_account_map))

    return OrgData(
        org_id=org_id,
        root_id=root_id,
        accounts=accounts,
        ous=ous,
        scp_constraints=scp_constraints,
        ou_account_map=ou_account_map,
    )


def _describe_organization(org_client: Any) -> tuple[str, str]:
    """Get org_id and root_id."""
    org = org_client.describe_organization()["Organization"]
    org_id = org["Id"]

    roots = org_client.list_roots()["Roots"]
    if not roots:
        raise ValueError("No organization roots found")
    root_id = roots[0]["Id"]

    return org_id, root_id


def _walk_ou_tree(
    org_client: Any,
    parent_id: str,
    parent_path: str,
    depth: int = 0,
    max_depth: int = 20,
) -> list[OUInfo]:
    """Recursively walk the OU tree under a parent.

    Per Invariant #15: OU inheritance is recursive downward only.
    Per Invariant #18: pagination is exhaustive.

    AWS allows max 5 levels of OU nesting, but we use max_depth=20
    as a safety valve against malformed API responses or circular references.
    """
    if depth >= max_depth:
        logger.warning(
            "OU tree walk exceeded max depth %d at %s — possible circular reference",
            max_depth,
            parent_path,
        )
        return []

    ous: list[OUInfo] = []
    paginator = org_client.get_paginator("list_organizational_units_for_parent")

    for page in paginator.paginate(ParentId=parent_id):
        for ou_raw in page.get("OrganizationalUnits", []):
            ou_id = ou_raw["Id"]
            ou_name = ou_raw["Name"]
            ou_path = f"{parent_path}/{ou_name}"

            ou_info = OUInfo(
                ou_id=ou_id,
                name=ou_name,
                parent_id=parent_id,
                ou_path=ou_path,
            )
            ous.append(ou_info)

            # Recurse into child OUs
            child_ous = _walk_ou_tree(org_client, ou_id, ou_path, depth + 1, max_depth)
            ou_info.child_ou_ids = [c.ou_id for c in child_ous]
            ous.extend(child_ous)

    return ous


def _list_all_accounts(org_client: Any) -> list[AccountInfo]:
    """List all accounts in the organization.

    Per Invariant #18: pagination is exhaustive.
    """
    accounts: list[AccountInfo] = []
    paginator = org_client.get_paginator("list_accounts")

    for page in paginator.paginate():
        for acct in page.get("Accounts", []):
            accounts.append(
                AccountInfo(
                    account_id=acct["Id"],
                    name=acct.get("Name", ""),
                    email=acct.get("Email", ""),
                    status=acct.get("Status", "ACTIVE"),
                    parent_id="",  # Assigned in next step
                )
            )

    return accounts


def _assign_accounts_to_parents(
    org_client: Any,
    accounts: list[AccountInfo],
    root_id: str,
    ous: list[OUInfo],
) -> None:
    """Assign each account to its parent OU (or root) by listing children.

    Mutates accounts in place to set parent_id and ou_path.
    Mutates OUInfo objects to set account_ids.
    """
    account_map = {a.account_id: a for a in accounts}
    ou_map = {ou.ou_id: ou for ou in ous}

    # Check accounts directly under each OU
    for ou in ous:
        _list_accounts_for_parent(org_client, ou.ou_id, account_map, ou_map)

    # Check accounts directly under root
    _list_accounts_for_parent(org_client, root_id, account_map, ou_map)


def _list_accounts_for_parent(
    org_client: Any,
    parent_id: str,
    account_map: dict[str, AccountInfo],
    ou_map: dict[str, OUInfo],
) -> None:
    """List accounts for a parent and assign parent_id."""
    paginator = org_client.get_paginator("list_accounts_for_parent")
    for page in paginator.paginate(ParentId=parent_id):
        for acct in page.get("Accounts", []):
            acct_id = acct["Id"]
            if acct_id in account_map:
                account_map[acct_id].parent_id = parent_id
                if parent_id in ou_map:
                    account_map[acct_id].ou_path = ou_map[parent_id].ou_path
                    ou_map[parent_id].account_ids.append(acct_id)
                else:
                    account_map[acct_id].ou_path = "/Root"


def _collect_scps(
    org_client: Any,
    ous: list[OUInfo],
    accounts: list[AccountInfo],
    root_id: str,
) -> list[Constraint]:
    """Collect all SCPs, parse them, and determine their scope bindings.

    For each SCP:
    1. DescribePolicy → get policy document
    2. Parse via parse_scp_document() → list[SCPParseResult]
    3. ListTargetsForPolicy → determine which OUs/accounts it's attached to
    4. Create Constraint objects with scope info
    """
    constraints: list[Constraint] = []

    # List all SCPs in the org
    paginator = org_client.get_paginator("list_policies")
    policy_summaries: list[dict[str, Any]] = []
    for page in paginator.paginate(Filter="SERVICE_CONTROL_POLICY"):
        policy_summaries.extend(page.get("Policies", []))

    # Build OU lookup for path resolution
    ou_map = {ou.ou_id: ou for ou in ous}

    for policy_summary in policy_summaries:
        policy_id = policy_summary["Id"]
        policy_name = policy_summary.get("Name", "")

        # Skip the default FullAWSAccess SCP — it's Allow * and doesn't constrain
        if policy_name == "FullAWSAccess":
            logger.debug("Skipping default FullAWSAccess SCP %s", policy_id)
            continue

        # Describe policy to get full document
        try:
            policy_detail = org_client.describe_policy(PolicyId=policy_id)
        except ClientError as e:
            logger.warning("Failed to describe SCP %s: %s", policy_id, e)
            continue

        policy_content = policy_detail["Policy"].get("Content", "{}")
        if isinstance(policy_content, str):
            try:
                policy_doc = json.loads(policy_content)
            except json.JSONDecodeError:
                logger.warning("Malformed SCP JSON for %s", policy_id)
                continue
        else:
            policy_doc = policy_content

        # Parse policy document → list of SCPParseResult
        parse_results = parse_scp_document(policy_doc, policy_id=policy_id, policy_name=policy_name)

        # Find targets (which OUs/accounts this SCP is attached to)
        targets = _list_targets_for_policy(org_client, policy_id)

        # Create Constraint per (parse_result × target)
        for pr_idx, pr in enumerate(parse_results):
            for target in targets:
                target_id = target["TargetId"]
                target_type = target.get("Type", "")

                if target_type == "ROOT":
                    scope_type = "ROOT"
                    scope_id = root_id
                    ou_name = "Root"
                    ou_path = "/Root"
                elif target_type == "ORGANIZATIONAL_UNIT":
                    scope_type = "OU"
                    scope_id = target_id
                    ou_info = ou_map.get(target_id)
                    ou_name = ou_info.name if ou_info else target_id
                    ou_path = ou_info.ou_path if ou_info else f"/{target_id}"
                elif target_type == "ACCOUNT":
                    scope_type = "ACCOUNT"
                    scope_id = target_id
                    ou_name = ""
                    ou_path = ""
                else:
                    logger.warning("Unknown SCP target type %s for %s", target_type, policy_id)
                    continue

                # Canonical JSON for raw conditions
                raw_conditions = pr.raw_conditions
                if raw_conditions:
                    raw_conditions = json.loads(json.dumps(raw_conditions, sort_keys=True, separators=(",", ":")))

                properties = {
                    "policy_name": policy_name,
                    "ou_name": ou_name,
                    "ou_path": ou_path,
                    "deny_actions": sorted(pr.deny_actions),
                    "deny_not_actions": sorted(pr.deny_not_actions),
                    "resource_patterns": sorted(pr.resource_patterns),
                    "exception_principal_patterns": sorted(pr.exception_principal_patterns),
                    "exception_org_ids": sorted(pr.exception_org_ids),
                    "exception_account_ids": sorted(pr.exception_account_ids),
                    "raw_conditions": raw_conditions,
                    "parse_status": pr.parse_status,
                    "parse_warnings": pr.parse_warnings,
                    "policy_document_raw": json.dumps(policy_doc, sort_keys=True, separators=(",", ":")),
                }
                if pr.applicable_principal_patterns:
                    properties["applicable_principal_patterns"] = sorted(pr.applicable_principal_patterns)

                constraint = Constraint(
                    provider=PROVIDER_AWS,
                    constraint_type=CONSTRAINT_TYPE_SCP,
                    scope_type=scope_type,
                    scope_id=scope_id,
                    policy_id=policy_id,
                    statement_id=pr.statement_id or f"stmt_{pr_idx}",
                    region=REGION_GLOBAL,
                    properties=properties,
                    status="ACTIVE",
                    validation_status="UNVALIDATED",
                    confidence_q=_scp_confidence(pr.parse_status),
                )
                constraints.append(constraint)

    return constraints


def _list_targets_for_policy(
    org_client: Any,
    policy_id: str,
) -> list[dict[str, Any]]:
    """List all targets (OUs, accounts, root) for an SCP.

    Per Invariant #18: exhaustive pagination.
    """
    targets: list[dict[str, Any]] = []
    paginator = org_client.get_paginator("list_targets_for_policy")
    for page in paginator.paginate(PolicyId=policy_id):
        targets.extend(page.get("Targets", []))
    return targets


def _compute_ou_account_map(
    root_id: str,
    ous: list[OUInfo],
    accounts: list[AccountInfo],
) -> dict[str, set[str]]:
    """Compute the recursive account set for each scope.

    Per Invariant #15: OU inheritance is recursive downward only.
    Parent SCPs apply to all accounts under them (children + descendants).

    Result maps scope_id → set[account_id] including:
    - Direct account children of the scope
    - All accounts in descendant OUs

    Also includes root_id and individual account IDs as scopes.
    """
    # Build parent→children map
    children_map: dict[str, list[str]] = {root_id: []}
    for ou in ous:
        children_map.setdefault(ou.parent_id, []).append(ou.ou_id)
        children_map.setdefault(ou.ou_id, [])

    # Build direct account assignments
    direct_accounts: dict[str, list[str]] = {root_id: []}
    for ou in ous:
        direct_accounts[ou.ou_id] = list(ou.account_ids)
    for acct in accounts:
        if acct.parent_id:
            direct_accounts.setdefault(acct.parent_id, []).append(acct.account_id)

    # Recursive computation
    result: dict[str, set[str]] = {}

    def _collect_recursive(scope_id: str) -> set[str]:
        if scope_id in result:
            return result[scope_id]

        acct_set: set[str] = set()
        # Add direct accounts
        for aid in direct_accounts.get(scope_id, []):
            acct_set.add(aid)
        # Recurse into child OUs
        for child_ou in children_map.get(scope_id, []):
            acct_set |= _collect_recursive(child_ou)

        result[scope_id] = acct_set
        return acct_set

    # Compute for root
    _collect_recursive(root_id)

    # Compute for each OU
    for ou in ous:
        _collect_recursive(ou.ou_id)

    # Add individual account scopes (account-level SCP attachment)
    for acct in accounts:
        result[acct.account_id] = {acct.account_id}

    return result


def _scp_confidence(parse_status: str) -> int:
    """Map SCP parse_status to initial confidence_q per R05."""
    if parse_status == "complete":
        return 800
    if parse_status == "partial":
        return 300
    return 100
