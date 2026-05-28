"""Permission edge builder — converts PermissionParseResults into _permission edges.

Implements architecture doc R08:
- Specific resource ARN → individual _permission edge (src → dst role)
- Wildcard resource + expand mode → individual edges for each known role
- Wildcard resource + warn mode → single __hyperedge__ (suppressed)
- Wildcard resource + skip mode → nothing emitted
- Hard limit 500 per expansion forces warn mode (non-overridable)

Also handles iam:PassRole edges with the same expansion logic,
using passrole_mode from the ExpansionController.

Per-principal cumulative budget:
- Tracks total expanded edges per source principal across all wildcard expansions
- Warns at CUMULATIVE_WARN_THRESHOLD (200) edges per principal
- Forces warn mode at CUMULATIVE_HARD_CAP (500) edges per principal
- Prevents the N² blowup: 3 users × (50 PassRole targets + 50 Lambda functions)
  = 300 expanded edges that sneak past the per-expansion 500 limit

All operations are deterministic: same inputs → same outputs.
"""

from __future__ import annotations

import fnmatch
import logging
from collections import defaultdict
from typing import Any

from iamscope.constants import (
    EDGE_LAYER_PERMISSION,
    EXPANSION_MODE_SKIP,
    NODE_TYPE_EC2_INSTANCE,
    NODE_TYPE_ECS_CLUSTER,
    NODE_TYPE_HYPEREDGE,
    NODE_TYPE_IAM_GROUP,
    NODE_TYPE_IAM_ROLE,
    NODE_TYPE_LAMBDA_FUNCTION,
    NODE_TYPE_S3_BUCKET,
    NODE_TYPE_SECRETS_MANAGER_SECRET,
    PROVIDER_AWS,
    REGION_GLOBAL,
)
from iamscope.controls.expansion import ExpansionController
from iamscope.models import ControlRef, Edge, Node, NodeRef, PermissionParseResult

logger = logging.getLogger(__name__)

# Per-principal cumulative expansion budget
CUMULATIVE_WARN_THRESHOLD: int = 200
CUMULATIVE_HARD_CAP: int = 500


def build_permission_edges(
    parse_results: list[PermissionParseResult],
    expansion_controller: ExpansionController,
    known_role_arns: list[str],
) -> tuple[list[Edge], list[Node]]:
    """Convert PermissionParseResults into _permission edges.

    For wildcard resources, applies expansion controls:
    - expand: create individual edges to each matching known role
    - warn: create a single __hyperedge__ summarizing the wildcard grant
    - skip: emit nothing for the wildcard grant

    Per-principal cumulative tracking: if a single source principal
    accumulates more than CUMULATIVE_HARD_CAP expanded edges across
    all its wildcard grants, subsequent expansions are forced to warn
    mode regardless of config. This prevents the N² scenario where
    50 PassRole targets × 50 Lambda functions × N users overwhelms
    the graph without triggering the per-expansion 500 limit.

    Args:
        parse_results: Parsed permission grants from all policies.
        expansion_controller: Controls expansion behavior per edge type.
        known_role_arns: All role ARNs collected in this account.

    Returns:
        Tuple of (edges, hyperedge_nodes).
        hyperedge_nodes should be added to the graph's node list.
    """
    edges: list[Edge] = []
    hyperedge_nodes: list[Node] = []

    # Per-principal cumulative expansion counter
    principal_expansion_count: dict[str, int] = defaultdict(int)

    for pr in parse_results:
        if pr.is_wildcard_resource:
            new_edges, new_nodes = _handle_wildcard_resource(
                pr,
                expansion_controller,
                known_role_arns,
                principal_expansion_count,
            )
            edges.extend(new_edges)
            hyperedge_nodes.extend(new_nodes)
        else:
            edge = _build_specific_edge(pr)
            if edge is not None:
                edges.append(edge)
                expansion_controller.register_edges(1)

    # Deduplicate hyperedge nodes by node_id
    seen_ids: set[str] = set()
    unique_nodes: list[Node] = []
    for node in hyperedge_nodes:
        if node.node_id not in seen_ids:
            seen_ids.add(node.node_id)
            unique_nodes.append(node)

    # Sort for determinism
    edges.sort(key=lambda e: e.edge_id)
    unique_nodes.sort(key=lambda n: n.node_id)

    return edges, unique_nodes


def _handle_wildcard_resource(
    pr: PermissionParseResult,
    expansion_controller: ExpansionController,
    known_role_arns: list[str],
    principal_expansion_count: dict[str, int],
) -> tuple[list[Edge], list[Node]]:
    """Handle a wildcard resource permission grant with expansion controls.

    Applies per-principal cumulative budget on top of the expansion
    controller's per-expansion and global limits.

    BUG-022: for non-role edge types — `lambda:InvokeFunction`,
    `lambda:CreateFunction`, `secretsmanager:GetSecretValue`,
    `s3:PutBucketPolicy`, `iam:AddUserToGroup`, `ec2:RunInstances`,
    `ecs:RegisterTaskDefinition`, `ecs:RunTask` — the resource
    pattern targets a non-role resource type, so filtering the
    pattern against `known_role_arns` is meaningless (zero matches
    by construction) and would previously have caused either a
    silent drop of the edge (zero-match "expand" mode) or produced
    a misleading empty hyperedge. Go straight to a hyperedge that
    records the wildcard pattern and its source statement — the
    downstream reasoners (`secrets_blast_radius`, `s3_bucket_takeover`,
    etc.) already know how to read hyperedge dst as check-2-UNKNOWN
    and emit INCONCLUSIVE verdicts with the wildcard pattern visible
    in the finding evidence.

    For `passrole` and `assume_role` edge types the target IS a role
    and the existing `known_role_arns` expansion applies unchanged.

    Returns:
        Tuple of (edges, hyperedge_nodes).
    """
    edge_type_key = _get_expansion_edge_type(pr.action)

    # Non-role edge types (lambda, ec2, secretsmanager, s3, ecs, etc.)
    # cannot meaningfully expand against known_role_arns — the
    # expansion target list is role ARNs and these resources aren't
    # roles, so the match count is zero by construction (BUG-022).
    #
    # But the expansion controller's MODE must still be consulted
    # before emitting anything — lambda_mode="skip" or ec2_mode="skip"
    # must suppress the hyperedge entirely. Pre-v0.2.38 the mode
    # check was bypassed along with the expansion matching (BUG-022's
    # early return at the old line 155), which meant skip mode was
    # silently ignored for non-role wildcard permissions. Reviewer
    # Top 10 #3.
    if edge_type_key not in ("passrole", "assume_role"):
        mode, _ = expansion_controller.check_expansion(0, edge_type_key)
        if mode == EXPANSION_MODE_SKIP:
            return [], []
        return _build_hyperedge(pr, would_expand_to=0)

    # Role-targeted edge types: filter known roles, then check mode
    # with the actual expansion count.
    matching_roles = _filter_matching_roles(pr.resource_pattern, known_role_arns)
    expansion_count = len(matching_roles)

    mode, warnings = expansion_controller.check_expansion(expansion_count, edge_type_key)

    for w in warnings:
        logger.warning("Expansion warning for %s: %s", pr.source_arn, w)

    if mode == "skip":
        return [], []

    # Per-principal cumulative budget check (only for expand mode)
    if mode == "expand":
        current_count = principal_expansion_count[pr.source_arn]
        projected = current_count + expansion_count

        if projected > CUMULATIVE_HARD_CAP:
            logger.warning(
                "Per-principal cumulative expansion cap reached for %s: "
                "%d existing + %d new = %d (cap=%d). Forcing warn mode.",
                pr.source_arn,
                current_count,
                expansion_count,
                projected,
                CUMULATIVE_HARD_CAP,
            )
            mode = "warn"
        elif projected > CUMULATIVE_WARN_THRESHOLD:
            logger.warning(
                "Per-principal cumulative expansion warning for %s: "
                "%d existing + %d new = %d (warn threshold=%d, cap=%d).",
                pr.source_arn,
                current_count,
                expansion_count,
                projected,
                CUMULATIVE_WARN_THRESHOLD,
                CUMULATIVE_HARD_CAP,
            )

    if mode == "warn":
        # Create a single __hyperedge__ summarizing the wildcard grant
        return _build_hyperedge(pr, expansion_count)

    # mode == "expand": create individual edges
    result_edges: list[Edge] = []
    for role_arn in matching_roles:
        edge = _build_expanded_edge(pr, role_arn)
        result_edges.append(edge)

    expansion_controller.register_edges(len(result_edges))
    principal_expansion_count[pr.source_arn] += len(result_edges)
    return result_edges, []


def _build_specific_edge(pr: PermissionParseResult) -> Edge | None:
    """Build a _permission edge for a specific resource ARN."""
    # Extract the target role ARN from the resource pattern
    target_arn = pr.resource_pattern

    # Determine target node type from the ARN
    target_node_type = _infer_node_type_from_arn(target_arn)

    edge_type = f"{pr.action}_{EDGE_LAYER_PERMISSION}"

    features: dict[str, Any] = {
        "action_matched_via": pr.action_matched_via,
        # DIG-1 (S05): ControlRef evidence attribution — single statement
        # on a specific-resource permission edge.
        "allow_controls": [_permission_control_ref(pr)],
        "effect": pr.effect,
        "has_conditions": pr.has_conditions,
        "is_wildcard_resource": False,
        "layer": EDGE_LAYER_PERMISSION,
        "permission_source": pr.policy_source,
        "policy_arn": pr.policy_arn,
        "policy_name": pr.policy_name,
        # PR-1 fix: propagate full condition block so downstream reasoners
        # (notably passrole_lambda) can evaluate iam:PassedToService scoping.
        # Preserves the {} default from PermissionParseResult, giving the
        # reasoner a stable `"raw_conditions" in features` precondition gate.
        "raw_conditions": pr.raw_conditions,
        "resource_pattern": pr.resource_pattern,
        "statement_index": pr.statement_index,
    }

    return Edge(
        edge_type=edge_type,
        src=NodeRef(
            provider=PROVIDER_AWS,
            node_type=pr.source_node_type,
            provider_id=pr.source_arn,
            region=REGION_GLOBAL,
        ),
        dst=NodeRef(
            provider=PROVIDER_AWS,
            node_type=target_node_type,
            provider_id=target_arn,
            region=REGION_GLOBAL,
        ),
        region=REGION_GLOBAL,
        features=features,
    )


def _build_expanded_edge(pr: PermissionParseResult, target_role_arn: str) -> Edge:
    """Build a single _permission edge from an expanded wildcard."""
    edge_type = f"{pr.action}_{EDGE_LAYER_PERMISSION}"

    features: dict[str, Any] = {
        "action_matched_via": pr.action_matched_via,
        # DIG-1 (S05): ControlRef evidence attribution — one statement
        # produced many expanded edges; all share the same digest.
        "allow_controls": [_permission_control_ref(pr)],
        "effect": pr.effect,
        "expanded_from_wildcard": True,
        "has_conditions": pr.has_conditions,
        "is_wildcard_resource": True,
        "layer": EDGE_LAYER_PERMISSION,
        "permission_source": pr.policy_source,
        "policy_arn": pr.policy_arn,
        "policy_name": pr.policy_name,
        # PR-1 fix: propagate full condition block for wildcard-expanded edges.
        "raw_conditions": pr.raw_conditions,
        "resource_pattern": pr.resource_pattern,
        "statement_index": pr.statement_index,
    }

    return Edge(
        edge_type=edge_type,
        src=NodeRef(
            provider=PROVIDER_AWS,
            node_type=pr.source_node_type,
            provider_id=pr.source_arn,
            region=REGION_GLOBAL,
        ),
        dst=NodeRef(
            provider=PROVIDER_AWS,
            node_type=NODE_TYPE_IAM_ROLE,
            provider_id=target_role_arn,
            region=REGION_GLOBAL,
        ),
        region=REGION_GLOBAL,
        features=features,
    )


def _build_hyperedge(
    pr: PermissionParseResult,
    would_expand_to: int,
) -> tuple[list[Edge], list[Node]]:
    """Build a __hyperedge__ for a suppressed wildcard expansion.

    Creates both:
    - A _permission edge pointing to the __hyperedge__ node
    - The __hyperedge__ node itself
    """
    expansion_type = _get_expansion_type(pr.action)
    hyperedge_id = f"__hyperedge__:{expansion_type}:{pr.source_account_id}"

    # Create the hyperedge node
    hyperedge_node = Node(
        provider=PROVIDER_AWS,
        node_type=NODE_TYPE_HYPEREDGE,
        provider_id=hyperedge_id,
        region=REGION_GLOBAL,
        properties={
            "expansion_type": expansion_type,
            "account_id": pr.source_account_id,
            "description": f"Suppressed wildcard {pr.action} expansion",
        },
    )

    edge_type = f"{pr.action}_{EDGE_LAYER_PERMISSION}"

    features: dict[str, Any] = {
        "action_matched_via": pr.action_matched_via,
        # DIG-1 (S05): ControlRef attribution also on warn-suppressed hyperedges,
        # so reasoners can trace back from a suppressed expansion to the exact
        # source statement even when individual target edges were collapsed.
        "allow_controls": [_permission_control_ref(pr)],
        "effect": pr.effect,
        "expansion_mode": "warn",
        "expansion_type": expansion_type,
        "has_conditions": pr.has_conditions,
        "is_wildcard_resource": True,
        "layer": EDGE_LAYER_PERMISSION,
        "permission_source": pr.policy_source,
        "policy_arn": pr.policy_arn,
        "policy_name": pr.policy_name,
        # PR-1 fix: propagate full condition block on suppressed hyperedges.
        # Maintains the "raw_conditions present on 100% of _permission edges"
        # invariant required by the passrole_lambda reasoner precondition gate,
        # including when a wildcard grant is warn-suppressed to a single edge.
        "raw_conditions": pr.raw_conditions,
        "resource_pattern": pr.resource_pattern,
        "statement_index": pr.statement_index,
        "suppressed": True,
        "would_expand_to": would_expand_to,
    }

    edge = Edge(
        edge_type=edge_type,
        src=NodeRef(
            provider=PROVIDER_AWS,
            node_type=pr.source_node_type,
            provider_id=pr.source_arn,
            region=REGION_GLOBAL,
        ),
        dst=NodeRef(
            provider=PROVIDER_AWS,
            node_type=NODE_TYPE_HYPEREDGE,
            provider_id=hyperedge_id,
            region=REGION_GLOBAL,
        ),
        region=REGION_GLOBAL,
        features=features,
    )

    return [edge], [hyperedge_node]


def _filter_matching_roles(
    resource_pattern: str,
    known_role_arns: list[str],
) -> list[str]:
    """Filter known role ARNs that match a resource pattern.

    For "*", all roles match. For patterns like "arn:aws:iam::*:role/App*",
    uses fnmatch to filter.

    Returns:
        Sorted list of matching role ARNs.
    """
    if resource_pattern == "*":
        return sorted(known_role_arns)

    pattern_lower = resource_pattern.lower()
    return sorted(arn for arn in known_role_arns if fnmatch.fnmatch(arn.lower(), pattern_lower))


def _get_expansion_edge_type(action: str) -> str:
    """Map action to expansion controller edge type key.

    The returned string must contain the substring that
    `ExpansionController.get_mode()` matches for type-specific
    overrides: "passrole" for passrole_mode, "lambda" for
    lambda_mode, "ec2" for ec2_mode. Actions that don't have a
    type-specific override map to "permission" (the generic bucket
    that falls through to global_mode).

    v0.2.38 (reviewer Top 10 #3): added "lambda" and "ec2" branches.
    Previously these fell through to "permission", which caused the
    BUG-022 non-role bypass to emit hyperedges without consulting
    the expansion controller's lambda_mode/ec2_mode overrides.
    """
    action_lower = action.lower()
    if action_lower == "iam:passrole":
        return "passrole"
    if action_lower.startswith("sts:"):
        return "assume_role"
    if action_lower.startswith("lambda:"):
        return "lambda"
    if action_lower.startswith("ec2:"):
        return "ec2"
    return "permission"


def _get_expansion_type(action: str) -> str:
    """Map action to expansion_type string for hyperedge features."""
    action_lower = action.lower()
    if action_lower == "iam:passrole":
        return "wildcard_passrole"
    if action_lower.startswith("sts:"):
        return "wildcard_assume_role"
    return "wildcard_permission"


def _permission_control_ref(pr: PermissionParseResult) -> dict[str, Any]:
    """Build a serialized ControlRef dict for a permission statement.

    DIG-1 (S05): every permission edge carries a single-element allow_controls
    list referencing the identity policy statement that granted the action.
    The digest is precomputed by the parser so the value is stable against the
    source policy bytes, not a resolver reconstruction.

    Policy identification uses the managed policy ARN when available; for
    inline policies where pr.policy_arn is empty, we fall back to None and
    let the summary string disambiguate (e.g. "inline:policy_name").
    """
    return ControlRef(
        control_type="IDENTITY_POLICY",
        policy_arn=pr.policy_arn or None,
        statement_index=pr.statement_index,
        digest=pr.statement_digest,
        summary=f"{pr.policy_source}:{pr.policy_name}",
    ).to_dict()


def _infer_node_type_from_arn(arn: str) -> str:
    """Infer node type from a resource ARN.

    TYP-1 fix (S04): recognises common non-role resource types that can
    appear as PassRole / permission edge targets. Falls back to IAMRole
    for role ARNs and for any unrecognised pattern (preserving the legacy
    default so unknown resource types don't break existing behaviour).

    Recognised substrings (checked in order):

    - `:role/`      → IAMRole                (pre-existing)
    - `:function:`  → LambdaFunction         (Lambda, canonical colon form)
    - `:function/`  → LambdaFunction         (plan-literal slash form, kept
                                              for forward compatibility)
    - `:cluster/`   → ECSCluster
    - `:instance/`  → EC2Instance
    - `:secret:`    → SecretsManagerSecret
    - `:group/`     → IAMGroup
    - `:s3:::`      → S3Bucket                (global S3 namespace, no region/account)
    - otherwise     → IAMRole                (legacy fallback; see handoff D9)
    """
    # Check role first — it's the primary case and must not be shadowed.
    if ":role/" in arn:
        return NODE_TYPE_IAM_ROLE
    if ":function:" in arn or ":function/" in arn:
        return NODE_TYPE_LAMBDA_FUNCTION
    if ":cluster/" in arn:
        return NODE_TYPE_ECS_CLUSTER
    if ":instance/" in arn:
        return NODE_TYPE_EC2_INSTANCE
    if ":secret:" in arn:
        return NODE_TYPE_SECRETS_MANAGER_SECRET
    if ":group/" in arn:
        return NODE_TYPE_IAM_GROUP
    if ":s3:::" in arn:
        return NODE_TYPE_S3_BUCKET
    # Unrecognised pattern → legacy default (IAMRole).
    return NODE_TYPE_IAM_ROLE
