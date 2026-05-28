"""SCP binder — binds SCP constraints to matching edges with governance metadata.

Implements architecture doc §5.5, §10.1-10.4:
- Matches SCP deny_actions/deny_not_actions against edge actions
- Extracts edge action from edge_type (e.g., "sts:AssumeRole" from "sts:AssumeRole_trust")
- Suppresses Deny bindings when a supported positive aws:PrincipalArn
  applicability filter definitively does not match the edge source
- Checks exception patterns against edge src principal
- Computes likely_blocking, governance_confidence, confidence_q
- Propagates OU inheritance: SCP on parent OU applies to all child accounts/OUs

CRITICAL correctness rules:
1. NotAction inversion (§10.1): if edge action NOT in deny_not_actions → IS denied
2. Exception matching checked BEFORE likely_blocking (Invariant #16)
3. likely_blocking=true requires parse_status="complete" (Invariant #17)
4. SCP governance feeds into downstream risk scoring (Invariant #4/R01)

All operations are deterministic: same inputs → same bindings.
"""

from __future__ import annotations

import fnmatch
import logging
from typing import Any

from iamscope.constants import (
    CONFIDENCE_Q_COMPLETE_BLOCKING,
    CONFIDENCE_Q_COMPLETE_NOT_BLOCKING,
    CONFIDENCE_Q_PARTIAL,
    CONFIDENCE_Q_UNSUPPORTED,
    GOVERNANCE_CONFIDENCE_COMPLETE,
    GOVERNANCE_CONFIDENCE_NEEDS_REVIEW,
    GOVERNANCE_CONFIDENCE_PARTIAL,
    PARSE_STATUS_COMPLETE,
    PARSE_STATUS_PARTIAL,
)
from iamscope.models import Constraint, Edge, EdgeConstraint

logger = logging.getLogger(__name__)


def bind_scp_to_edge(
    edge: Edge,
    constraint: Constraint,
) -> EdgeConstraint | None:
    """Attempt to bind an SCP constraint to an edge.

    Checks if the SCP's deny_actions or deny_not_actions match the
    edge's action. If matched, creates an EdgeConstraint binding
    with governance metadata.

    Args:
        edge: The edge to check.
        constraint: The SCP constraint to bind.

    Returns:
        EdgeConstraint if the SCP matches the edge action, None otherwise.
    """
    props = constraint.properties
    edge_action = _extract_action_from_edge_type(edge.edge_type)

    deny_actions: list[str] = props.get("deny_actions", [])
    deny_not_actions: list[str] = props.get("deny_not_actions", [])

    # Check if the SCP matches this edge's action
    if not _match_scp_action(edge_action, deny_actions, deny_not_actions):
        return None

    resource_patterns: list[str] = props.get("resource_patterns", ["*"])
    if not _match_scp_resource(edge, resource_patterns):
        return None

    # Positive PrincipalArn filters are applicability gates, not blockers.
    # If the edge source does not match one of the supported patterns, the
    # Deny statement is not applicable to this edge at all.
    if not _check_principal_applicability_match(edge, props):
        return None

    # Check exception patterns — if edge matches an exception, SCP doesn't block
    parse_status: str = props.get("parse_status", "complete")
    exception_match = _check_exception_match(edge, props)

    # Compute governance metadata
    likely_blocking = _compute_likely_blocking(
        action_matched=True,
        exception_match=exception_match,
        parse_status=parse_status,
    )
    governance_confidence = _compute_governance_confidence(parse_status, likely_blocking)
    binding_reason = _build_binding_reason(
        edge_action,
        deny_actions,
        deny_not_actions,
        exception_match,
        resource_patterns,
        props.get("applicable_principal_patterns", []),
    )

    # SCP-1 fix (S04): when the SCP has org_id or account_id exceptions populated,
    # we cannot confidently claim a block without knowing the source principal's
    # org/account membership. IAMScope has no org membership resolver for external
    # principals today, so the safest move is to downgrade to needs_review rather
    # than emit a high-confidence block that might be wrong. The downgrade is
    # scoped to likely_blocking=True cases — if we're not claiming a block anyway
    # (action miss, principal exception match, or non-complete parse), the
    # downgrade has no signal value and we leave the binding alone.
    exception_org_ids: list[str] = props.get("exception_org_ids", [])
    exception_account_ids: list[str] = props.get("exception_account_ids", [])
    if likely_blocking and (exception_org_ids or exception_account_ids):
        governance_confidence = "needs_review"
        binding_reason = (
            f"{binding_reason} | downgraded: "
            f"exception_org_ids={len(exception_org_ids)}, "
            f"exception_account_ids={len(exception_account_ids)}; "
            f"source principal org/account membership unresolved"
        )

    return EdgeConstraint(
        edge_id=edge.edge_id,
        constraint_id=constraint.constraint_id,
        governance_confidence=governance_confidence,
        likely_blocking=likely_blocking,
        binding_reason=binding_reason,
    )


def bind_all_scps(
    edges: list[Edge],
    constraints: list[Constraint],
    ou_account_map: dict[str, set[str]] | None = None,
) -> list[EdgeConstraint]:
    """Bind all SCP constraints to all matching edges.

    For each (edge, constraint) pair, checks if the SCP's action scope
    matches the edge action. OU inheritance is handled by checking if
    the edge's destination account is within the constraint's scope.

    Args:
        edges: All edges in the graph.
        constraints: All SCP constraints.
        ou_account_map: Mapping from scope_id (OU or account) → set of
                       account IDs under that scope. Used for OU inheritance.
                       If None, scope matching is skipped (all constraints
                       applied globally).

    Returns:
        Sorted list of EdgeConstraint bindings.
    """
    bindings: list[EdgeConstraint] = []

    for edge in edges:
        dst_account = _extract_account_from_ref(edge.dst)

        for constraint in constraints:
            # Check scope: does this SCP apply to the edge's destination account?
            if ou_account_map is not None and dst_account:
                scope_accounts = ou_account_map.get(constraint.scope_id, set())
                if dst_account not in scope_accounts:
                    continue

            binding = bind_scp_to_edge(edge, constraint)
            if binding is not None:
                bindings.append(binding)

    # Sort by composite key for determinism
    bindings.sort(key=lambda ec: ec.sort_key)
    return bindings


def _extract_action_from_edge_type(edge_type: str) -> str:
    """Extract the action from an edge_type string.

    Example: "sts:AssumeRole_trust" → "sts:AssumeRole"
             "iam:PassRole_permission" → "iam:PassRole"
             "lambda:InvokeFunction_trust" → "lambda:InvokeFunction"
    """
    # Split on last underscore (layer suffix)
    parts = edge_type.rsplit("_", 1)
    return parts[0] if len(parts) >= 1 else edge_type


def _match_scp_action(
    edge_action: str,
    deny_actions: list[str],
    deny_not_actions: list[str],
) -> bool:
    """Check if an SCP matches an edge action.

    Two modes:
    1. deny_actions: SCP denies specific actions. Match if edge_action in list.
    2. deny_not_actions (NotAction): SCP denies everything EXCEPT listed actions.
       Match if edge_action is NOT in the exception list (= it IS denied).

    Action matching uses case-insensitive comparison and supports wildcards
    via fnmatch (e.g., "sts:*" matches "sts:AssumeRole").

    Args:
        edge_action: The action to check (e.g., "sts:AssumeRole").
        deny_actions: List of actions explicitly denied.
        deny_not_actions: List of actions NOT denied (NotAction).

    Returns:
        True if the SCP would deny this action.
    """
    action_lower = edge_action.lower()

    if deny_actions:
        # Standard deny: match if edge action is in deny list
        return any(fnmatch.fnmatch(action_lower, da.lower()) for da in deny_actions)

    if deny_not_actions:
        # NotAction inversion (§10.1 CRITICAL):
        # If edge action NOT in the exception list → it IS denied
        is_excepted = any(fnmatch.fnmatch(action_lower, dna.lower()) for dna in deny_not_actions)
        return not is_excepted

    # No actions specified — can't match
    return False


def _match_scp_resource(edge: Edge, resource_patterns: list[str]) -> bool:
    """Check if the SCP resource scope matches the edge target resource."""
    if not resource_patterns:
        return True
    if "*" in resource_patterns:
        return True
    dst_resource = edge.dst.provider_id.lower()
    return any(fnmatch.fnmatch(dst_resource, pattern.lower()) for pattern in resource_patterns)


def _check_exception_match(
    edge: Edge,
    constraint_properties: dict[str, Any],
) -> bool:
    """Check if the edge's source principal matches an SCP exception pattern.

    If matched, the SCP does NOT block this edge (the principal is excepted).

    Checks exception_principal_patterns using fnmatch against the source
    principal's provider_id (ARN).

    Args:
        edge: The edge to check (uses src.provider_id).
        constraint_properties: The SCP constraint's properties dict.

    Returns:
        True if the edge matches an exception (SCP does NOT block).
    """
    src_arn = edge.src.provider_id.lower()

    # Principal ARN exceptions
    principal_patterns: list[str] = constraint_properties.get("exception_principal_patterns", [])
    # Org ID / account ID exceptions are handled at the caller level via
    # governance_confidence downgrade (SCP-1 fix, S04, in bind_scp_to_edge).
    # We do not mark them as principal-level exception matches here because
    # we don't have org membership for external principals — downgrade is
    # the safe move, not suppression.

    return any(fnmatch.fnmatch(src_arn, pattern.lower()) for pattern in principal_patterns)


def _check_principal_applicability_match(
    edge: Edge,
    constraint_properties: dict[str, Any],
) -> bool:
    """Return whether a positive PrincipalArn Deny filter applies to this edge.

    Supported positive PrincipalArn filters are parsed into
    applicable_principal_patterns. If no supported filter is present, keep the
    existing conservative binding behavior. If one is present, the Deny applies
    only when the edge source ARN matches at least one pattern.
    """
    applicable_patterns: list[str] = constraint_properties.get("applicable_principal_patterns", [])
    if not applicable_patterns:
        return True

    src_arn = edge.src.provider_id.lower()
    return any(fnmatch.fnmatch(src_arn, pattern.lower()) for pattern in applicable_patterns)


def _compute_likely_blocking(
    action_matched: bool,
    exception_match: bool,
    parse_status: str,
) -> bool:
    """Compute whether the SCP is likely blocking this edge.

    Rules (from architecture doc invariants):
    - Invariant #16: Exception matching checked BEFORE likely_blocking
    - Invariant #17: likely_blocking=true requires parse_status="complete"

    Args:
        action_matched: Whether the SCP action matches the edge.
        exception_match: Whether the edge matches an SCP exception.
        parse_status: The SCP's parse_status.

    Returns:
        True if the SCP is likely blocking this edge.
    """
    if not action_matched:
        return False

    # Exception match means SCP doesn't block this principal
    if exception_match:
        return False

    # Invariant #17: likely_blocking requires complete parse
    return parse_status == PARSE_STATUS_COMPLETE


def _compute_governance_confidence(parse_status: str, likely_blocking: bool) -> str:
    """Map parse_status + likely_blocking to governance_confidence enum.

    Returns:
        One of: "complete", "partial", "needs_review"
    """
    if parse_status == PARSE_STATUS_COMPLETE:
        return GOVERNANCE_CONFIDENCE_COMPLETE

    if parse_status == PARSE_STATUS_PARTIAL:
        return GOVERNANCE_CONFIDENCE_PARTIAL

    # unsupported or unknown
    return GOVERNANCE_CONFIDENCE_NEEDS_REVIEW


def compute_confidence_q(parse_status: str, likely_blocking: bool) -> int:
    """Map parse_status + likely_blocking to confidence_q integer.

    Mapping (from Phase A R05):
    - complete + blocking: 800
    - complete + not blocking: 500
    - partial: 300
    - unsupported: 100
    """
    if parse_status == PARSE_STATUS_COMPLETE:
        if likely_blocking:
            return CONFIDENCE_Q_COMPLETE_BLOCKING
        return CONFIDENCE_Q_COMPLETE_NOT_BLOCKING

    if parse_status == PARSE_STATUS_PARTIAL:
        return CONFIDENCE_Q_PARTIAL

    return CONFIDENCE_Q_UNSUPPORTED


def _build_binding_reason(
    edge_action: str,
    deny_actions: list[str],
    deny_not_actions: list[str],
    exception_match: bool,
    resource_patterns: list[str],
    applicable_principal_patterns: list[str],
) -> str:
    """Build a human-readable binding reason string."""
    parts: list[str] = []

    if deny_actions:
        parts.append(f"edge action {edge_action} in SCP deny_actions")
    elif deny_not_actions:
        parts.append(f"edge action {edge_action} not in SCP deny_not_actions (NotAction inversion)")

    if exception_match:
        parts.append("but principal matches exception pattern")

    if resource_patterns and resource_patterns != ["*"]:
        parts.append(f"resource matches SCP resource_patterns={resource_patterns}")

    if applicable_principal_patterns:
        parts.append(f"source principal matches applicable_principal_patterns={applicable_principal_patterns}")

    return "; ".join(parts)


def _extract_account_from_ref(ref: Any) -> str | None:
    """Extract account ID from a NodeRef's provider_id (ARN)."""
    provider_id = getattr(ref, "provider_id", "")
    if not provider_id or provider_id == "*":
        return None
    parts = provider_id.split(":")
    if len(parts) >= 5 and len(parts[4]) == 12 and parts[4].isdigit():
        return parts[4]
    return None
