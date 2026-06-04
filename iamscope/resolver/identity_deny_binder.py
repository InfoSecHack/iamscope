"""Identity-policy Deny binder.

Converts parsed identity-policy Deny statements into constraints and binds
those constraints to matching permission edges.
"""

from __future__ import annotations

import fnmatch

from iamscope.constants import (
    CONFIDENCE_Q_COMPLETE_BLOCKING,
    CONFIDENCE_Q_PARTIAL,
    CONSTRAINT_STATUS_ACTIVE,
    CONSTRAINT_TYPE_IDENTITY_DENY,
    GOVERNANCE_CONFIDENCE_COMPLETE,
    GOVERNANCE_CONFIDENCE_NEEDS_REVIEW,
    GOVERNANCE_CONFIDENCE_PARTIAL,
    PARSE_STATUS_COMPLETE,
    PROVIDER_AWS,
    REGION_GLOBAL,
    VALIDATION_STATUS_UNVALIDATED,
)
from iamscope.models import Constraint, Edge, EdgeConstraint, PermissionDenyResult

_PERMISSION_SUFFIX = "_permission"


def build_identity_deny_constraints(
    deny_results: list[PermissionDenyResult],
) -> list[Constraint]:
    """Convert parsed identity-policy Deny statements into constraints."""
    constraints: list[Constraint] = []

    for dr in deny_results:
        if dr.has_conditions:
            confidence_q = CONFIDENCE_Q_PARTIAL
        elif dr.parse_status == PARSE_STATUS_COMPLETE:
            confidence_q = CONFIDENCE_Q_COMPLETE_BLOCKING
        else:
            confidence_q = CONFIDENCE_Q_PARTIAL

        constraints.append(
            Constraint(
                provider=PROVIDER_AWS,
                constraint_type=CONSTRAINT_TYPE_IDENTITY_DENY,
                scope_type="Principal",
                scope_id=dr.principal_arn,
                policy_id=dr.policy_arn,
                statement_id=dr.statement_id,
                region=REGION_GLOBAL,
                properties={
                    "deny_actions": list(dr.deny_actions),
                    "resource_patterns": list(dr.resource_patterns),
                    "has_conditions": dr.has_conditions,
                    "raw_conditions": dr.raw_conditions,
                    "parse_status": dr.parse_status,
                },
                status=CONSTRAINT_STATUS_ACTIVE,
                validation_status=VALIDATION_STATUS_UNVALIDATED,
                confidence_q=confidence_q,
            )
        )

    return constraints


def bind_identity_deny_to_edge(
    edge: Edge,
    constraint: Constraint,
) -> EdgeConstraint | None:
    """Bind an IDENTITY_DENY constraint to one matching permission edge."""
    if constraint.constraint_type != CONSTRAINT_TYPE_IDENTITY_DENY:
        return None
    if constraint.scope_type != "Principal":
        return None
    if constraint.scope_id != edge.src.provider_id:
        return None

    edge_action = _extract_permission_edge_action(edge)
    if edge_action is None:
        return None

    props = constraint.properties
    deny_actions: list[str] = props.get("deny_actions", [])
    resource_patterns: list[str] = props.get("resource_patterns", ["*"])
    parse_status: str = props.get("parse_status", PARSE_STATUS_COMPLETE)
    has_conditions: bool = props.get("has_conditions", False)

    if not deny_actions:
        return None
    if not _action_matches_deny(edge_action, deny_actions):
        return None

    if not _resource_matches_deny(edge.dst.provider_id, resource_patterns):
        return None

    if has_conditions:
        governance_confidence = GOVERNANCE_CONFIDENCE_NEEDS_REVIEW
    elif parse_status == PARSE_STATUS_COMPLETE:
        governance_confidence = GOVERNANCE_CONFIDENCE_COMPLETE
    else:
        governance_confidence = GOVERNANCE_CONFIDENCE_PARTIAL

    return EdgeConstraint(
        edge_id=edge.edge_id,
        constraint_id=constraint.constraint_id,
        governance_confidence=governance_confidence,
        likely_blocking=True,
        binding_reason=(
            f"identity policy Deny on {edge.src.provider_id}: "
            f"action={edge_action!r} actions={deny_actions!r} "
            f"resources={resource_patterns!r}"
            f"{' (conditional - conservative)' if has_conditions else ''}"
        ),
    )


def bind_all_identity_denies(
    permission_edges: list[Edge],
    constraints: list[Constraint],
) -> list[EdgeConstraint]:
    """Bind all IDENTITY_DENY constraints to all matching permission edges."""
    identity_deny_constraints = [c for c in constraints if c.constraint_type == CONSTRAINT_TYPE_IDENTITY_DENY]
    if not permission_edges or not identity_deny_constraints:
        return []

    bindings: list[EdgeConstraint] = []
    for edge in permission_edges:
        for constraint in identity_deny_constraints:
            binding = bind_identity_deny_to_edge(edge, constraint)
            if binding is not None:
                bindings.append(binding)

    bindings.sort(key=lambda ec: ec.sort_key)
    return bindings


def _extract_permission_edge_action(edge: Edge) -> str | None:
    """Extract the action from an `<action>_permission` edge type."""
    if not edge.edge_type.endswith(_PERMISSION_SUFFIX):
        return None
    return edge.edge_type[: -len(_PERMISSION_SUFFIX)]


def _action_matches_deny(action_to_check: str, deny_actions: list[str]) -> bool:
    """Case-insensitive fnmatch against each deny action pattern."""
    action_lower = action_to_check.lower()
    return any(fnmatch.fnmatch(action_lower, pattern.lower()) for pattern in deny_actions)


def _resource_matches_deny(resource_arn: str, resource_patterns: list[str]) -> bool:
    """Case-insensitive ARN glob match. A wildcard pattern always matches."""
    resource_lower = resource_arn.lower()
    for pattern in resource_patterns:
        if pattern == "*":
            return True
        if resource_arn == "*":
            return True
        if fnmatch.fnmatch(resource_lower, pattern.lower()):
            return True
    return False
