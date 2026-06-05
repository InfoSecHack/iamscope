"""Permission boundary constraint builder.

Parses IAM permission boundary policies into Constraint objects and
binds them to edges where the constrained principal has the boundary.

Permission boundaries define the *maximum* permissions a principal
can have — the effective permissions are the intersection of identity
policies and the boundary. This means a boundary acts as a ceiling,
similar to SCPs but scoped per-principal.

Binding rules:
- Permission edges: bind to edges where src has the boundary
- Trust edges: do not bind. Permission boundaries constrain a principal's
  effective permissions; they do not constrain who can assume that principal
  through a trust policy.

BND-1 post-fix behaviour (S03):
- If the constraint's `parse_status` is "complete", compare the edge's
  action against the boundary's `allowed_actions` list with case-insensitive
  fnmatch. Action in the allowed set → `likely_blocking=False`; action not
  in the allowed set → `likely_blocking=True`. Both cases emit
  `governance_confidence="complete"`.
- Otherwise (parse_status != "complete", including legacy constraints that
  don't carry the field), emit the pre-fix shape: `likely_blocking=False,
  governance_confidence="needs_review"`.

Boundaries are positive-list only — there is no NotAction semantics here,
so the primitive in use is simpler than `scp_binder._match_scp_action`
(no deny/NotAction inversion). The matching helper below mirrors that
function's deny-branch so behaviour stays aligned across files.
"""

from __future__ import annotations

import fnmatch
import logging
from typing import Any

from iamscope.constants import (
    CONFIDENCE_Q_PERMISSION_BOUNDARY,
    CONSTRAINT_STATUS_ACTIVE,
    CONSTRAINT_TYPE_PERMISSION_BOUNDARY,
    PROVIDER_AWS,
    REGION_GLOBAL,
    VALIDATION_STATUS_NEEDS_REVIEW,
)
from iamscope.models import Constraint, Edge, EdgeConstraint, Node

logger = logging.getLogger(__name__)


def build_permission_boundary_constraints(
    boundary_policies: dict[str, dict],
) -> list[Constraint]:
    """Create Constraint objects from permission boundary policy documents.

    Args:
        boundary_policies: Map of boundary_arn → policy_document.

    Returns:
        List of PermissionBoundary Constraint objects.
    """
    constraints: list[Constraint] = []

    for boundary_arn, policy_doc in sorted(boundary_policies.items()):
        allowed_actions = _extract_allowed_actions(policy_doc)
        boundary_statements = _extract_boundary_statements(policy_doc)

        constraint = Constraint(
            provider=PROVIDER_AWS,
            constraint_type=CONSTRAINT_TYPE_PERMISSION_BOUNDARY,
            scope_type="Principal",
            scope_id=boundary_arn,
            policy_id=boundary_arn,
            statement_id="PermissionBoundary",
            region=REGION_GLOBAL,
            properties={
                "boundary_arn": boundary_arn,
                "allowed_actions": allowed_actions,
                "boundary_statements": boundary_statements,
                "statement_count": _count_allow_statements(policy_doc),
            },
            status=CONSTRAINT_STATUS_ACTIVE,
            validation_status=VALIDATION_STATUS_NEEDS_REVIEW,
            confidence_q=CONFIDENCE_Q_PERMISSION_BOUNDARY,
        )
        constraints.append(constraint)
        logger.debug("Built boundary constraint for %s (%d allowed actions)", boundary_arn, len(allowed_actions))

    return constraints


def bind_permission_boundaries(
    edges: list[Edge],
    nodes: list[Node],
    constraints: list[Constraint],
) -> list[EdgeConstraint]:
    """Bind permission boundary constraints to edges.

    A boundary applies to permission edges where the edge source is the
    constrained principal. It intentionally does not bind to trust edges:
    permission boundaries constrain what a principal can do after credentials
    exist, not who can assume a role through its trust policy.

    Post-BND-1 (S03): the binding now computes action intersection against
    the boundary's `allowed_actions`. See the module docstring for the
    decision table.

    Args:
        edges: All edges (trust + permission).
        nodes: All nodes (to look up boundary ARNs).
        constraints: PermissionBoundary constraints from build_permission_boundary_constraints.

    Returns:
        List of EdgeConstraint bindings.
    """
    if not constraints:
        return []

    # Build lookup: provider_id → boundary_arn
    boundary_by_principal: dict[str, str] = {}
    for node in nodes:
        boundary_arn = node.properties.get("permission_boundary_arn", "")
        if boundary_arn:
            boundary_by_principal[node.provider_id] = boundary_arn

    if not boundary_by_principal:
        return []

    # Build lookup: boundary_arn → Constraint (need full constraint for properties)
    constraint_by_boundary: dict[str, Constraint] = {}
    for c in constraints:
        if c.constraint_type == CONSTRAINT_TYPE_PERMISSION_BOUNDARY:
            boundary_arn = c.properties.get("boundary_arn", "")
            if boundary_arn:
                constraint_by_boundary[boundary_arn] = c

    edge_constraints: list[EdgeConstraint] = []

    for edge in edges:
        if "_permission" not in edge.edge_type:
            continue

        constrained_id = edge.src.provider_id
        side = "src"

        boundary_arn = boundary_by_principal.get(constrained_id, "")
        if not boundary_arn or boundary_arn not in constraint_by_boundary:
            continue

        constraint = constraint_by_boundary[boundary_arn]
        ec = _evaluate_boundary_binding(edge, constraint, side, boundary_arn)
        edge_constraints.append(ec)

    logger.info(
        "Bound %d permission boundary constraints to %d edges",
        len(constraint_by_boundary),
        len(edge_constraints),
    )
    return edge_constraints


def _evaluate_boundary_binding(
    edge: Edge,
    constraint: Constraint,
    side: str,
    boundary_arn: str,
) -> EdgeConstraint:
    """Compute the EdgeConstraint for a boundary applying to an edge.

    Permission boundaries are intersections: an identity permission is usable
    only if the boundary has an applicable Allow and no applicable Deny. This
    evaluator is deliberately conservative. It returns complete blocking only
    for simple Action/Resource matches it can prove. Conditional or unsupported
    boundary shapes become needs_review rather than hard claims.
    """
    props = constraint.properties
    parse_status = props.get("parse_status", "complete")

    if parse_status != "complete":
        return EdgeConstraint(
            edge_id=edge.edge_id,
            constraint_id=constraint.constraint_id,
            governance_confidence="needs_review",
            likely_blocking=False,
            binding_reason=(
                f"{side} has permission boundary {boundary_arn}; "
                f"parse_status={parse_status!r}, cannot evaluate intersection"
            ),
        )

    edge_action = _extract_edge_action(edge.edge_type)
    if edge_action is None:
        return EdgeConstraint(
            edge_id=edge.edge_id,
            constraint_id=constraint.constraint_id,
            governance_confidence="needs_review",
            likely_blocking=False,
            binding_reason=(
                f"{side} has permission boundary {boundary_arn}; edge_type {edge.edge_type!r} has no extractable action"
            ),
        )

    edge_resource = edge.dst.provider_id
    statements = props.get("boundary_statements")
    if not statements:
        # Legacy constraints from before resource-aware parsing: retain the
        # previous action-only behavior for backward compatibility.
        allowed_actions: list[str] = props.get("allowed_actions", [])
        if _action_in_allowed_set(edge_action, allowed_actions):
            return EdgeConstraint(
                edge_id=edge.edge_id,
                constraint_id=constraint.constraint_id,
                governance_confidence="complete",
                likely_blocking=False,
                binding_reason=(
                    f"{side} has permission boundary {boundary_arn}; action {edge_action} matches allowed_actions"
                ),
            )
        return EdgeConstraint(
            edge_id=edge.edge_id,
            constraint_id=constraint.constraint_id,
            governance_confidence="complete",
            likely_blocking=True,
            binding_reason=(
                f"{side} has permission boundary {boundary_arn}; "
                f"action {edge_action} not in allowed_actions ({len(allowed_actions)} entries)"
            ),
        )

    decision = _evaluate_boundary_statements(
        edge_action=edge_action,
        edge_resource=edge_resource,
        statements=statements,
    )
    return EdgeConstraint(
        edge_id=edge.edge_id,
        constraint_id=constraint.constraint_id,
        governance_confidence=decision["governance_confidence"],
        likely_blocking=decision["likely_blocking"],
        binding_reason=(f"{side} has permission boundary {boundary_arn}; {decision['reason']}"),
    )


def _extract_edge_action(edge_type: str) -> str | None:
    """Return the action portion of an edge_type string.

    Edge types follow the pattern `<action>_<layer>` where layer is
    `permission` (e.g. `iam:PassRole_permission`). Returns None if
    the suffix does not match.
    """
    if edge_type.endswith("_permission"):
        return edge_type[: -len("_permission")]
    return None


def _action_in_allowed_set(edge_action: str, allowed_actions: list[str]) -> bool:
    """Case-insensitive fnmatch check: is edge_action in the allowed set?

    Mirrors the deny-branch primitive of `scp_binder._match_scp_action`
    so matching semantics stay consistent across files. Boundaries are
    positive-list only (no NotAction), which is why this is a separate
    helper rather than a direct reuse — the SCP helper's NotAction branch
    has no meaning for boundaries.
    """
    if not allowed_actions:
        return False
    action_lower = edge_action.lower()
    return any(fnmatch.fnmatch(action_lower, allowed.lower()) for allowed in allowed_actions)


def _evaluate_boundary_statements(
    *,
    edge_action: str,
    edge_resource: str,
    statements: list[dict[str, Any]],
) -> dict[str, Any]:
    """Evaluate simple boundary statement intersection for one edge."""
    ambiguous_matches = 0
    unsupported_relevant = 0
    unconditional_allow_match = False

    for stmt in statements:
        effect = stmt.get("effect")
        if stmt.get("unsupported"):
            unsupported_relevant += 1
            continue
        if not _action_in_allowed_set(edge_action, stmt.get("actions", [])):
            continue
        if not _resource_in_allowed_set(edge_resource, stmt.get("resources", [])):
            continue
        if stmt.get("has_conditions"):
            ambiguous_matches += 1
            continue
        if effect == "Deny":
            return {
                "governance_confidence": "complete",
                "likely_blocking": True,
                "reason": (f"explicit boundary Deny matches action {edge_action} and resource {edge_resource}"),
            }
        if effect == "Allow":
            unconditional_allow_match = True

    if unconditional_allow_match:
        return {
            "governance_confidence": "complete",
            "likely_blocking": False,
            "reason": (f"boundary Allow matches action {edge_action} and resource {edge_resource}"),
        }

    if ambiguous_matches or unsupported_relevant:
        return {
            "governance_confidence": "needs_review",
            "likely_blocking": False,
            "reason": (
                f"boundary has {ambiguous_matches} conditional and "
                f"{unsupported_relevant} unsupported statement(s) that may affect "
                f"action {edge_action} on resource {edge_resource}"
            ),
        }

    return {
        "governance_confidence": "complete",
        "likely_blocking": True,
        "reason": (f"no boundary Allow matches action {edge_action} and resource {edge_resource}"),
    }


def _extract_allowed_actions(policy_doc: dict[str, Any]) -> list[str]:
    """Extract allowed actions from a permission boundary policy."""
    actions: list[str] = []
    for stmt in _statements(policy_doc):
        if stmt.get("Effect") != "Allow":
            continue
        stmt_actions = stmt.get("Action", [])
        if isinstance(stmt_actions, str):
            stmt_actions = [stmt_actions]
        actions.extend(stmt_actions)
    return sorted(set(actions))


def _count_allow_statements(policy_doc: dict[str, Any]) -> int:
    """Count Allow statements in policy."""
    return sum(1 for stmt in _statements(policy_doc) if stmt.get("Effect") == "Allow")


def _extract_boundary_statements(policy_doc: dict[str, Any]) -> list[dict[str, Any]]:
    """Extract simple Allow/Deny boundary statement rows for intersection."""
    rows: list[dict[str, Any]] = []
    for index, stmt in enumerate(_statements(policy_doc)):
        effect = stmt.get("Effect")
        if effect not in ("Allow", "Deny"):
            continue
        unsupported = "NotAction" in stmt or "NotResource" in stmt
        rows.append(
            {
                "effect": effect,
                "actions": _string_list(stmt.get("Action", [])),
                "resources": _string_list(stmt.get("Resource", "*")),
                "has_conditions": bool(stmt.get("Condition")),
                "unsupported": unsupported,
                "unsupported_reason": "NotAction/NotResource" if unsupported else "",
                "statement_index": index,
                "sid": stmt.get("Sid", ""),
            }
        )
    return rows


def _resource_in_allowed_set(edge_resource: str, allowed_resources: list[str]) -> bool:
    """Case-sensitive ARN/resource fnmatch check for boundary Resource."""
    if not allowed_resources:
        return False
    return any(fnmatch.fnmatch(edge_resource, resource) for resource in allowed_resources)


def _statements(policy_doc: dict[str, Any]) -> list[dict[str, Any]]:
    raw = policy_doc.get("Statement", [])
    if isinstance(raw, dict):
        return [raw]
    if isinstance(raw, list):
        return [stmt for stmt in raw if isinstance(stmt, dict)]
    return []


def _string_list(value: Any) -> list[str]:
    if isinstance(value, str):
        return [value]
    if isinstance(value, list):
        return [v for v in value if isinstance(v, str)]
    return []
