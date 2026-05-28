"""Trust-condition binder.

Converts conditioned trust edges into TRUST_CONDITION constraints so exported
scenario.json carries the shared trust-control family for ARF-RT.
"""

from __future__ import annotations

from typing import Any

from iamscope.constants import (
    CONFIDENCE_Q_PARTIAL,
    CONSTRAINT_STATUS_ACTIVE,
    CONSTRAINT_TYPE_TRUST_CONDITION,
    EDGE_LAYER_TRUST,
    GOVERNANCE_CONFIDENCE_NEEDS_REVIEW,
    PROVIDER_AWS,
    REGION_GLOBAL,
    VALIDATION_STATUS_NEEDS_REVIEW,
)
from iamscope.models import Constraint, Edge, EdgeConstraint

_TRUST_SUFFIX = f"_{EDGE_LAYER_TRUST}"


def build_trust_condition_constraints(trust_edges: list[Edge]) -> list[Constraint]:
    """Build one TRUST_CONDITION constraint per conditioned trust statement."""
    constraints_by_id: dict[str, Constraint] = {}

    for edge in trust_edges:
        if not _is_conditioned_trust_edge(edge):
            continue

        constraint = _constraint_for_edge(edge)
        constraints_by_id.setdefault(constraint.constraint_id, constraint)

    return sorted(constraints_by_id.values(), key=lambda c: c.constraint_id)


def bind_trust_condition_to_edge(
    edge: Edge,
    constraint: Constraint,
) -> EdgeConstraint | None:
    """Bind a TRUST_CONDITION constraint to its originating trust edge."""
    if constraint.constraint_type != CONSTRAINT_TYPE_TRUST_CONDITION:
        return None
    if not _is_conditioned_trust_edge(edge):
        return None
    if constraint.scope_id != edge.dst.provider_id:
        return None
    if constraint.policy_id != edge.dst.provider_id:
        return None
    if constraint.statement_id != _statement_id(edge):
        return None

    return EdgeConstraint(
        edge_id=edge.edge_id,
        constraint_id=constraint.constraint_id,
        governance_confidence=GOVERNANCE_CONFIDENCE_NEEDS_REVIEW,
        likely_blocking=False,
        binding_reason=(f"trust policy Condition present on {edge.dst.provider_id}; external context required"),
    )


def bind_all_trust_conditions(
    trust_edges: list[Edge],
    constraints: list[Constraint],
) -> list[EdgeConstraint]:
    """Bind all TRUST_CONDITION constraints to matching trust edges."""
    trust_condition_constraints = [c for c in constraints if c.constraint_type == CONSTRAINT_TYPE_TRUST_CONDITION]
    if not trust_edges or not trust_condition_constraints:
        return []

    bindings: list[EdgeConstraint] = []
    for edge in trust_edges:
        for constraint in trust_condition_constraints:
            binding = bind_trust_condition_to_edge(edge, constraint)
            if binding is not None:
                bindings.append(binding)

    bindings.sort(key=lambda ec: ec.sort_key)
    return bindings


def _constraint_for_edge(edge: Edge) -> Constraint:
    raw_conditions = edge.features.get("raw_conditions") or {}
    return Constraint(
        provider=PROVIDER_AWS,
        constraint_type=CONSTRAINT_TYPE_TRUST_CONDITION,
        scope_type="TrustPolicy",
        scope_id=edge.dst.provider_id,
        policy_id=edge.dst.provider_id,
        statement_id=_statement_id(edge),
        region=REGION_GLOBAL,
        properties={
            "action": _extract_trust_edge_action(edge),
            "condition_keys": _condition_keys(raw_conditions),
            "has_external_id": bool(edge.features.get("has_external_id", False)),
            "has_mfa_condition": bool(edge.features.get("has_mfa_condition", False)),
            "has_org_id_condition": bool(edge.features.get("has_org_id_condition", False)),
            "has_source_account_condition": bool(edge.features.get("has_source_account_condition", False)),
            "has_source_ip_condition": bool(edge.features.get("has_source_ip_condition", False)),
            "has_source_vpc_condition": bool(edge.features.get("has_source_vpc_condition", False)),
            "raw_conditions": raw_conditions,
        },
        status=CONSTRAINT_STATUS_ACTIVE,
        validation_status=VALIDATION_STATUS_NEEDS_REVIEW,
        confidence_q=CONFIDENCE_Q_PARTIAL,
    )


def _is_conditioned_trust_edge(edge: Edge) -> bool:
    return edge.edge_type.endswith(_TRUST_SUFFIX) and bool(edge.features.get("raw_conditions"))


def _statement_id(edge: Edge) -> str:
    return f"trust:{edge.features.get('statement_index', 0)}"


def _extract_trust_edge_action(edge: Edge) -> str:
    if not edge.edge_type.endswith(_TRUST_SUFFIX):
        return edge.edge_type
    return edge.edge_type[: -len(_TRUST_SUFFIX)]


def _condition_keys(raw_conditions: dict[str, Any]) -> list[str]:
    keys: set[str] = set()
    for operator_body in raw_conditions.values():
        if isinstance(operator_body, dict):
            keys.update(str(key) for key in operator_body)
    return sorted(keys)
