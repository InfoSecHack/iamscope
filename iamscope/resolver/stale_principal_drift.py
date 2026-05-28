"""Detect stale IAM principal unique-ID drift on policy-derived edges.

AWS rewrites some role/user ARN principals in trust/resource policies to
immutable unique principal IDs after the original IAM principal is deleted.
Those bare IDs are intentionally not reusable by a recreated role/user with
the same ARN, so they are strong evidence that the policy reference is stale.
"""

from __future__ import annotations

import re
from typing import Any

from iamscope.constants import (
    CONFIDENCE_Q_COMPLETE_BLOCKING,
    CONSTRAINT_TYPE_STALE_PRINCIPAL_DRIFT,
    EDGE_LAYER_RESOURCE_POLICY,
    EDGE_LAYER_TRUST,
    GOVERNANCE_CONFIDENCE_COMPLETE,
    PROVIDER_AWS,
    REGION_GLOBAL,
    VALIDATION_STATUS_UNVALIDATED,
)
from iamscope.models import Constraint, Edge, EdgeConstraint

_PRINCIPAL_ID_PATTERN = re.compile(r"^(AROA|AIDA)[A-Z0-9]{16,}$")
_PRINCIPAL_ID_KIND_BY_PREFIX: dict[str, str] = {
    "AROA": "role",
    "AIDA": "user",
}


def is_stale_unique_principal_id(value: str) -> bool:
    """Return True when value has the IAM role/user unique-ID placeholder shape."""
    return bool(_PRINCIPAL_ID_PATTERN.match(value))


def classify_stale_unique_principal_id(value: str) -> str:
    """Classify a stale unique-ID principal as role/user/unknown."""
    if not is_stale_unique_principal_id(value):
        return "unknown"
    return _PRINCIPAL_ID_KIND_BY_PREFIX.get(value[:4], "unknown")


def build_stale_principal_drift_constraints(
    edges: list[Edge],
) -> tuple[list[Constraint], list[EdgeConstraint]]:
    """Build constraints for trust/resource-policy edges with stale principals.

    Detection is deliberately narrow: a bare AROA*/AIDA* principal ID on a
    policy-derived edge is treated as complete stale-drift evidence. Other
    unresolved principal shapes are not guessed here.
    """
    constraints: list[Constraint] = []
    edge_constraints: list[EdgeConstraint] = []
    seen_constraints: set[str] = set()

    for edge in sorted(edges, key=lambda e: e.edge_id):
        if not _is_policy_principal_edge(edge):
            continue
        principal = edge.src.provider_id
        if not is_stale_unique_principal_id(principal):
            continue

        constraint = _constraint_for_edge(edge, principal)
        if constraint.constraint_id not in seen_constraints:
            constraints.append(constraint)
            seen_constraints.add(constraint.constraint_id)
        edge_constraints.append(
            EdgeConstraint(
                edge_id=edge.edge_id,
                constraint_id=constraint.constraint_id,
                governance_confidence=GOVERNANCE_CONFIDENCE_COMPLETE,
                likely_blocking=True,
                binding_reason=(
                    "policy principal is a stale IAM unique principal ID; "
                    "a recreated role/user with the same ARN will not satisfy this trust"
                ),
            )
        )

    return constraints, edge_constraints


def _is_policy_principal_edge(edge: Edge) -> bool:
    return edge.edge_type.endswith(f"_{EDGE_LAYER_TRUST}") or edge.edge_type.endswith(f"_{EDGE_LAYER_RESOURCE_POLICY}")


def _constraint_for_edge(edge: Edge, principal_id: str) -> Constraint:
    features = edge.features or {}
    statement_digest, statement_index, policy_arn = _statement_metadata(edge)
    policy_source = str(
        features.get("source_policy") or features.get("policy_source") or features.get("permission_source") or "policy"
    )
    return Constraint(
        provider=PROVIDER_AWS,
        constraint_type=CONSTRAINT_TYPE_STALE_PRINCIPAL_DRIFT,
        scope_type="EDGE",
        scope_id=edge.edge_id,
        policy_id=policy_arn or edge.dst.provider_id,
        statement_id=statement_digest or edge.edge_id,
        region=edge.region or REGION_GLOBAL,
        properties={
            "detection": "bare_iam_unique_principal_id",
            "drift_state": "stale_unique_id_suspected",
            "evidence_level": "complete",
            "principal_id": principal_id,
            "principal_id_kind": classify_stale_unique_principal_id(principal_id),
            "policy_source": policy_source,
            "reason": (
                "AWS IAM unique principal IDs in Principal fields usually mean "
                "the referenced role/user was deleted and the policy no longer "
                "trusts a recreated principal with the old ARN."
            ),
            "source_principal": edge.src.provider_id,
            "statement_digest": statement_digest,
            "statement_index": statement_index,
            "target": edge.dst.provider_id,
        },
        validation_status=VALIDATION_STATUS_UNVALIDATED,
        confidence_q=CONFIDENCE_Q_COMPLETE_BLOCKING,
    )


def _statement_metadata(edge: Edge) -> tuple[str, int, str]:
    controls = edge.features.get("allow_controls", []) if edge.features else []
    if controls and isinstance(controls[0], dict):
        first: dict[str, Any] = controls[0]
        return (
            str(first.get("digest", "")),
            int(first.get("statement_index", 0)),
            str(first.get("policy_arn", "")),
        )
    return (
        str(edge.features.get("statement_digest", "")) if edge.features else "",
        int(edge.features.get("statement_index", 0)) if edge.features else 0,
        edge.dst.provider_id,
    )


__all__ = [
    "build_stale_principal_drift_constraints",
    "classify_stale_unique_principal_id",
    "is_stale_unique_principal_id",
]
