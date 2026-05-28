"""Build graph edges from parsed resource-policy Allow statements."""

from __future__ import annotations

from typing import Any

from iamscope.constants import (
    CONSTRAINT_TYPE_RESOURCE_POLICY_CONDITION,
    EDGE_LAYER_RESOURCE_POLICY,
    GOVERNANCE_CONFIDENCE_NEEDS_REVIEW,
    NODE_TYPE_AWS_SERVICE,
    NODE_TYPE_EXTERNAL_ACCOUNT,
    NODE_TYPE_WILDCARD_PRINCIPAL,
    PROVIDER_AWS,
    REGION_GLOBAL,
)
from iamscope.models import Constraint, ControlRef, Edge, EdgeConstraint, Node, NodeRef, ResourcePolicyParseResult


def build_resource_policy_graph(
    parse_results: list[ResourcePolicyParseResult],
    existing_nodes: list[Node],
) -> tuple[list[Node], list[Edge], list[Constraint], list[EdgeConstraint]]:
    """Convert parsed resource policy rows into nodes, edges, and bindings."""
    known_keys = {(n.provider, n.node_type, n.provider_id) for n in existing_nodes}
    synthetic_nodes_by_key: dict[tuple[str, str, str], Node] = {}
    edges: list[Edge] = []
    constraints_by_key: dict[tuple[str, str, str, str], Constraint] = {}
    edge_constraints: list[EdgeConstraint] = []

    for result in sorted(parse_results, key=_result_sort_key):
        src_ref = NodeRef(
            provider=PROVIDER_AWS,
            node_type=result.resolved_node_type,
            provider_id=result.principal_value,
            region=REGION_GLOBAL,
        )
        src_key = (src_ref.provider, src_ref.node_type, src_ref.provider_id)
        if src_key not in known_keys and src_key not in synthetic_nodes_by_key:
            synthetic_nodes_by_key[src_key] = _synthetic_principal_node(result)

        edge = Edge(
            edge_type=f"{result.action}_{EDGE_LAYER_RESOURCE_POLICY}",
            src=src_ref,
            dst=NodeRef(
                provider=PROVIDER_AWS,
                node_type=result.target_node_type,
                provider_id=result.target_arn,
                region=result.region,
            ),
            region=result.region,
            features={
                "allow_controls": [_resource_policy_control_ref(result)],
                "effect": result.effect,
                "has_conditions": result.has_conditions,
                "layer": EDGE_LAYER_RESOURCE_POLICY,
                "permission_source": "resource_policy",
                "policy_name": result.policy_name,
                "policy_source": result.policy_source,
                "principal_type": result.principal_type,
                "raw_conditions": result.raw_conditions,
                "resource_pattern": result.resource_pattern,
                "statement_index": result.statement_index,
                "statement_sid": result.statement_sid,
                "target_arn": result.target_arn,
            },
        )
        edges.append(edge)

        if result.has_conditions:
            constraint_key = (
                result.target_arn,
                result.statement_digest,
                result.action,
                result.resource_pattern,
            )
            constraint = constraints_by_key.get(constraint_key)
            if constraint is None:
                constraint = _condition_constraint(result)
                constraints_by_key[constraint_key] = constraint
            edge_constraints.append(
                EdgeConstraint(
                    edge_id=edge.edge_id,
                    constraint_id=constraint.constraint_id,
                    governance_confidence=GOVERNANCE_CONFIDENCE_NEEDS_REVIEW,
                    likely_blocking=False,
                    binding_reason="resource policy statement has conditions that require runtime context",
                )
            )

    return (
        sorted(synthetic_nodes_by_key.values(), key=lambda n: n.node_id),
        sorted(edges, key=lambda e: e.edge_id),
        sorted(constraints_by_key.values(), key=lambda c: c.constraint_id),
        sorted(edge_constraints, key=lambda ec: ec.sort_key),
    )


def _synthetic_principal_node(result: ResourcePolicyParseResult) -> Node:
    props: dict[str, Any] = {
        "is_synthetic": True,
        "source_policy": "resource_policy",
        "policy_source": result.policy_source,
    }
    account_id = _extract_account_id(result.principal_value)
    if account_id:
        props["account_id"] = account_id
        props["org_member"] = account_id == result.account_id
        props["is_external"] = account_id != result.account_id
    if result.resolved_node_type == NODE_TYPE_WILDCARD_PRINCIPAL:
        props["description"] = "Any principal named in a resource policy"
        props["org_member"] = False
        props["is_external"] = True
    elif result.resolved_node_type == NODE_TYPE_AWS_SERVICE:
        props["service_name"] = result.principal_value
    elif result.resolved_node_type == NODE_TYPE_EXTERNAL_ACCOUNT:
        props["raw_principal"] = result.principal_value

    return Node(
        provider=PROVIDER_AWS,
        node_type=result.resolved_node_type,
        provider_id=result.principal_value,
        region=REGION_GLOBAL,
        properties=props,
    )


def _condition_constraint(result: ResourcePolicyParseResult) -> Constraint:
    return Constraint(
        provider=PROVIDER_AWS,
        constraint_type=CONSTRAINT_TYPE_RESOURCE_POLICY_CONDITION,
        scope_type="RESOURCE",
        scope_id=result.target_arn,
        policy_id=result.target_arn,
        statement_id=_condition_statement_id(result),
        region=result.region,
        properties={
            "action": result.action,
            "policy_source": result.policy_source,
            "policy_name": result.policy_name,
            "raw_conditions": result.raw_conditions,
            "resource_pattern": result.resource_pattern,
            "statement_digest": result.statement_digest,
            "statement_index": result.statement_index,
            "statement_sid": result.statement_sid,
            "target_arn": result.target_arn,
        },
        validation_status="NEEDS_REVIEW",
        confidence_q=300,
    )


def _condition_statement_id(result: ResourcePolicyParseResult) -> str:
    """Return stable ID material for an expanded resource-policy condition."""
    parts = [
        f"source={result.policy_source}",
        f"digest={result.statement_digest}",
        f"action={result.action}",
        f"resource={result.resource_pattern}",
    ]
    if result.statement_sid:
        parts.insert(0, f"sid={result.statement_sid}")
    return "|".join(parts)


def _resource_policy_control_ref(result: ResourcePolicyParseResult) -> dict[str, Any]:
    return ControlRef(
        control_type="RESOURCE_POLICY",
        policy_arn=result.target_arn,
        statement_index=result.statement_index,
        statement_sid=result.statement_sid,
        digest=result.statement_digest,
        summary=f"{result.policy_source}:{result.target_arn}",
    ).to_dict()


def _extract_account_id(arn_or_id: str) -> str | None:
    if len(arn_or_id) == 12 and arn_or_id.isdigit():
        return arn_or_id
    parts = arn_or_id.split(":")
    if len(parts) >= 5 and len(parts[4]) == 12 and parts[4].isdigit():
        return parts[4]
    return None


def _result_sort_key(result: ResourcePolicyParseResult) -> tuple[str, int, str, str, str]:
    return (
        result.target_arn,
        result.statement_index,
        result.principal_value,
        result.action,
        result.resource_pattern,
    )


__all__ = [
    "build_resource_policy_graph",
]
