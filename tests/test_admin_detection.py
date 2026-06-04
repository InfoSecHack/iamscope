"""Focused tests for shared admin-equivalence detection."""

from __future__ import annotations

from iamscope.collector.passrole import build_permission_edges
from iamscope.constants import NODE_TYPE_IAM_ROLE, PROVIDER_AWS, REGION_GLOBAL
from iamscope.controls.expansion import ExpansionController
from iamscope.models import Edge, Node
from iamscope.parser.permission_policy import parse_permission_policy
from iamscope.reasoner import FactGraph
from iamscope.reasoner.admin_detection import find_admin_witness_edge

_ACCOUNT = "111111\u003111111"
_ROLE_ARN = f"arn:aws:iam::{_ACCOUNT}:role/AdminCandidate"


def _role() -> Node:
    return Node(
        provider=PROVIDER_AWS,
        node_type=NODE_TYPE_IAM_ROLE,
        provider_id=_ROLE_ARN,
        properties={"account_id": _ACCOUNT},
    )


def _facts_from_policy_action(action: str) -> FactGraph:
    policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Action": action,
                "Resource": "*",
            }
        ],
    }
    role = _role()
    parse_results = parse_permission_policy(
        policy,
        source_arn=_ROLE_ARN,
        source_node_type=NODE_TYPE_IAM_ROLE,
        source_account_id=_ACCOUNT,
        policy_source="inline",
        policy_name="AdminDetectionPolicy",
    )
    edges, hyperedge_nodes = build_permission_edges(
        parse_results,
        ExpansionController(global_mode="warn"),
        known_role_arns=[_ROLE_ARN],
    )
    return FactGraph(
        nodes=(role, *hyperedge_nodes),
        edges=tuple(edges),
        constraints=(),
        edge_constraints=(),
        scenario_hash="a" * 64,
        edge_budget_exhausted=False,
    )


def _facts_from_explicit_admin_edge(edge_type: str) -> FactGraph:
    role = _role()
    edge = Edge(
        edge_type=edge_type,
        src=role.to_ref(),
        dst=role.to_ref(),
        region=REGION_GLOBAL,
        features={
            "effect": "Allow",
            "is_wildcard_resource": True,
            "layer": "permission",
            "resource_pattern": "*",
        },
    )
    return FactGraph(
        nodes=(role,),
        edges=(edge,),
        constraints=(),
        edge_constraints=(),
        scenario_hash="b" * 64,
        edge_budget_exhausted=False,
    )


def test_real_parser_iam_wildcard_policy_is_admin_equivalent() -> None:
    facts = _facts_from_policy_action("iam:*")

    witness = find_admin_witness_edge(facts, _role())

    assert witness is not None
    assert witness.features["action_matched_via"] == "wildcard_iam"
    assert witness.features["is_wildcard_resource"] is True
    assert witness.features["resource_pattern"] == "*"


def test_real_parser_star_policy_remains_admin_equivalent() -> None:
    facts = _facts_from_policy_action("*")

    witness = find_admin_witness_edge(facts, _role())

    assert witness is not None
    assert witness.features["action_matched_via"] == "wildcard_star"
    assert witness.features["is_wildcard_resource"] is True
    assert witness.features["resource_pattern"] == "*"


def test_real_parser_lambda_create_function_wildcard_resource_is_not_admin() -> None:
    facts = _facts_from_policy_action("lambda:CreateFunction")

    assert find_admin_witness_edge(facts, _role()) is None


def test_real_parser_passrole_wildcard_resource_is_not_admin() -> None:
    facts = _facts_from_policy_action("iam:PassRole")

    assert find_admin_witness_edge(facts, _role()) is None


def test_explicit_iam_star_permission_edge_still_admin() -> None:
    facts = _facts_from_explicit_admin_edge("iam:*_permission")

    witness = find_admin_witness_edge(facts, _role())

    assert witness is not None
    assert witness.edge_type == "iam:*_permission"


def test_explicit_star_permission_edge_still_admin() -> None:
    facts = _facts_from_explicit_admin_edge("*_permission")

    witness = find_admin_witness_edge(facts, _role())

    assert witness is not None
    assert witness.edge_type == "*_permission"


def test_real_parser_iam_wildcard_preserves_deterministic_provenance() -> None:
    facts = _facts_from_policy_action("iam:*")
    iam_edges = sorted(
        (edge for edge in facts.edges if edge.edge_type.startswith("iam:") and edge.edge_type.endswith("_permission")),
        key=lambda edge: edge.edge_type,
    )

    assert [edge.features["action_matched_via"] for edge in iam_edges] == [
        "wildcard_iam",
        "wildcard_iam",
    ]
    assert [edge.features["resource_pattern"] for edge in iam_edges] == ["*", "*"]
