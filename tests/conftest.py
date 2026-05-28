"""Shared test fixtures for IAMScope."""

import pytest

from iamscope.constants import (
    CONSTRAINT_TYPE_SCP,
    NODE_TYPE_ACCOUNT_ROOT,
    NODE_TYPE_IAM_ROLE,
    PROVIDER_AWS,
    REGION_GLOBAL,
)
from iamscope.models import (
    Constraint,
    Edge,
    EdgeConstraint,
    Node,
    ScenarioMetadata,
)


@pytest.fixture
def minimal_role_node() -> Node:
    """A minimal IAMRole node for testing."""
    return Node(
        provider=PROVIDER_AWS,
        node_type=NODE_TYPE_IAM_ROLE,
        provider_id="arn:aws:iam::111111111111:role/TestRole",
        region=REGION_GLOBAL,
        properties={
            "account_id": "111111111111",
            "path": "/",
            "is_synthetic": False,
        },
    )


@pytest.fixture
def minimal_account_root_node() -> Node:
    """A minimal AccountPrincipalSet synthetic node for testing."""
    return Node(
        provider=PROVIDER_AWS,
        node_type=NODE_TYPE_ACCOUNT_ROOT,
        provider_id="arn:aws:iam::222222222222:root",
        region=REGION_GLOBAL,
        properties={
            "account_id": "222222222222",
            "principal_count": 50,
            "is_synthetic": True,
        },
    )


@pytest.fixture
def minimal_trust_edge(minimal_account_root_node: Node, minimal_role_node: Node) -> Edge:
    """A minimal _trust edge from account root to role."""
    return Edge(
        edge_type="sts:AssumeRole_trust",
        src=minimal_account_root_node.to_ref(),
        dst=minimal_role_node.to_ref(),
        region=REGION_GLOBAL,
        features={
            "cross_account": True,
            "has_external_id": False,
            "layer": "trust",
            "naked_trust": True,
            "trust_scope": "account_root",
        },
    )


@pytest.fixture
def minimal_constraint() -> Constraint:
    """A minimal SCP constraint for testing."""
    return Constraint(
        provider=PROVIDER_AWS,
        constraint_type=CONSTRAINT_TYPE_SCP,
        scope_type="OU",
        scope_id="ou-abc123-prodou",
        policy_id="p-1234567890",
        statement_id="DenyAssumeRole",
        region=REGION_GLOBAL,
        properties={
            "deny_actions": ["sts:AssumeRole"],
            "deny_not_actions": [],
            "exception_principal_patterns": [],
            "parse_status": "complete",
            "policy_name": "DenyAssumeRoleProd",
            "resource_patterns": ["*"],
        },
        status="ACTIVE",
        validation_status="UNVALIDATED",
        confidence_q=800,
    )


@pytest.fixture
def minimal_edge_constraint(minimal_trust_edge: Edge, minimal_constraint: Constraint) -> EdgeConstraint:
    """A minimal edge_constraint binding."""
    return EdgeConstraint(
        edge_id=minimal_trust_edge.edge_id,
        constraint_id=minimal_constraint.constraint_id,
        governance_confidence="complete",
        likely_blocking=True,
        binding_reason="edge action sts:AssumeRole in SCP deny_actions",
    )


@pytest.fixture
def minimal_metadata() -> ScenarioMetadata:
    """Minimal metadata for testing (timestamps fixed for determinism tests)."""
    return ScenarioMetadata(
        collector="iamscope",
        collector_version="0.2.0",
        id_algorithm="sha256_null_separated_v2",
        org_id="o-testorg",
        accounts_collected=1,
        accounts_skipped=0,
        collection_timestamp="2026-01-01T00:00:00Z",
        collection_duration_seconds=5.0,
        noise_filter={
            "exclude_service_linked": True,
            "expansion_mode": "warn",
        },
        graph_stats={
            "total_edges": 1,
            "total_nodes": 2,
        },
    )
