"""Tests for stale IAM unique-principal drift detection."""

from __future__ import annotations

from iamscope.constants import (
    CONSTRAINT_TYPE_STALE_PRINCIPAL_DRIFT,
    NODE_TYPE_EXTERNAL_ACCOUNT,
    NODE_TYPE_IAM_ROLE,
    PROVIDER_AWS,
    REGION_GLOBAL,
)
from iamscope.models import Edge, Node
from iamscope.output.scenario_json import emit_scenario
from iamscope.resolver.stale_principal_drift import (
    build_stale_principal_drift_constraints,
    classify_stale_unique_principal_id,
    is_stale_unique_principal_id,
)
from iamscope.truth.stale_principal_drift import (
    render_stale_drift_summary,
    summarize_stale_drift,
)

_STALE_ROLE_ID = "AROAABCDEFGHIJKLMNOP"
_TARGET_ROLE_ARN = "arn:aws:iam::111111\u003111111:role/Target"
_CLEAN_ROLE_ARN = "arn:aws:iam::222222\u003222222:role/Source"


def _node(node_type: str, provider_id: str) -> Node:
    return Node(
        provider=PROVIDER_AWS,
        node_type=node_type,
        provider_id=provider_id,
        region=REGION_GLOBAL,
        properties={},
    )


def _trust_edge(src: Node, dst: Node) -> Edge:
    return Edge(
        edge_type="sts:AssumeRole_trust",
        src=src.to_ref(),
        dst=dst.to_ref(),
        region=REGION_GLOBAL,
        features={
            "allow_controls": [
                {
                    "control_type": "TRUST",
                    "policy_arn": dst.provider_id,
                    "statement_index": 0,
                    "digest": "d" * 64,
                    "summary": "trust policy",
                }
            ],
            "layer": "trust",
            "source_policy": "TrustPolicy",
        },
    )


def test_positive_stale_unique_role_id_detection() -> None:
    assert is_stale_unique_principal_id(_STALE_ROLE_ID) is True
    assert classify_stale_unique_principal_id(_STALE_ROLE_ID) == "role"
    src = _node(NODE_TYPE_EXTERNAL_ACCOUNT, _STALE_ROLE_ID)
    dst = _node(NODE_TYPE_IAM_ROLE, _TARGET_ROLE_ARN)
    edge = _trust_edge(src, dst)

    constraints, edge_constraints = build_stale_principal_drift_constraints([edge])

    assert len(constraints) == 1
    assert constraints[0].constraint_type == CONSTRAINT_TYPE_STALE_PRINCIPAL_DRIFT
    assert constraints[0].properties["principal_id"] == _STALE_ROLE_ID
    assert constraints[0].properties["principal_id_kind"] == "role"
    assert constraints[0].properties["evidence_level"] == "complete"
    assert len(edge_constraints) == 1
    assert edge_constraints[0].edge_id == edge.edge_id
    assert edge_constraints[0].likely_blocking is True
    assert edge_constraints[0].governance_confidence == "complete"


def test_clean_role_arn_does_not_trigger_stale_drift() -> None:
    assert is_stale_unique_principal_id(_CLEAN_ROLE_ARN) is False
    src = _node(NODE_TYPE_IAM_ROLE, _CLEAN_ROLE_ARN)
    dst = _node(NODE_TYPE_IAM_ROLE, _TARGET_ROLE_ARN)
    edge = _trust_edge(src, dst)

    constraints, edge_constraints = build_stale_principal_drift_constraints([edge])

    assert constraints == []
    assert edge_constraints == []


def test_resource_policy_edge_with_unique_id_triggers_stale_drift() -> None:
    src = _node(NODE_TYPE_EXTERNAL_ACCOUNT, "AIDAABCDEFGHIJKLMNOP")
    dst = _node(NODE_TYPE_IAM_ROLE, _TARGET_ROLE_ARN)
    edge = Edge(
        edge_type="secretsmanager:GetSecretValue_resource_policy",
        src=src.to_ref(),
        dst=dst.to_ref(),
        region=REGION_GLOBAL,
        features={
            "allow_controls": [
                {
                    "control_type": "RESOURCE_POLICY",
                    "policy_arn": dst.provider_id,
                    "statement_index": 0,
                    "digest": "e" * 64,
                    "summary": "resource policy",
                }
            ],
            "layer": "resource_policy",
            "policy_source": "secretsmanager_resource_policy",
        },
    )

    constraints, edge_constraints = build_stale_principal_drift_constraints([edge])

    assert len(constraints) == 1
    assert constraints[0].properties["principal_id_kind"] == "user"
    assert len(edge_constraints) == 1
    assert edge_constraints[0].edge_id == edge.edge_id


def test_stale_drift_constraint_preserves_scenario_schema() -> None:
    src = _node(NODE_TYPE_EXTERNAL_ACCOUNT, _STALE_ROLE_ID)
    dst = _node(NODE_TYPE_IAM_ROLE, _TARGET_ROLE_ARN)
    edge = _trust_edge(src, dst)
    constraints, edge_constraints = build_stale_principal_drift_constraints([edge])

    scenario_bytes, _ = emit_scenario(
        nodes=[src, dst],
        edges=[edge],
        constraints=constraints,
        edge_constraints=edge_constraints,
        metadata=__import__("iamscope.models", fromlist=["ScenarioMetadata"]).ScenarioMetadata(),
    )

    import json

    scenario = json.loads(scenario_bytes)
    assert set(scenario) == {
        "constraints",
        "edge_constraints",
        "edges",
        "metadata",
        "nodes",
        "objectives",
        "observations",
    }
    assert scenario["constraints"][0]["constraint_type"] == CONSTRAINT_TYPE_STALE_PRINCIPAL_DRIFT


def test_operator_summary_reports_bound_stale_drift_evidence() -> None:
    src = _node(NODE_TYPE_EXTERNAL_ACCOUNT, _STALE_ROLE_ID)
    dst = _node(NODE_TYPE_IAM_ROLE, _TARGET_ROLE_ARN)
    edge = _trust_edge(src, dst)
    constraints, edge_constraints = build_stale_principal_drift_constraints([edge])

    scenario_bytes, _ = emit_scenario(
        nodes=[src, dst],
        edges=[edge],
        constraints=constraints,
        edge_constraints=edge_constraints,
        metadata=__import__("iamscope.models", fromlist=["ScenarioMetadata"]).ScenarioMetadata(),
    )

    import json

    summary = summarize_stale_drift(json.loads(scenario_bytes), edge_id=edge.edge_id)

    assert summary["stale_drift_count"] == 1
    assert summary["evidence"][0]["principal_id"] == _STALE_ROLE_ID
    rendered = render_stale_drift_summary(summary)
    assert "stale principal drift" in rendered.lower()
    assert _STALE_ROLE_ID in rendered
