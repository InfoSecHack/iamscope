"""Tests for trust-condition resolver binding."""

from __future__ import annotations

import json

from iamscope.collector.account import AccountData
from iamscope.constants import (
    CONFIDENCE_Q_PARTIAL,
    CONSTRAINT_TYPE_TRUST_CONDITION,
    GOVERNANCE_CONFIDENCE_NEEDS_REVIEW,
    NODE_TYPE_IAM_ROLE,
    PROVIDER_AWS,
    REGION_GLOBAL,
    TRUST_SCOPE_SPECIFIC_ROLE,
)
from iamscope.models import (
    AccountInfo,
    Edge,
    Node,
    OrgData,
    ScenarioMetadata,
    TrustParseResult,
)
from iamscope.output.scenario_json import emit_scenario
from iamscope.pipeline import PipelineConfig, _run_resolution
from iamscope.resolver.cross_account import build_trust_edges
from iamscope.resolver.trust_condition_binder import (
    bind_all_trust_conditions,
    bind_trust_condition_to_edge,
    build_trust_condition_constraints,
)

SOURCE_ROLE_ARN = "arn:aws:iam::111111\u003111111:role/JumpRole"
TARGET_ROLE_ARN = "arn:aws:iam::222222\u003222222:role/ProdDeployRole"
RAW_CONDITIONS = {"StringEquals": {"sts:ExternalId": "serim-shared-prod-trust"}}


def _role_node(arn: str = TARGET_ROLE_ARN, account_id: str = "222222\u003222222") -> Node:
    return Node(
        provider=PROVIDER_AWS,
        node_type=NODE_TYPE_IAM_ROLE,
        provider_id=arn,
        region=REGION_GLOBAL,
        properties={"account_id": account_id, "is_synthetic": False, "path": "/"},
    )


def _trust_result(
    *,
    principal_arn: str = SOURCE_ROLE_ARN,
    statement_index: int = 0,
    raw_conditions: dict | None = None,
) -> TrustParseResult:
    return TrustParseResult(
        statement_index=statement_index,
        effect="Allow",
        action="sts:AssumeRole",
        principal_type="AWS",
        principal_value=principal_arn,
        resolved_node_type=NODE_TYPE_IAM_ROLE,
        trust_scope=TRUST_SCOPE_SPECIFIC_ROLE,
        has_external_id=bool(raw_conditions),
        condition_keys=["sts:ExternalId"] if raw_conditions else [],
        raw_conditions=raw_conditions or {},
        cross_account=True,
    )


def _conditioned_edge() -> Edge:
    return build_trust_edges([_trust_result(raw_conditions=RAW_CONDITIONS)], _role_node())[0]


class TestBuildTrustConditionConstraints:
    def test_conditioned_trust_edge_builds_constraint(self) -> None:
        edge = _conditioned_edge()

        assert edge.features["has_conditions"] is True
        constraints = build_trust_condition_constraints([edge])

        assert len(constraints) == 1
        constraint = constraints[0]
        assert constraint.constraint_type == CONSTRAINT_TYPE_TRUST_CONDITION
        assert constraint.scope_type == "TrustPolicy"
        assert constraint.scope_id == TARGET_ROLE_ARN
        assert constraint.policy_id == TARGET_ROLE_ARN
        assert constraint.statement_id == "trust:0"
        assert constraint.confidence_q == CONFIDENCE_Q_PARTIAL
        assert constraint.properties["raw_conditions"] == RAW_CONDITIONS
        assert constraint.properties["condition_keys"] == ["sts:ExternalId"]
        assert constraint.properties["has_external_id"] is True

    def test_unconditioned_trust_edge_builds_no_constraint(self) -> None:
        edge = build_trust_edges([_trust_result()], _role_node())[0]

        assert build_trust_condition_constraints([edge]) == []

    def test_multiple_principals_from_same_statement_share_constraint(self) -> None:
        role = _role_node()
        edges = build_trust_edges(
            [
                _trust_result(raw_conditions=RAW_CONDITIONS),
                _trust_result(
                    principal_arn="arn:aws:iam::111111\u003111111:role/TerraformRole",
                    raw_conditions=RAW_CONDITIONS,
                ),
            ],
            role,
        )

        constraints = build_trust_condition_constraints(edges)

        assert len(constraints) == 1


class TestBindTrustConditionToEdge:
    def test_condition_constraint_binds_to_originating_trust_edge(self) -> None:
        edge = _conditioned_edge()
        constraint = build_trust_condition_constraints([edge])[0]

        binding = bind_trust_condition_to_edge(edge, constraint)

        assert binding is not None
        assert binding.edge_id == edge.edge_id
        assert binding.constraint_id == constraint.constraint_id
        assert binding.governance_confidence == GOVERNANCE_CONFIDENCE_NEEDS_REVIEW
        assert binding.likely_blocking is False

    def test_bind_all_trust_conditions_binds_shared_statement_edges(self) -> None:
        role = _role_node()
        edges = build_trust_edges(
            [
                _trust_result(raw_conditions=RAW_CONDITIONS),
                _trust_result(
                    principal_arn="arn:aws:iam::111111\u003111111:role/TerraformRole",
                    raw_conditions=RAW_CONDITIONS,
                ),
            ],
            role,
        )
        constraints = build_trust_condition_constraints(edges)

        bindings = bind_all_trust_conditions(edges, constraints)

        assert len(bindings) == 2
        assert {binding.constraint_id for binding in bindings} == {constraints[0].constraint_id}


class TestTrustConditionPipeline:
    def test_resolution_exports_trust_condition_constraint_to_scenario(self) -> None:
        role = _role_node()
        acct = AccountData(
            account_id="222222\u003222222",
            nodes=[role],
            trust_results=[(role, _trust_result(raw_conditions=RAW_CONDITIONS))],
            role_arns=[TARGET_ROLE_ARN],
        )
        org_data = OrgData(
            org_id="o-test",
            root_id="r-test",
            accounts=[
                AccountInfo(
                    account_id="111111\u003111111",
                    name="dev",
                    email="",
                    status="ACTIVE",
                    parent_id="r-test",
                ),
                AccountInfo(
                    account_id="222222\u003222222",
                    name="prod",
                    email="",
                    status="ACTIVE",
                    parent_id="r-test",
                ),
            ],
        )

        nodes, edges, constraints, edge_constraints, _budget_hit = _run_resolution(
            org_data,
            [acct],
            PipelineConfig(),
            service_nodes=[],
            service_edges=[],
        )
        trust_constraints = [c for c in constraints if c.constraint_type == CONSTRAINT_TYPE_TRUST_CONDITION]

        assert len(trust_constraints) == 1
        assert any(ec.constraint_id == trust_constraints[0].constraint_id for ec in edge_constraints)

        scenario_bytes, _hash = emit_scenario(
            nodes=nodes,
            edges=edges,
            constraints=constraints,
            edge_constraints=edge_constraints,
            metadata=ScenarioMetadata(org_id="o-test"),
        )
        scenario = json.loads(scenario_bytes)

        assert [c["constraint_type"] for c in scenario["constraints"]] == [CONSTRAINT_TYPE_TRUST_CONDITION]
        assert scenario["constraints"][0]["properties"]["raw_conditions"] == RAW_CONDITIONS
        assert scenario["edge_constraints"] == [
            {
                "constraint_id": trust_constraints[0].constraint_id,
                "edge_id": edge_constraints[0].edge_id,
            }
        ]
