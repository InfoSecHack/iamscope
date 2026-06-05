"""Pipeline-shaped tests for synthetic org-membership uncertainty."""

from __future__ import annotations

import json

from iamscope.collector.account import AccountData
from iamscope.constants import (
    NODE_TYPE_ACCOUNT_ROOT,
    NODE_TYPE_IAM_ROLE,
    PROVIDER_AWS,
    REGION_GLOBAL,
    TRUST_SCOPE_ACCOUNT_ROOT,
    TRUST_SCOPE_SPECIFIC_ROLE,
)
from iamscope.models import AccountInfo, Node, OrgData, ScenarioMetadata, TrustParseResult
from iamscope.output.scenario_json import emit_scenario
from iamscope.pipeline import PipelineConfig, _run_resolution

MEMBER_ACCOUNT = "1" * 12
OTHER_ACCOUNT = "2" * 12
SKIPPED_ACCOUNT = "3" * 12


def _role_arn(account_id: str, role_name: str = "TargetRole") -> str:
    return f"arn:aws:iam::{account_id}:role/{role_name}"


def _root_arn(account_id: str) -> str:
    return f"arn:aws:iam::{account_id}:root"


def _role_node(account_id: str = MEMBER_ACCOUNT) -> Node:
    arn = _role_arn(account_id)
    return Node(
        provider=PROVIDER_AWS,
        node_type=NODE_TYPE_IAM_ROLE,
        provider_id=arn,
        region=REGION_GLOBAL,
        properties={"account_id": account_id, "is_synthetic": False, "path": "/"},
    )


def _trust_result(
    principal_value: str,
    resolved_node_type: str = NODE_TYPE_ACCOUNT_ROOT,
    trust_scope: str = TRUST_SCOPE_ACCOUNT_ROOT,
    cross_account: bool = True,
) -> TrustParseResult:
    return TrustParseResult(
        statement_index=0,
        effect="Allow",
        action="sts:AssumeRole",
        principal_type="AWS",
        principal_value=principal_value,
        resolved_node_type=resolved_node_type,
        trust_scope=trust_scope,
        raw_conditions={},
        cross_account=cross_account,
    )


def _account_data(role_node: Node, trust_result: TrustParseResult) -> AccountData:
    return AccountData(
        account_id=role_node.properties["account_id"],
        nodes=[role_node],
        trust_results=[(role_node, trust_result)],
        permission_results=[],
        role_arns=[role_node.provider_id],
    )


def _org_data(account_ids: list[str]) -> OrgData:
    return OrgData(
        org_id="o-example",
        root_id="r-root",
        accounts=[
            AccountInfo(
                account_id=account_id,
                name=f"Account{index}",
                email=f"account{index}@example.com",
                status="ACTIVE",
                parent_id="r-root",
            )
            for index, account_id in enumerate(account_ids)
        ],
    )


def _resolve_single_trust(
    org_account_ids: list[str],
    trust_result: TrustParseResult,
    *,
    config: PipelineConfig | None = None,
) -> tuple[list[Node], bytes, str]:
    role_node = _role_node()
    nodes, edges, constraints, edge_constraints, _budget = _run_resolution(
        org_data=_org_data(org_account_ids),
        all_account_data=[_account_data(role_node, trust_result)],
        config=config or PipelineConfig(),
    )
    scenario_bytes, scenario_hash = emit_scenario(
        nodes=nodes,
        edges=edges,
        constraints=constraints,
        edge_constraints=edge_constraints,
        metadata=ScenarioMetadata(),
    )
    return nodes, scenario_bytes, scenario_hash


def _node_by_provider_id(nodes: list[Node], provider_id: str) -> Node:
    return next(node for node in nodes if node.provider_id == provider_id)


def test_pipeline_known_account_root_synthetic_node_is_member() -> None:
    """Known org accounts stay member even when their account data is absent."""
    trust_result = _trust_result(_root_arn(OTHER_ACCOUNT))

    nodes, _scenario_bytes, _scenario_hash = _resolve_single_trust(
        [MEMBER_ACCOUNT, OTHER_ACCOUNT],
        trust_result,
    )

    source_node = _node_by_provider_id(nodes, _root_arn(OTHER_ACCOUNT))
    assert source_node.properties["org_membership_status"] == "member"
    assert source_node.properties["org_member"] is True
    assert source_node.properties["is_external"] is False


def test_pipeline_complete_org_absent_account_is_non_member() -> None:
    """Complete org collection can classify absent accounts as non-members."""
    trust_result = _trust_result(_root_arn(OTHER_ACCOUNT))

    nodes, _scenario_bytes, _scenario_hash = _resolve_single_trust(
        [MEMBER_ACCOUNT],
        trust_result,
    )

    source_node = _node_by_provider_id(nodes, _root_arn(OTHER_ACCOUNT))
    assert source_node.properties["org_membership_status"] == "non_member"
    assert source_node.properties["org_member"] is False
    assert source_node.properties["is_external"] is True


def test_pipeline_partial_org_absent_account_remains_unknown() -> None:
    """Skipped or partial collection avoids false non-member classification."""
    trust_result = _trust_result(_root_arn(OTHER_ACCOUNT))

    nodes, _scenario_bytes, _scenario_hash = _resolve_single_trust(
        [MEMBER_ACCOUNT, SKIPPED_ACCOUNT],
        trust_result,
    )

    source_node = _node_by_provider_id(nodes, _root_arn(OTHER_ACCOUNT))
    assert source_node.properties["org_membership_status"] == "unknown"
    assert source_node.properties["org_member"] is None
    assert source_node.properties["is_external"] is None


def test_pipeline_cross_account_role_uses_same_membership_logic() -> None:
    """Cross-account IAMRole synthetics carry the same tri-state signal."""
    source_role_arn = _role_arn(OTHER_ACCOUNT, "SourceRole")
    trust_result = _trust_result(
        source_role_arn,
        resolved_node_type=NODE_TYPE_IAM_ROLE,
        trust_scope=TRUST_SCOPE_SPECIFIC_ROLE,
        cross_account=True,
    )

    nodes, _scenario_bytes, _scenario_hash = _resolve_single_trust(
        [MEMBER_ACCOUNT, SKIPPED_ACCOUNT],
        trust_result,
    )

    source_node = _node_by_provider_id(nodes, source_role_arn)
    assert source_node.properties["org_membership_status"] == "unknown"
    assert source_node.properties["org_member"] is None
    assert source_node.properties["is_external"] is None


def test_pipeline_standalone_own_account_synthetic_is_member() -> None:
    """Standalone own-account synthetics are not marked external."""
    trust_result = _trust_result(
        _root_arn(MEMBER_ACCOUNT),
        cross_account=False,
    )

    nodes, _scenario_bytes, _scenario_hash = _resolve_single_trust(
        [],
        trust_result,
        config=PipelineConfig(standalone=True),
    )

    source_node = _node_by_provider_id(nodes, _root_arn(MEMBER_ACCOUNT))
    assert source_node.properties["org_membership_status"] == "member"
    assert source_node.properties["org_member"] is True
    assert source_node.properties["is_external"] is False


def test_pipeline_scenario_json_membership_status_is_deterministic() -> None:
    """Scenario JSON deterministically emits the tri-state membership field."""
    trust_result = _trust_result(_root_arn(OTHER_ACCOUNT))

    _nodes_a, scenario_a, hash_a = _resolve_single_trust(
        [MEMBER_ACCOUNT, SKIPPED_ACCOUNT],
        trust_result,
    )
    _nodes_b, scenario_b, hash_b = _resolve_single_trust(
        [MEMBER_ACCOUNT, SKIPPED_ACCOUNT],
        trust_result,
    )

    assert scenario_a == scenario_b
    assert hash_a == hash_b
    scenario = json.loads(scenario_a)
    source_node = next(node for node in scenario["nodes"] if node["provider_id"] == _root_arn(OTHER_ACCOUNT))
    assert source_node["properties"]["org_membership_status"] == "unknown"
