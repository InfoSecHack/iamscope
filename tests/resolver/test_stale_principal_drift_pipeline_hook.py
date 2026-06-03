"""Pipeline hook regression for stale principal drift constraints."""

from __future__ import annotations

from iamscope.collector.account import AccountData
from iamscope.constants import CONSTRAINT_TYPE_STALE_PRINCIPAL_DRIFT, NODE_TYPE_IAM_ROLE, PROVIDER_AWS
from iamscope.models import AccountInfo, Node, OrgData
from iamscope.output.scenario_json import emit_scenario
from iamscope.parser.trust_policy import parse_trust_policy
from iamscope.pipeline import PipelineConfig, _run_resolution


def test_run_resolution_emits_stale_principal_drift_constraint() -> None:
    account_id = "111111\u003111111"
    role_arn = f"arn:aws:iam::{account_id}:role/Target"
    role_node = Node(
        provider=PROVIDER_AWS,
        node_type=NODE_TYPE_IAM_ROLE,
        provider_id=role_arn,
        properties={"account_id": account_id},
    )
    trust_results = parse_trust_policy(
        {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Effect": "Allow",
                    "Principal": {"AWS": "AROAABCDEFGHIJKLMNOP"},
                    "Action": "sts:AssumeRole",
                }
            ],
        },
        role_arn=role_arn,
        role_account_id=account_id,
    )
    account_data = AccountData(
        account_id=account_id,
        nodes=[role_node],
        trust_results=[(role_node, trust_results[0])],
        role_arns=[role_arn],
    )
    org_data = OrgData(
        org_id="o-example",
        root_id="r-root",
        accounts=[
            AccountInfo(
                account_id=account_id,
                name="Example",
                email="example@example.com",
                status="ACTIVE",
                parent_id="r-root",
            )
        ],
    )

    nodes, edges, constraints, edge_constraints, _budget = _run_resolution(
        org_data,
        [account_data],
        PipelineConfig(),
    )

    stale_constraints = [c for c in constraints if c.constraint_type == CONSTRAINT_TYPE_STALE_PRINCIPAL_DRIFT]
    assert len(stale_constraints) == 1
    assert any(ec.constraint_id == stale_constraints[0].constraint_id for ec in edge_constraints)

    scenario_bytes, _ = emit_scenario(
        nodes=nodes,
        edges=edges,
        constraints=constraints,
        edge_constraints=edge_constraints,
        metadata=__import__("iamscope.models", fromlist=["ScenarioMetadata"]).ScenarioMetadata(),
    )

    import json

    scenario = json.loads(scenario_bytes)
    assert any(c["constraint_type"] == CONSTRAINT_TYPE_STALE_PRINCIPAL_DRIFT for c in scenario["constraints"])
    assert any(ec["constraint_id"] == stale_constraints[0].constraint_id for ec in scenario["edge_constraints"])
