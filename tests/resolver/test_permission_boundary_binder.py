"""Permission-boundary binder tests."""

from __future__ import annotations

from iamscope.collector.account import AccountData
from iamscope.constants import (
    CONSTRAINT_TYPE_PERMISSION_BOUNDARY,
    EDGE_LAYER_PERMISSION,
    EDGE_LAYER_TRUST,
    NODE_TYPE_ACCOUNT_ROOT,
    NODE_TYPE_IAM_ROLE,
    NODE_TYPE_S3_BUCKET,
    PROVIDER_AWS,
    REGION_GLOBAL,
)
from iamscope.models import AccountInfo, Edge, Node, OrgData
from iamscope.parser.permission_policy import parse_permission_policy
from iamscope.parser.trust_policy import parse_trust_policy
from iamscope.pipeline import PipelineConfig, _run_resolution
from iamscope.resolver.permission_boundary import bind_permission_boundaries, build_permission_boundary_constraints

TARGET_ACCOUNT = "1" * 12
SOURCE_ACCOUNT = "2" * 12


def _role_arn(account_id: str = TARGET_ACCOUNT) -> str:
    return f"arn:aws:iam::{account_id}:role/BoundaryTarget"


def _root_arn(account_id: str = SOURCE_ACCOUNT) -> str:
    return f"arn:aws:iam::{account_id}:root"


def _boundary_arn(account_id: str = TARGET_ACCOUNT) -> str:
    return f"arn:aws:iam::{account_id}:policy/BoundaryPolicy"


def _bucket_arn() -> str:
    return "arn:aws:s3:::boundary-demo-bucket"


def _role_node() -> Node:
    return Node(
        provider=PROVIDER_AWS,
        node_type=NODE_TYPE_IAM_ROLE,
        provider_id=_role_arn(),
        region=REGION_GLOBAL,
        properties={
            "account_id": TARGET_ACCOUNT,
            "path": "/",
            "permission_boundary_arn": _boundary_arn(),
        },
    )


def _source_root_node() -> Node:
    return Node(
        provider=PROVIDER_AWS,
        node_type=NODE_TYPE_ACCOUNT_ROOT,
        provider_id=_root_arn(),
        region=REGION_GLOBAL,
        properties={"account_id": SOURCE_ACCOUNT, "is_synthetic": True},
    )


def _bucket_node() -> Node:
    return Node(
        provider=PROVIDER_AWS,
        node_type=NODE_TYPE_S3_BUCKET,
        provider_id=_bucket_arn(),
        region="us-east-1",
        properties={"account_id": TARGET_ACCOUNT},
    )


def _boundary_policy() -> dict:
    return {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Action": ["s3:ListBucket", "lambda:CreateFunction"],
                "Resource": "*",
            }
        ],
    }


def test_permission_boundary_binds_permission_edge_not_trust_edge() -> None:
    """Boundaries constrain source-principal permissions, not trust admission."""
    source = _source_root_node()
    role = _role_node()
    bucket = _bucket_node()
    trust_edge = Edge(
        edge_type=f"sts:AssumeRole_{EDGE_LAYER_TRUST}",
        src=source.to_ref(),
        dst=role.to_ref(),
        region=REGION_GLOBAL,
        features={"layer": EDGE_LAYER_TRUST},
    )
    permission_edge = Edge(
        edge_type=f"s3:ListBucket_{EDGE_LAYER_PERMISSION}",
        src=role.to_ref(),
        dst=bucket.to_ref(),
        region=REGION_GLOBAL,
        features={"layer": EDGE_LAYER_PERMISSION},
    )
    constraints = build_permission_boundary_constraints({_boundary_arn(): _boundary_policy()})

    edge_constraints = bind_permission_boundaries(
        [trust_edge, permission_edge],
        [source, role, bucket],
        constraints,
    )

    assert len(edge_constraints) == 1
    assert edge_constraints[0].edge_id == permission_edge.edge_id
    assert edge_constraints[0].likely_blocking is False
    assert edge_constraints[0].governance_confidence == "complete"
    assert "src has permission boundary" in edge_constraints[0].binding_reason


def test_run_resolution_does_not_attach_permission_boundary_to_trust_edge() -> None:
    """Pipeline output has boundary sidecars only on permission edges."""
    role = _role_node()
    trust_result = parse_trust_policy(
        {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Effect": "Allow",
                    "Principal": {"AWS": _root_arn()},
                    "Action": "sts:AssumeRole",
                }
            ],
        },
        role_arn=role.provider_id,
        role_account_id=TARGET_ACCOUNT,
    )[0]
    permission_results = parse_permission_policy(
        {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Effect": "Allow",
                    "Action": "lambda:CreateFunction",
                    "Resource": "*",
                }
            ],
        },
        source_arn=role.provider_id,
        source_node_type=NODE_TYPE_IAM_ROLE,
        source_account_id=TARGET_ACCOUNT,
        policy_source="inline",
        policy_name="BoundaryTargetPolicy",
    )
    account_data = AccountData(
        account_id=TARGET_ACCOUNT,
        nodes=[role, _bucket_node()],
        trust_results=[(role, trust_result)],
        permission_results=permission_results,
        role_arns=[role.provider_id],
        permission_boundary_policies={_boundary_arn(): _boundary_policy()},
    )
    org_data = OrgData(
        org_id="o-boundary",
        root_id="r-root",
        accounts=[
            AccountInfo(
                account_id=TARGET_ACCOUNT,
                name="Boundary",
                email="boundary@example.invalid",
                status="ACTIVE",
                parent_id="r-root",
            )
        ],
    )

    _nodes, edges, constraints, edge_constraints, _budget = _run_resolution(
        org_data,
        [account_data],
        PipelineConfig(),
    )

    boundary_constraint_ids = {
        constraint.constraint_id
        for constraint in constraints
        if constraint.constraint_type == CONSTRAINT_TYPE_PERMISSION_BOUNDARY
    }
    assert boundary_constraint_ids
    trust_edge_ids = {edge.edge_id for edge in edges if edge.edge_type.endswith(f"_{EDGE_LAYER_TRUST}")}
    permission_edge_ids = {edge.edge_id for edge in edges if edge.edge_type.endswith(f"_{EDGE_LAYER_PERMISSION}")}

    boundary_binding_edge_ids = {
        edge_constraint.edge_id
        for edge_constraint in edge_constraints
        if edge_constraint.constraint_id in boundary_constraint_ids
    }

    assert boundary_binding_edge_ids
    assert boundary_binding_edge_ids <= permission_edge_ids
    assert boundary_binding_edge_ids.isdisjoint(trust_edge_ids)
