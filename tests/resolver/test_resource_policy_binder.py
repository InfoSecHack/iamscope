"""Tests for resource-policy-derived edge production."""

from __future__ import annotations

import json

from iamscope.constants import (
    CONSTRAINT_TYPE_RESOURCE_POLICY_DENY,
    NODE_TYPE_S3_BUCKET,
    PROVIDER_AWS,
    REGION_GLOBAL,
)
from iamscope.models import AccountInfo, Node, OrgData, ResourcePolicyDocument, ScenarioMetadata
from iamscope.output.scenario_json import emit_scenario
from iamscope.parser.resource_policy import parse_resource_policy_document
from iamscope.pipeline import PipelineConfig, _run_resolution
from iamscope.resolver.resource_policy_binder import build_resource_policy_graph
from iamscope.validate import validate_scenario


def _bucket_node() -> Node:
    return Node(
        provider=PROVIDER_AWS,
        node_type=NODE_TYPE_S3_BUCKET,
        provider_id="arn:aws:s3:::demo-bucket",
        region=REGION_GLOBAL,
        properties={"account_id": "111111111111", "is_synthetic": False},
    )


def _s3_doc(principal: object = "arn:aws:iam::222222222222:role/Partner") -> ResourcePolicyDocument:
    return ResourcePolicyDocument(
        target_arn="arn:aws:s3:::demo-bucket",
        policy_document={
            "Statement": [
                {
                    "Effect": "Allow",
                    "Principal": {"AWS": principal},
                    "Action": "s3:GetObject",
                    "Resource": "arn:aws:s3:::demo-bucket/*",
                }
            ],
        },
        policy_source="s3_bucket_policy",
        account_id="111111111111",
        region=REGION_GLOBAL,
        resource_type="S3Bucket",
    )


def _s3_deny_doc() -> ResourcePolicyDocument:
    return ResourcePolicyDocument(
        target_arn="arn:aws:s3:::demo-bucket",
        policy_document={
            "Statement": [
                {
                    "Effect": "Deny",
                    "Principal": {"AWS": "arn:aws:iam::222222222222:role/Partner"},
                    "Action": "s3:GetObject",
                    "Resource": "arn:aws:s3:::demo-bucket/*",
                }
            ],
        },
        policy_source="s3_bucket_policy",
        account_id="111111111111",
        region=REGION_GLOBAL,
        resource_type="S3Bucket",
    )


def test_resource_policy_binder_emits_edge_and_synthetic_external_principal() -> None:
    results = parse_resource_policy_document(_s3_doc())

    synthetic_nodes, edges, constraints, edge_constraints = build_resource_policy_graph(
        results,
        existing_nodes=[_bucket_node()],
    )

    assert len(edges) == 1
    assert edges[0].edge_type == "s3:GetObject_resource_policy"
    assert edges[0].src.provider_id == "arn:aws:iam::222222222222:role/Partner"
    assert edges[0].dst.provider_id == "arn:aws:s3:::demo-bucket"
    assert edges[0].features["layer"] == "resource_policy"
    assert edges[0].features["allow_controls"][0]["control_type"] == "RESOURCE_POLICY"
    assert len(synthetic_nodes) == 1
    assert synthetic_nodes[0].node_type == "IAMRole"
    assert synthetic_nodes[0].properties["is_external"] is True
    assert constraints == []
    assert edge_constraints == []


def test_condition_bearing_resource_policy_emits_constraint_binding() -> None:
    doc = ResourcePolicyDocument(
        target_arn="arn:aws:s3:::demo-bucket",
        policy_document={
            "Statement": [
                {
                    "Effect": "Allow",
                    "Principal": "*",
                    "Action": "s3:GetObject",
                    "Resource": "arn:aws:s3:::demo-bucket/*",
                    "Condition": {"Bool": {"aws:SecureTransport": "true"}},
                }
            ],
        },
        policy_source="s3_bucket_policy",
        account_id="111111111111",
        region=REGION_GLOBAL,
        resource_type="S3Bucket",
    )
    results = parse_resource_policy_document(doc)

    synthetic_nodes, edges, constraints, edge_constraints = build_resource_policy_graph(
        results,
        existing_nodes=[_bucket_node()],
    )

    assert len(synthetic_nodes) == 1
    assert len(edges) == 1
    assert len(constraints) == 1
    assert constraints[0].constraint_type == "RESOURCE_POLICY_CONDITION"
    assert constraints[0].properties["raw_conditions"] == {"Bool": {"aws:SecureTransport": "true"}}
    assert len(edge_constraints) == 1
    assert edge_constraints[0].edge_id == edges[0].edge_id
    assert edge_constraints[0].constraint_id == constraints[0].constraint_id
    assert edge_constraints[0].governance_confidence == "needs_review"


def test_condition_constraints_are_unique_for_kms_multi_action_reused_sid_policy() -> None:
    doc = ResourcePolicyDocument(
        target_arn="arn:aws:kms:us-east-1:111111111111:key/abc",
        policy_document={
            "Statement": [
                {
                    "Sid": "AllowSecretsManagerUse",
                    "Effect": "Allow",
                    "Principal": {"AWS": "111111111111"},
                    "Action": [
                        "kms:CreateGrant",
                        "kms:Decrypt",
                        "kms:DescribeKey",
                        "kms:Encrypt",
                        "kms:ReEncrypt*",
                    ],
                    "Resource": "*",
                    "Condition": {
                        "StringEquals": {
                            "kms:CallerAccount": "111111111111",
                            "kms:ViaService": "secretsmanager.us-east-1.amazonaws.com",
                        }
                    },
                },
                {
                    "Sid": "AllowSecretsManagerUse",
                    "Effect": "Allow",
                    "Principal": {"AWS": "111111111111"},
                    "Action": "kms:GenerateDataKey*",
                    "Resource": "*",
                    "Condition": {
                        "StringEquals": {"kms:CallerAccount": "111111111111"},
                        "StringLike": {"kms:ViaService": "secretsmanager.*.amazonaws.com"},
                    },
                },
            ],
        },
        policy_source="kms_key_policy",
        account_id="111111111111",
        region="us-east-1",
        resource_type="KMSKey",
    )
    target = Node(
        provider=PROVIDER_AWS,
        node_type="KMSKey",
        provider_id=doc.target_arn,
        region="us-east-1",
    )

    synthetic_nodes, edges, constraints, edge_constraints = build_resource_policy_graph(
        parse_resource_policy_document(doc),
        existing_nodes=[target],
    )

    assert len(edges) == 6
    assert len(edge_constraints) == 6
    assert len(constraints) == 6
    assert len({c.constraint_id for c in constraints}) == len(constraints)
    assert {c.properties["action"] for c in constraints} == {
        "kms:CreateGrant",
        "kms:Decrypt",
        "kms:DescribeKey",
        "kms:Encrypt",
        "kms:ReEncrypt*",
        "kms:GenerateDataKey*",
    }
    assert {ec.constraint_id for ec in edge_constraints} == {c.constraint_id for c in constraints}

    scenario_bytes, _ = emit_scenario(
        nodes=[target, *synthetic_nodes],
        edges=edges,
        constraints=constraints,
        edge_constraints=edge_constraints,
        metadata=ScenarioMetadata(),
    )
    errors = validate_scenario(json.loads(scenario_bytes))
    assert not [e for e in errors if "Duplicate constraint_id" in e]


def test_resolution_export_includes_resource_policy_edge_without_schema_change() -> None:
    org_data = OrgData(
        org_id="standalone",
        root_id="standalone",
        accounts=[
            AccountInfo("111111111111", "standalone", "", "ACTIVE", "standalone"),
        ],
    )
    nodes, edges, constraints, edge_constraints, budget_hit = _run_resolution(
        org_data=org_data,
        all_account_data=[],
        config=PipelineConfig(standalone=True),
        service_nodes=[_bucket_node()],
        service_edges=[],
        resource_policy_documents=[_s3_doc()],
    )

    assert budget_hit is False
    assert any(edge.edge_type == "s3:GetObject_resource_policy" for edge in edges)

    scenario_bytes, _ = emit_scenario(
        nodes=nodes,
        edges=edges,
        constraints=constraints,
        edge_constraints=edge_constraints,
        metadata=__import__("iamscope.models", fromlist=["ScenarioMetadata"]).ScenarioMetadata(),
    )
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
    edge = next(e for e in scenario["edges"] if e["edge_type"] == "s3:GetObject_resource_policy")
    assert edge["features"]["permission_source"] == "resource_policy"


def test_lambda_resource_policy_is_parsed_as_principal_to_function_edge() -> None:
    doc = ResourcePolicyDocument(
        target_arn="arn:aws:lambda:us-east-1:111111111111:function:demo",
        policy_document={
            "Statement": [
                {
                    "Effect": "Allow",
                    "Principal": {"Service": "events.amazonaws.com"},
                    "Action": "lambda:InvokeFunction",
                    "Resource": "arn:aws:lambda:us-east-1:111111111111:function:demo",
                }
            ],
        },
        policy_source="lambda_resource_policy",
        account_id="111111111111",
        region="us-east-1",
        resource_type="LambdaFunction",
    )
    target = Node(
        provider=PROVIDER_AWS,
        node_type="LambdaFunction",
        provider_id=doc.target_arn,
        region="us-east-1",
    )
    nodes, edges, _constraints, _edge_constraints = build_resource_policy_graph(
        parse_resource_policy_document(doc),
        existing_nodes=[target],
    )

    assert len(edges) == 1
    assert edges[0].edge_type == "lambda:InvokeFunction_resource_policy"
    assert edges[0].src.node_type == "AWSService"
    assert edges[0].src.provider_id == "events.amazonaws.com"
    assert nodes[0].properties["service_name"] == "events.amazonaws.com"


def test_deny_only_resource_policy_does_not_emit_supported_deny_constraints() -> None:
    results = parse_resource_policy_document(_s3_deny_doc())

    synthetic_nodes, edges, constraints, edge_constraints = build_resource_policy_graph(
        results,
        existing_nodes=[_bucket_node()],
    )

    assert results == []
    assert synthetic_nodes == []
    assert edges == []
    assert constraints == []
    assert edge_constraints == []


def test_resolution_export_does_not_claim_resource_policy_deny_support() -> None:
    org_data = OrgData(
        org_id="standalone",
        root_id="standalone",
        accounts=[AccountInfo("111111111111", "standalone", "", "ACTIVE", "standalone")],
    )

    nodes, edges, constraints, edge_constraints, budget_hit = _run_resolution(
        org_data=org_data,
        all_account_data=[],
        config=PipelineConfig(standalone=True),
        service_nodes=[_bucket_node()],
        service_edges=[],
        resource_policy_documents=[_s3_deny_doc()],
    )

    assert budget_hit is False
    assert not any(edge.edge_type.endswith("_resource_policy") for edge in edges)
    assert not any(c.constraint_type == CONSTRAINT_TYPE_RESOURCE_POLICY_DENY for c in constraints)
    assert edge_constraints == []

    scenario_bytes, _ = emit_scenario(
        nodes=nodes,
        edges=edges,
        constraints=constraints,
        edge_constraints=edge_constraints,
        metadata=__import__("iamscope.models", fromlist=["ScenarioMetadata"]).ScenarioMetadata(),
    )
    scenario = json.loads(scenario_bytes)

    assert not any(edge["edge_type"].endswith("_resource_policy") for edge in scenario["edges"])
    assert not any(c["constraint_type"] == CONSTRAINT_TYPE_RESOURCE_POLICY_DENY for c in scenario["constraints"])
