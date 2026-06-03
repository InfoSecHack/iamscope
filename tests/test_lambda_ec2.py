"""Tests for Lambda and EC2 service edge collectors.

Moto-based tests with:
- Lambda functions with execution roles → service edges
- EC2 instance profiles with associated roles → service edges
- Permission parser Lambda/EC2 action extraction
- Pipeline integration with service nodes/edges

Tests cover:
- Lambda function discovery and node creation
- Lambda → execution role service edge
- Instance profile discovery and node creation
- Instance profile → role service edge
- Permission parser extracts lambda:InvokeFunction
- Permission parser extracts ec2:RunInstances
- Wildcard lambda:* and ec2:* matching
- Pipeline includes service edges in scenario.json
"""

import json

import pytest
from moto import mock_aws

from iamscope.auth.session import get_session
from iamscope.collector.ec2_collector import collect_instance_profiles
from iamscope.collector.lambda_collector import collect_lambda_functions
from iamscope.constants import (
    EDGE_LAYER_SERVICE,
    NODE_TYPE_EC2_INSTANCE_PROFILE,
    NODE_TYPE_LAMBDA_FUNCTION,
)
from iamscope.parser.permission_policy import parse_permission_policy


@pytest.fixture
def lambda_setup():
    """Create Lambda functions with execution roles in moto."""
    with mock_aws():
        session = get_session(region_name="us-east-1")
        iam = session.client("iam")
        lam = session.client("lambda", region_name="us-east-1")
        sts = session.client("sts")
        account_id = sts.get_caller_identity()["Account"]

        # Create execution role
        trust = json.dumps(
            {
                "Version": "2012-10-17",
                "Statement": [
                    {
                        "Effect": "Allow",
                        "Principal": {"Service": "lambda.amazonaws.com"},
                        "Action": "sts:AssumeRole",
                    }
                ],
            }
        )
        iam.create_role(RoleName="OrderProcessorRole", AssumeRolePolicyDocument=trust)
        role_arn = iam.get_role(RoleName="OrderProcessorRole")["Role"]["Arn"]

        # Create Lambda function
        lam.create_function(
            FunctionName="ProcessOrders",
            Runtime="python3.12",
            Role=role_arn,
            Handler="index.handler",
            Code={"ZipFile": b"fake"},
        )

        yield {
            "session": session,
            "account_id": account_id,
            "role_arn": role_arn,
        }


@pytest.fixture
def ec2_setup():
    """Create EC2 instance profiles with associated roles in moto."""
    with mock_aws():
        session = get_session(region_name="us-east-1")
        iam = session.client("iam")
        sts = session.client("sts")
        account_id = sts.get_caller_identity()["Account"]

        # Create role for instance profile
        trust = json.dumps(
            {
                "Version": "2012-10-17",
                "Statement": [
                    {
                        "Effect": "Allow",
                        "Principal": {"Service": "ec2.amazonaws.com"},
                        "Action": "sts:AssumeRole",
                    }
                ],
            }
        )
        iam.create_role(RoleName="WebServerRole", AssumeRolePolicyDocument=trust)
        role_arn = iam.get_role(RoleName="WebServerRole")["Role"]["Arn"]

        # Create instance profile and associate role
        iam.create_instance_profile(InstanceProfileName="WebServerProfile")
        iam.add_role_to_instance_profile(
            InstanceProfileName="WebServerProfile",
            RoleName="WebServerRole",
        )

        # Create empty instance profile (no role)
        iam.create_instance_profile(InstanceProfileName="EmptyProfile")

        yield {
            "session": session,
            "account_id": account_id,
            "role_arn": role_arn,
        }


class TestLambdaCollector:
    """Tests for Lambda function discovery and service edges."""

    def test_function_node_created(self, lambda_setup) -> None:
        """Lambda function creates a node."""
        nodes, _ = collect_lambda_functions(lambda_setup["session"], lambda_setup["account_id"])
        assert len(nodes) == 1
        assert nodes[0].node_type == NODE_TYPE_LAMBDA_FUNCTION
        assert "ProcessOrders" in nodes[0].provider_id

    def test_function_properties(self, lambda_setup) -> None:
        """Lambda node has correct properties."""
        nodes, _ = collect_lambda_functions(lambda_setup["session"], lambda_setup["account_id"])
        props = nodes[0].properties
        assert props["function_name"] == "ProcessOrders"
        assert props["execution_role_arn"] == lambda_setup["role_arn"]
        assert props["is_synthetic"] is False

    def test_service_edge_to_execution_role(self, lambda_setup) -> None:
        """Service edge connects function to its execution role."""
        _, edges = collect_lambda_functions(lambda_setup["session"], lambda_setup["account_id"])
        assert len(edges) == 1
        edge = edges[0]
        assert edge.edge_type == f"lambda:ExecutionRole_{EDGE_LAYER_SERVICE}"
        assert edge.dst.provider_id == lambda_setup["role_arn"]
        assert "ProcessOrders" in edge.src.provider_id

    def test_service_edge_properties(self, lambda_setup) -> None:
        """Service edge has descriptive features."""
        _, edges = collect_lambda_functions(lambda_setup["session"], lambda_setup["account_id"])
        feats = edges[0].features
        assert feats["function_name"] == "ProcessOrders"
        assert feats["execution_role_arn"] == lambda_setup["role_arn"]
        assert "description" in feats


class TestEC2Collector:
    """Tests for EC2 instance profile discovery and service edges."""

    def test_profile_nodes_created(self, ec2_setup) -> None:
        """Instance profiles create nodes."""
        nodes, _ = collect_instance_profiles(ec2_setup["session"], ec2_setup["account_id"])
        # 2 profiles: WebServerProfile + EmptyProfile
        assert len(nodes) == 2
        assert all(n.node_type == NODE_TYPE_EC2_INSTANCE_PROFILE for n in nodes)

    def test_profile_properties(self, ec2_setup) -> None:
        """Instance profile node has correct properties."""
        nodes, _ = collect_instance_profiles(ec2_setup["session"], ec2_setup["account_id"])
        web_profile = [n for n in nodes if "WebServer" in n.provider_id][0]
        assert web_profile.properties["profile_name"] == "WebServerProfile"
        assert web_profile.properties["role_count"] == 1
        assert ec2_setup["role_arn"] in web_profile.properties["role_arns"]

    def test_service_edge_to_role(self, ec2_setup) -> None:
        """Service edge connects profile to its associated role."""
        _, edges = collect_instance_profiles(ec2_setup["session"], ec2_setup["account_id"])
        # Only 1 edge — EmptyProfile has no roles
        assert len(edges) == 1
        edge = edges[0]
        assert edge.edge_type == f"ec2:InstanceProfile_{EDGE_LAYER_SERVICE}"
        assert edge.dst.provider_id == ec2_setup["role_arn"]

    def test_empty_profile_no_edge(self, ec2_setup) -> None:
        """Empty instance profile creates node but no service edge."""
        nodes, edges = collect_instance_profiles(ec2_setup["session"], ec2_setup["account_id"])
        empty = [n for n in nodes if "Empty" in n.provider_id][0]
        assert empty.properties["role_count"] == 0
        # No edge for empty profile
        empty_edges = [e for e in edges if "Empty" in e.src.provider_id]
        assert len(empty_edges) == 0


class TestPermissionParserLambdaEC2:
    """Tests for Lambda/EC2 action extraction in permission parser."""

    def test_lambda_invoke_extracted(self) -> None:
        """lambda:InvokeFunction is extracted from permission policy."""
        policy = {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Effect": "Allow",
                    "Action": "lambda:InvokeFunction",
                    "Resource": "arn:aws:lambda:us-east-1:123456\u003789012:function:MyFunc",
                }
            ],
        }
        results = parse_permission_policy(
            policy,
            source_arn="arn:aws:iam::123456\u003789012:role/Caller",
            source_node_type="IAMRole",
            source_account_id="123456\u003789012",
        )
        assert len(results) == 1
        assert results[0].action == "lambda:InvokeFunction"
        assert "MyFunc" in results[0].resource_pattern

    def test_lambda_create_extracted(self) -> None:
        """lambda:CreateFunction is extracted from permission policy."""
        policy = {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Effect": "Allow",
                    "Action": "lambda:CreateFunction",
                    "Resource": "*",
                }
            ],
        }
        results = parse_permission_policy(
            policy,
            source_arn="arn:aws:iam::123456\u003789012:role/Deployer",
            source_node_type="IAMRole",
            source_account_id="123456\u003789012",
        )
        assert len(results) == 1
        assert results[0].action == "lambda:CreateFunction"

    def test_ec2_run_instances_extracted(self) -> None:
        """ec2:RunInstances is extracted from permission policy."""
        policy = {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Effect": "Allow",
                    "Action": "ec2:RunInstances",
                    "Resource": "*",
                }
            ],
        }
        results = parse_permission_policy(
            policy,
            source_arn="arn:aws:iam::123456\u003789012:role/Admin",
            source_node_type="IAMRole",
            source_account_id="123456\u003789012",
        )
        assert len(results) == 1
        assert results[0].action == "ec2:RunInstances"

    def test_wildcard_lambda_star(self) -> None:
        """lambda:* matches lambda:InvokeFunction and lambda:CreateFunction."""
        policy = {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Effect": "Allow",
                    "Action": "lambda:*",
                    "Resource": "*",
                }
            ],
        }
        results = parse_permission_policy(
            policy,
            source_arn="arn:aws:iam::123456\u003789012:role/Admin",
            source_node_type="IAMRole",
            source_account_id="123456\u003789012",
        )
        actions = {r.action for r in results}
        assert "lambda:InvokeFunction" in actions
        assert "lambda:CreateFunction" in actions

    def test_wildcard_ec2_star(self) -> None:
        """ec2:* matches ec2:RunInstances."""
        policy = {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Effect": "Allow",
                    "Action": "ec2:*",
                    "Resource": "*",
                }
            ],
        }
        results = parse_permission_policy(
            policy,
            source_arn="arn:aws:iam::123456\u003789012:role/Admin",
            source_node_type="IAMRole",
            source_account_id="123456\u003789012",
        )
        actions = {r.action for r in results}
        assert "ec2:RunInstances" in actions

    def test_star_matches_all_actions(self) -> None:
        """* matches all relevant actions including Lambda/EC2."""
        policy = {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Effect": "Allow",
                    "Action": "*",
                    "Resource": "*",
                }
            ],
        }
        results = parse_permission_policy(
            policy,
            source_arn="arn:aws:iam::123456\u003789012:role/Admin",
            source_node_type="IAMRole",
            source_account_id="123456\u003789012",
        )
        actions = {r.action for r in results}
        assert "sts:AssumeRole" in actions
        assert "iam:PassRole" in actions
        assert "lambda:InvokeFunction" in actions
        assert "lambda:CreateFunction" in actions
        assert "ec2:RunInstances" in actions

    def test_unrelated_action_not_extracted(self) -> None:
        """Actions we don't care about are not extracted."""
        policy = {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Effect": "Allow",
                    "Action": "s3:GetObject",
                    "Resource": "*",
                }
            ],
        }
        results = parse_permission_policy(
            policy,
            source_arn="arn:aws:iam::123456\u003789012:role/Reader",
            source_node_type="IAMRole",
            source_account_id="123456\u003789012",
        )
        assert len(results) == 0


class TestPipelineLambdaEC2Integration:
    """Tests for Lambda/EC2 in the full pipeline."""

    @mock_aws
    def test_pipeline_includes_service_edges(self) -> None:
        """Full pipeline includes Lambda/EC2 service edges in scenario."""
        import boto3

        from iamscope.pipeline import PipelineConfig, run_pipeline

        # Set up org
        org_client = boto3.client("organizations", region_name="us-east-1")
        org_client.create_organization(FeatureSet="ALL")

        # Create Lambda function
        iam = boto3.client("iam")
        trust = json.dumps(
            {
                "Version": "2012-10-17",
                "Statement": [
                    {
                        "Effect": "Allow",
                        "Principal": {"Service": "lambda.amazonaws.com"},
                        "Action": "sts:AssumeRole",
                    }
                ],
            }
        )
        iam.create_role(RoleName="LambdaExec", AssumeRolePolicyDocument=trust)
        role_arn = iam.get_role(RoleName="LambdaExec")["Role"]["Arn"]

        lam = boto3.client("lambda", region_name="us-east-1")
        lam.create_function(
            FunctionName="MyFunc",
            Runtime="python3.12",
            Role=role_arn,
            Handler="index.handler",
            Code={"ZipFile": b"fake"},
        )

        # Create instance profile
        iam.create_instance_profile(InstanceProfileName="WebProfile")
        trust2 = json.dumps(
            {
                "Version": "2012-10-17",
                "Statement": [
                    {
                        "Effect": "Allow",
                        "Principal": {"Service": "ec2.amazonaws.com"},
                        "Action": "sts:AssumeRole",
                    }
                ],
            }
        )
        iam.create_role(RoleName="EC2Role", AssumeRolePolicyDocument=trust2)
        iam.add_role_to_instance_profile(InstanceProfileName="WebProfile", RoleName="EC2Role")

        session = get_session(region_name="us-east-1")
        config = PipelineConfig(region_name="us-east-1")
        result = run_pipeline(session, config)

        scenario = json.loads(result.scenario_bytes)

        # Check for service edges
        service_edges = [e for e in scenario["edges"] if "_service" in e["edge_type"]]
        assert len(service_edges) >= 2  # Lambda + EC2

        # Check for Lambda node
        lambda_nodes = [n for n in scenario["nodes"] if n.get("node_type") == NODE_TYPE_LAMBDA_FUNCTION]
        assert len(lambda_nodes) >= 1

        # Check for instance profile node
        ip_nodes = [n for n in scenario["nodes"] if n.get("node_type") == NODE_TYPE_EC2_INSTANCE_PROFILE]
        assert len(ip_nodes) >= 1

        # Check stats
        assert result.total_lambda_functions >= 1
        assert result.total_instance_profiles >= 1

    @mock_aws
    def test_pipeline_without_lambda_ec2(self) -> None:
        """Pipeline works with collect_lambda=False, collect_instance_profiles=False."""
        import boto3

        from iamscope.pipeline import PipelineConfig, run_pipeline

        org_client = boto3.client("organizations", region_name="us-east-1")
        org_client.create_organization(FeatureSet="ALL")

        session = get_session(region_name="us-east-1")
        config = PipelineConfig(
            region_name="us-east-1",
            collect_lambda=False,
            collect_instance_profiles=False,
        )
        result = run_pipeline(session, config)
        assert result.total_lambda_functions == 0
        assert result.total_instance_profiles == 0
