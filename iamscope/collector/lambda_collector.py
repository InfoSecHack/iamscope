"""Lambda collector — discovers functions and creates service edges.

Discovers Lambda functions in an AWS account and creates:
- LambdaFunction nodes for each function
- Service edges from each function to its execution role

Service edges represent lateral movement: if an attacker can invoke
a Lambda function, they effectively gain the function's execution role
for the duration of the invocation.

Per Invariant #1: READ-ONLY ONLY (ListFunctions only).
Per Invariant #18: Pagination exhaustive.
"""

from __future__ import annotations

import logging

import boto3
from botocore.exceptions import ClientError

from iamscope.auth.session import get_client
from iamscope.collector.failures import CollectionFailure, make_failure
from iamscope.constants import (
    EDGE_LAYER_SERVICE,
    NODE_TYPE_IAM_ROLE,
    NODE_TYPE_LAMBDA_FUNCTION,
    PROVIDER_AWS,
    REGION_GLOBAL,
)
from iamscope.models import Edge, Node, NodeRef, ResourcePolicyDocument

logger = logging.getLogger(__name__)

# Regions to scan for Lambda functions
# Lambda is regional, so we need to check each region where functions may exist
DEFAULT_LAMBDA_REGIONS = ["us-east-1"]


def collect_lambda_functions(
    session: boto3.Session,
    account_id: str,
    regions: list[str] | None = None,
    failures: list[CollectionFailure] | None = None,
    resource_policies: list[ResourcePolicyDocument] | None = None,
) -> tuple[list[Node], list[Edge]]:
    """Collect Lambda functions and build service edges to execution roles.

    Args:
        session: boto3 Session with lambda:ListFunctions permission.
        account_id: AWS account ID.
        regions: Regions to scan. Defaults to us-east-1.
        failures: Optional shared list for structured failure records.
            If provided, per-region exceptions are appended here in
            addition to being logged, so callers can detect partial
            collection. See `iamscope.collector.failures` for context.

    Returns:
        Tuple of (function_nodes, service_edges).
    """
    if regions is None:
        regions = list(DEFAULT_LAMBDA_REGIONS)

    all_nodes: list[Node] = []
    all_edges: list[Edge] = []

    for region in regions:
        try:
            nodes, edges = _collect_region(session, account_id, region, failures, resource_policies)
            all_nodes.extend(nodes)
            all_edges.extend(edges)
        except Exception as e:
            logger.warning(
                "Failed to collect Lambda functions in %s/%s: %s",
                account_id,
                region,
                e,
            )
            if failures is not None:
                failures.append(make_failure("lambda", account_id, region, e))

    logger.info(
        "Account %s: %d Lambda functions, %d service edges",
        account_id,
        len(all_nodes),
        len(all_edges),
    )
    return all_nodes, all_edges


def _collect_region(
    session: boto3.Session,
    account_id: str,
    region: str,
    failures: list[CollectionFailure] | None = None,
    resource_policies: list[ResourcePolicyDocument] | None = None,
) -> tuple[list[Node], list[Edge]]:
    """Collect Lambda functions in a single region."""
    lambda_client = get_client(session, "lambda", region_name=region)

    nodes: list[Node] = []
    edges: list[Edge] = []

    paginator = lambda_client.get_paginator("list_functions")
    for page in paginator.paginate():
        for fn in page.get("Functions", []):
            fn_name = fn.get("FunctionName", "")
            fn_arn = fn.get("FunctionArn", "")
            role_arn = fn.get("Role", "")

            if not fn_arn or not role_arn:
                continue

            # Create function node
            node = Node(
                provider=PROVIDER_AWS,
                node_type=NODE_TYPE_LAMBDA_FUNCTION,
                provider_id=fn_arn,
                region=region,
                properties={
                    "account_id": account_id,
                    "function_name": fn_name,
                    "runtime": fn.get("Runtime", ""),
                    "execution_role_arn": role_arn,
                    "is_synthetic": False,
                },
            )
            nodes.append(node)

            # Create service edge: Lambda function → execution role
            edge = Edge(
                edge_type=f"lambda:ExecutionRole_{EDGE_LAYER_SERVICE}",
                src=NodeRef(
                    provider=PROVIDER_AWS,
                    node_type=NODE_TYPE_LAMBDA_FUNCTION,
                    provider_id=fn_arn,
                    region=region,
                ),
                dst=NodeRef(
                    provider=PROVIDER_AWS,
                    node_type=NODE_TYPE_IAM_ROLE,
                    provider_id=role_arn,
                    region=REGION_GLOBAL,
                ),
                region=region,
                features={
                    "layer": "service",
                    "account_id": account_id,
                    "function_name": fn_name,
                    "function_arn": fn_arn,
                    "execution_role_arn": role_arn,
                    "description": (
                        f"Lambda function {fn_name} uses execution role "
                        f"{role_arn.split('/')[-1] if '/' in role_arn else role_arn}"
                    ),
                },
            )
            edges.append(edge)

            if resource_policies is not None:
                _collect_lambda_policy(
                    lambda_client,
                    account_id,
                    region,
                    fn_arn,
                    fn_name,
                    failures,
                    resource_policies,
                )

    return nodes, edges


def _collect_lambda_policy(
    lambda_client: object,
    account_id: str,
    region: str,
    function_arn: str,
    function_name: str,
    failures: list[CollectionFailure] | None,
    resource_policies: list[ResourcePolicyDocument],
) -> None:
    """Collect one Lambda resource policy if present."""
    try:
        policy_resp = lambda_client.get_policy(FunctionName=function_arn)  # type: ignore[attr-defined]
    except ClientError as exc:
        code = exc.response.get("Error", {}).get("Code", "")
        if code in {"ResourceNotFoundException", "PolicyNotFoundException"}:
            return
        if failures is not None:
            failures.append(make_failure("lambda_resource_policy", account_id, region, exc))
        return
    except Exception as exc:
        if failures is not None:
            failures.append(make_failure("lambda_resource_policy", account_id, region, exc))
        return

    policy = policy_resp.get("Policy", "")
    if not policy:
        return
    resource_policies.append(
        ResourcePolicyDocument(
            target_arn=function_arn,
            policy_document=policy,
            policy_source="lambda_resource_policy",
            account_id=account_id,
            region=region,
            resource_type="LambdaFunction",
            policy_name=f"lambda-resource-policy:{function_name}",
        )
    )
