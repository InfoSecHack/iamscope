"""EC2 instance profile collector — discovers profiles and service edges.

Discovers EC2 instance profiles in an AWS account and creates:
- EC2InstanceProfile nodes for each profile
- Service edges from each profile to its associated IAM role(s)

Service edges represent lateral movement: if an attacker can access an
EC2 instance with a profile attached, they can obtain temporary credentials
for the profile's role via the instance metadata service (IMDS).

Instance profiles are IAM resources (global), not EC2 resources,
so we only need one API call per account, not per region.

Per Invariant #1: READ-ONLY ONLY (ListInstanceProfiles only).
Per Invariant #18: Pagination exhaustive.
"""

from __future__ import annotations

import logging

import boto3

from iamscope.auth.session import get_client
from iamscope.constants import (
    EDGE_LAYER_SERVICE,
    NODE_TYPE_EC2_INSTANCE_PROFILE,
    NODE_TYPE_IAM_ROLE,
    PROVIDER_AWS,
    REGION_GLOBAL,
)
from iamscope.models import Edge, Node, NodeRef

logger = logging.getLogger(__name__)


def collect_instance_profiles(
    session: boto3.Session,
    account_id: str,
) -> tuple[list[Node], list[Edge]]:
    """Collect EC2 instance profiles and build service edges to roles.

    Args:
        session: boto3 Session with iam:ListInstanceProfiles permission.
        account_id: AWS account ID.

    Returns:
        Tuple of (profile_nodes, service_edges).
    """
    iam_client = get_client(session, "iam")

    nodes: list[Node] = []
    edges: list[Edge] = []

    paginator = iam_client.get_paginator("list_instance_profiles")
    for page in paginator.paginate():
        for profile in page.get("InstanceProfiles", []):
            profile_name = profile.get("InstanceProfileName", "")
            profile_arn = profile.get("Arn", "")
            profile_id = profile.get("InstanceProfileId", "")

            if not profile_arn:
                continue

            roles = profile.get("Roles", [])
            role_arns = [r.get("Arn", "") for r in roles if r.get("Arn")]

            # Create profile node
            node = Node(
                provider=PROVIDER_AWS,
                node_type=NODE_TYPE_EC2_INSTANCE_PROFILE,
                provider_id=profile_arn,
                region=REGION_GLOBAL,
                properties={
                    "account_id": account_id,
                    "profile_name": profile_name,
                    "profile_id": profile_id,
                    "role_arns": sorted(role_arns),
                    "role_count": len(role_arns),
                    "is_synthetic": False,
                },
            )
            nodes.append(node)

            # Create service edge: instance profile → each associated role
            for role_arn in sorted(role_arns):
                role_name = role_arn.split("/")[-1] if "/" in role_arn else role_arn
                edge = Edge(
                    edge_type=f"ec2:InstanceProfile_{EDGE_LAYER_SERVICE}",
                    src=NodeRef(
                        provider=PROVIDER_AWS,
                        node_type=NODE_TYPE_EC2_INSTANCE_PROFILE,
                        provider_id=profile_arn,
                        region=REGION_GLOBAL,
                    ),
                    dst=NodeRef(
                        provider=PROVIDER_AWS,
                        node_type=NODE_TYPE_IAM_ROLE,
                        provider_id=role_arn,
                        region=REGION_GLOBAL,
                    ),
                    region=REGION_GLOBAL,
                    features={
                        "layer": "service",
                        "account_id": account_id,
                        "profile_name": profile_name,
                        "profile_arn": profile_arn,
                        "role_arn": role_arn,
                        "description": (f"Instance profile {profile_name} is associated with role {role_name}"),
                    },
                )
                edges.append(edge)

    logger.info(
        "Account %s: %d instance profiles, %d service edges",
        account_id,
        len(nodes),
        len(edges),
    )
    return nodes, edges
