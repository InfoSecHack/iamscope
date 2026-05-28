"""Secrets Manager collector — discovers secrets and creates Secret nodes.

Discovers Secrets Manager secrets in an AWS account and creates:
- SecretsManagerSecret nodes for each secret

Unlike lambda_collector, there are no service edges here — secrets
don't have an "execution role" or similar lateral-movement primitive.
The reasoner that consumes these nodes (`secrets_blast_radius`) walks
IAM permission edges that target these nodes via `secretsmanager:GetSecretValue`
and is independent of any collector-provided edges.

Per Invariant #1: READ-ONLY ONLY (ListSecrets only).
Per Invariant #18: Pagination exhaustive.
"""

from __future__ import annotations

import logging

import boto3
from botocore.exceptions import ClientError

from iamscope.auth.session import get_client
from iamscope.collector.failures import CollectionFailure, make_failure
from iamscope.constants import (
    NODE_TYPE_SECRETS_MANAGER_SECRET,
    PROVIDER_AWS,
)
from iamscope.models import Node, ResourcePolicyDocument

logger = logging.getLogger(__name__)

# Regions to scan for secrets. SecretsManager is regional.
DEFAULT_SECRETS_REGIONS = ["us-east-1"]


def collect_secrets(
    session: boto3.Session,
    account_id: str,
    regions: list[str] | None = None,
    failures: list[CollectionFailure] | None = None,
    resource_policies: list[ResourcePolicyDocument] | None = None,
) -> list[Node]:
    """Collect SecretsManager secrets as SecretsManagerSecret nodes.

    Args:
        session: boto3 Session with secretsmanager:ListSecrets permission.
        account_id: AWS account ID.
        regions: Regions to scan. Defaults to us-east-1.
        failures: Optional shared list for structured failure records.
            If provided, per-region exceptions are appended here in
            addition to being logged, so callers can detect partial
            collection. See `iamscope.collector.failures` for context.

    Returns:
        List of SecretsManagerSecret nodes (one per discovered secret).
    """
    if regions is None:
        regions = list(DEFAULT_SECRETS_REGIONS)

    all_nodes: list[Node] = []

    for region in regions:
        try:
            nodes = _collect_region(session, account_id, region, failures, resource_policies)
            all_nodes.extend(nodes)
        except Exception as e:
            logger.warning(
                "Failed to collect secrets in %s/%s: %s",
                account_id,
                region,
                e,
            )
            if failures is not None:
                failures.append(make_failure("secrets", account_id, region, e))

    logger.info(
        "Account %s: %d SecretsManager secrets",
        account_id,
        len(all_nodes),
    )
    return all_nodes


def _collect_region(
    session: boto3.Session,
    account_id: str,
    region: str,
    failures: list[CollectionFailure] | None = None,
    resource_policies: list[ResourcePolicyDocument] | None = None,
) -> list[Node]:
    """Collect secrets in a single region via list_secrets pagination."""
    client = get_client(session, "secretsmanager", region_name=region)

    nodes: list[Node] = []

    paginator = client.get_paginator("list_secrets")
    for page in paginator.paginate():
        for secret in page.get("SecretList", []):
            arn = secret.get("ARN", "")
            name = secret.get("Name", "")
            if not arn:
                continue

            node = Node(
                provider=PROVIDER_AWS,
                node_type=NODE_TYPE_SECRETS_MANAGER_SECRET,
                provider_id=arn,
                region=region,
                properties={
                    "account_id": account_id,
                    "secret_name": name,
                    "kms_key_id": secret.get("KmsKeyId", ""),
                    "is_synthetic": False,
                },
            )
            nodes.append(node)

            if resource_policies is not None:
                _collect_secret_policy(
                    client,
                    account_id,
                    region,
                    arn,
                    name,
                    failures,
                    resource_policies,
                )

    return nodes


def _collect_secret_policy(
    client: object,
    account_id: str,
    region: str,
    secret_arn: str,
    secret_name: str,
    failures: list[CollectionFailure] | None,
    resource_policies: list[ResourcePolicyDocument],
) -> None:
    """Collect one Secrets Manager resource policy if present."""
    try:
        policy_resp = client.get_resource_policy(SecretId=secret_arn)  # type: ignore[attr-defined]
    except ClientError as exc:
        code = exc.response.get("Error", {}).get("Code", "")
        if code in {"ResourceNotFoundException", "ResourceNotFound"}:
            return
        if failures is not None:
            failures.append(make_failure("secrets_resource_policy", account_id, region, exc))
        return
    except Exception as exc:
        if failures is not None:
            failures.append(make_failure("secrets_resource_policy", account_id, region, exc))
        return

    policy = policy_resp.get("ResourcePolicy", "")
    if not policy:
        return
    resource_policies.append(
        ResourcePolicyDocument(
            target_arn=secret_arn,
            policy_document=policy,
            policy_source="secretsmanager_resource_policy",
            account_id=account_id,
            region=region,
            resource_type="SecretsManagerSecret",
            policy_name=f"secret-resource-policy:{secret_name}",
        )
    )
