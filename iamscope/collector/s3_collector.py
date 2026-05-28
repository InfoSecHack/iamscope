"""S3 collector — discovers S3 buckets.

Discovers S3 buckets in an AWS account and creates:
- S3Bucket nodes for each bucket

Unlike the Lambda/ECS collectors, there are no service edges emitted
here — S3 buckets don't have an execution-role lateral-movement
primitive, they're pure target nodes. The reasoner that consumes
these nodes (`s3_bucket_takeover`) walks IAM permission edges that
target them via `s3:PutBucketPolicy` and is independent of any
collector-provided edges.

Unlike SecretsManager and KMS, S3 is a global namespace — buckets
don't have regions in their ARNs. `list_buckets` returns all buckets
in the account with one call, no per-region iteration needed.

Per Invariant #1: READ-ONLY ONLY (ListBuckets only). v1 explicitly
does NOT call `get_bucket_policy`, `get_bucket_acl`, or
`get_public_access_block` — the reasoner only cares that a principal
CAN rewrite the policy, not what the current policy is. A future v2
could pull the current policy for defense-in-depth analysis.

Per Invariant #18: list_buckets is NOT paginated in the boto3 API
(it returns all buckets in a single call), so no pagination loop is
needed.
"""

from __future__ import annotations

import logging

import boto3
from botocore.exceptions import ClientError

from iamscope.auth.session import get_client
from iamscope.collector.failures import CollectionFailure, make_failure
from iamscope.constants import (
    NODE_TYPE_S3_BUCKET,
    PROVIDER_AWS,
    REGION_GLOBAL,
)
from iamscope.models import Node, ResourcePolicyDocument

logger = logging.getLogger(__name__)


def collect_s3_buckets(
    session: boto3.Session,
    account_id: str,
    failures: list[CollectionFailure] | None = None,
    resource_policies: list[ResourcePolicyDocument] | None = None,
) -> list[Node]:
    """Collect S3 buckets as S3Bucket nodes.

    Args:
        session: boto3 Session with s3:ListAllMyBuckets permission.
        account_id: AWS account ID.
        failures: Optional shared list for structured failure records.
            If provided, a `list_buckets` exception is appended here
            in addition to being logged (with `region=REGION_GLOBAL`
            since `ListAllMyBuckets` is not a regional call), so
            callers can detect that S3 collection failed versus
            legitimately returning zero buckets. See
            `iamscope.collector.failures`.

    Returns:
        List of S3Bucket nodes (one per discovered bucket).
    """
    try:
        client = get_client(session, "s3", region_name="us-east-1")
        response = client.list_buckets()
    except Exception as e:
        logger.warning(
            "Failed to list S3 buckets in account %s: %s",
            account_id,
            e,
        )
        if failures is not None:
            failures.append(make_failure("s3", account_id, REGION_GLOBAL, e))
        return []

    nodes: list[Node] = []
    for bucket in response.get("Buckets", []):
        name = bucket.get("Name", "")
        if not name:
            continue
        arn = f"arn:aws:s3:::{name}"
        node = Node(
            provider=PROVIDER_AWS,
            node_type=NODE_TYPE_S3_BUCKET,
            provider_id=arn,
            region=REGION_GLOBAL,
            properties={
                "account_id": account_id,
                "bucket_name": name,
                "is_synthetic": False,
            },
        )
        nodes.append(node)

        if resource_policies is not None:
            _collect_bucket_policy(
                client,
                account_id,
                name,
                arn,
                failures,
                resource_policies,
            )

    logger.info("Account %s: %d S3 buckets", account_id, len(nodes))
    return nodes


def _collect_bucket_policy(
    client: object,
    account_id: str,
    bucket_name: str,
    bucket_arn: str,
    failures: list[CollectionFailure] | None,
    resource_policies: list[ResourcePolicyDocument],
) -> None:
    """Collect one S3 bucket policy if present."""
    try:
        policy_resp = client.get_bucket_policy(Bucket=bucket_name)  # type: ignore[attr-defined]
    except ClientError as exc:
        code = exc.response.get("Error", {}).get("Code", "")
        if code in {"NoSuchBucketPolicy", "NoSuchBucket", "NoSuchPolicy"}:
            return
        if failures is not None:
            failures.append(make_failure("s3_resource_policy", account_id, REGION_GLOBAL, exc))
        return
    except Exception as exc:
        if failures is not None:
            failures.append(make_failure("s3_resource_policy", account_id, REGION_GLOBAL, exc))
        return

    policy = policy_resp.get("Policy", "")
    if not policy:
        return
    resource_policies.append(
        ResourcePolicyDocument(
            target_arn=bucket_arn,
            policy_document=policy,
            policy_source="s3_bucket_policy",
            account_id=account_id,
            region=REGION_GLOBAL,
            resource_type="S3Bucket",
            policy_name=f"bucket-policy:{bucket_name}",
        )
    )
