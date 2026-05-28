"""KMS collector — discovers KMS keys and stores their key policies.

Discovers customer-managed and AWS-managed KMS keys in an AWS account
and creates:
- KMSKey nodes for each key

Each KMSKey node stores the parsed key policy JSON as a `key_policy`
property, plus metadata (key_id, arn, manager, description). The
policy is stored as the raw JSON string so the `secrets_blast_radius`
reasoner can evaluate it inline via `_kms_policy_allows_decrypt`.

This is the v2 fact-layer work for `secrets_blast_radius` KMS-aware
blast radius analysis. The v1 reasoner emits findings based on IAM-layer
`secretsmanager:GetSecretValue` permission alone; v2 extends it with a
KMS-layer check that verifies whether the principal can actually
decrypt the secret's encryption key.

Per Invariant #1: READ-ONLY ONLY (ListKeys, DescribeKey, GetKeyPolicy).
Per Invariant #18: Pagination exhaustive.

KMS key policy semantics reminder:
- AWS-managed keys (KeyManager=AWS) have canonical account-root
  delegation policies — access is fully gated by IAM.
- Customer-managed keys (KeyManager=CUSTOMER) have whatever policy
  the customer wrote. Common patterns:
  1. Account-root delegation ("Principal": {"AWS": "arn:...:root"})
     → behaves like AWS-managed, delegates to IAM
  2. Specific principal grants → only those principals can decrypt
  3. Conditions (aws:ViaService, aws:SourceAccount, etc.) → UNKNOWN
     territory for the reasoner, evaluates as inconclusive

The collector does NOT pre-compute "who can decrypt" sets. It stores
the raw policy JSON and lets the reasoner evaluate per-candidate.
"""

from __future__ import annotations

import logging

import boto3

from iamscope.auth.session import get_client
from iamscope.collector.failures import CollectionFailure, make_failure
from iamscope.constants import (
    NODE_TYPE_KMS_KEY,
    PROVIDER_AWS,
)
from iamscope.models import Node, ResourcePolicyDocument

logger = logging.getLogger(__name__)

# Regions to scan for KMS keys. KMS is regional.
DEFAULT_KMS_REGIONS = ["us-east-1"]


def collect_kms_keys(
    session: boto3.Session,
    account_id: str,
    regions: list[str] | None = None,
    failures: list[CollectionFailure] | None = None,
    resource_policies: list[ResourcePolicyDocument] | None = None,
) -> list[Node]:
    """Collect KMS keys as KMSKey nodes with attached key policies.

    Args:
        session: boto3 Session with kms:ListKeys + DescribeKey +
            GetKeyPolicy permissions.
        account_id: AWS account ID.
        regions: Regions to scan. Defaults to us-east-1.
        failures: Optional shared list for structured failure records.
            If provided, per-region exceptions are appended here in
            addition to being logged, so callers can detect partial
            collection. See `iamscope.collector.failures` for context.

            NOTE (BUG-013b, tracked separately): per-key DescribeKey /
            GetKeyPolicy failures inside `_collect_region` are NOT
            currently reported through this list. Those failures
            produce degraded KMSKey nodes with empty metadata or an
            empty `key_policy`, and the KMS reasoner in
            `secrets_blast_radius` treats an empty policy as "no allow
            statements" — a false-negative. Fixing this requires a
            reasoner-side change (a `policy_fetch_failed` node property
            that drives INCONCLUSIVE instead of NOT_APPLICABLE), which
            is out of scope for the v0.2.29 region-level fix.

    Returns:
        List of KMSKey nodes (one per discovered key).
    """
    if regions is None:
        regions = list(DEFAULT_KMS_REGIONS)

    all_nodes: list[Node] = []

    for region in regions:
        try:
            nodes = _collect_region(session, account_id, region, failures, resource_policies)
            all_nodes.extend(nodes)
        except Exception as e:
            logger.warning(
                "Failed to collect KMS keys in %s/%s: %s",
                account_id,
                region,
                e,
            )
            if failures is not None:
                failures.append(make_failure("kms", account_id, region, e))

    logger.info(
        "Account %s: %d KMS keys",
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
    """Collect KMS keys in a single region."""
    client = get_client(session, "kms", region_name=region)

    nodes: list[Node] = []

    paginator = client.get_paginator("list_keys")
    for page in paginator.paginate():
        for key_summary in page.get("Keys", []):
            key_id = key_summary.get("KeyId", "")
            key_arn = key_summary.get("KeyArn", "")
            if not key_id or not key_arn:
                continue

            # DescribeKey for metadata (KeyManager, Description, etc.)
            # BUG-013b: track whether this per-key call failed so the
            # reasoner can distinguish "degraded collection" from
            # "legitimately missing metadata". Currently the metadata
            # fields (KeyManager, Description, KeyState) are NOT used
            # in reasoning decisions — they're observability-only — so
            # the flag is purely informational for downstream consumers
            # that want to highlight degraded nodes in reports.
            metadata_fetch_failed = False
            try:
                describe = client.describe_key(KeyId=key_id)
                metadata = describe.get("KeyMetadata", {})
            except Exception as e:
                logger.warning("DescribeKey failed for %s: %s", key_id, e)
                metadata = {}
                metadata_fetch_failed = True

            key_manager = metadata.get("KeyManager", "")
            description = metadata.get("Description", "")
            key_state = metadata.get("KeyState", "")

            # GetKeyPolicy — pull the default "default" policy
            # BUG-013b: track policy fetch failure separately. This one
            # DOES affect reasoning — the `secrets_blast_radius` KMS
            # check evaluates `key_policy` and currently emits an
            # UNKNOWN reason of "empty KMS policy JSON" when the policy
            # string is empty, which is operationally ambiguous: it
            # could mean "customer key has no policy (weird)" OR "our
            # GetKeyPolicy call failed (our collector has bad perms)".
            # The reasoner consults this flag before evaluating the
            # policy and emits a clearer reason string when the flag
            # is set, so operators reading the finding can distinguish
            # the two cases.
            policy_fetch_failed = False
            try:
                policy_resp = client.get_key_policy(
                    KeyId=key_id,
                    PolicyName="default",
                )
                key_policy_json = policy_resp.get("Policy", "")
            except Exception as e:
                logger.warning("GetKeyPolicy failed for %s: %s", key_id, e)
                key_policy_json = ""
                policy_fetch_failed = True
                if failures is not None:
                    failures.append(make_failure("kms_resource_policy", account_id, region, e))

            node = Node(
                provider=PROVIDER_AWS,
                node_type=NODE_TYPE_KMS_KEY,
                provider_id=key_arn,
                region=region,
                properties={
                    "account_id": account_id,
                    "key_id": key_id,
                    "key_manager": key_manager,
                    "description": description,
                    "key_state": key_state,
                    "key_policy": key_policy_json,
                    "kms_metadata_fetch_failed": metadata_fetch_failed,
                    "kms_policy_fetch_failed": policy_fetch_failed,
                    "is_synthetic": False,
                },
            )
            nodes.append(node)

            if resource_policies is not None and key_policy_json:
                resource_policies.append(
                    ResourcePolicyDocument(
                        target_arn=key_arn,
                        policy_document=key_policy_json,
                        policy_source="kms_key_policy",
                        account_id=account_id,
                        region=region,
                        resource_type="KMSKey",
                        policy_name=f"key-policy:{key_id}",
                    )
                )

    return nodes
