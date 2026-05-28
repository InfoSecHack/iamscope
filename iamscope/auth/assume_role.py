"""AssumeRole helper — assumes into member accounts for collection.

Per R11: sts:AssumeRole for collection authentication is PERMITTED.
It's a credential operation, not a state mutation. The prohibition
is on using sts:AssumeRole to TEST whether a trust path works (probing).

Per R12: Uses retry config from session module.
"""

from __future__ import annotations

import logging

import boto3
from botocore.exceptions import ClientError

from iamscope.auth.session import get_client

logger = logging.getLogger(__name__)

SESSION_NAME = "iamscope-collect"


def assume_collection_role(
    session: boto3.Session,
    account_id: str,
    role_name: str,
    region_name: str = "us-east-1",
    session_name: str = SESSION_NAME,
    external_id: str | None = None,
) -> boto3.Session | None:
    """Assume a read-only collection role in a member account.

    Args:
        session: Source boto3 Session (management account or delegated admin).
        account_id: Target AWS account ID.
        role_name: Name of the role to assume (e.g., 'IAMScopeReader').
        region_name: AWS region for the STS call.
        session_name: Role session name for CloudTrail attribution.
        external_id: Optional ExternalId for cross-account trust.

    Returns:
        New boto3.Session with temporary credentials for the target account,
        or None if assume-role fails (account skipped with warning).
    """
    role_arn = f"arn:aws:iam::{account_id}:role/{role_name}"
    sts_client = get_client(session, "sts", region_name=region_name)

    assume_kwargs: dict[str, object] = {
        "RoleArn": role_arn,
        "RoleSessionName": session_name,
        "DurationSeconds": 3600,
    }
    if external_id:
        assume_kwargs["ExternalId"] = external_id

    try:
        response = sts_client.assume_role(**assume_kwargs)
    except ClientError as e:
        error_code = e.response.get("Error", {}).get("Code", "Unknown")
        logger.warning(
            "Failed to assume role %s in account %s: %s (%s). Skipping account.",
            role_name,
            account_id,
            error_code,
            e,
        )
        return None

    creds = response["Credentials"]
    assumed_session = boto3.Session(
        aws_access_key_id=creds["AccessKeyId"],
        aws_secret_access_key=creds["SecretAccessKey"],
        aws_session_token=creds["SessionToken"],
        region_name=region_name,
    )

    logger.info(
        "Assumed role %s in account %s (session=%s)",
        role_name,
        account_id,
        session_name,
    )
    return assumed_session


def get_caller_identity(session: boto3.Session) -> dict[str, str]:
    """Get the caller identity for a session.

    Returns:
        Dict with Account, Arn, UserId keys.
    """
    sts_client = get_client(session, "sts")
    result: dict[str, str] = sts_client.get_caller_identity()
    return result
