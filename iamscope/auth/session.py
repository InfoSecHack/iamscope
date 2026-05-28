"""Session factory — boto3 sessions with retry and backoff configuration.

Per architecture R12:
- boto3 built-in retry with max_attempts=10, exponential backoff (standard mode)
- Per-account configurable delay
- Throttle events logged

Per Invariant #1: READ-ONLY ONLY. This module does NOT enforce read-only
at the session level (that's the caller's responsibility), but the
retry config is designed for read-heavy workloads.
"""

from __future__ import annotations

import logging
from typing import Any

import boto3
from botocore.config import Config

from iamscope.constants import DEFAULT_MAX_RETRY_ATTEMPTS

logger = logging.getLogger(__name__)


def get_session(
    profile_name: str | None = None,
    region_name: str = "us-east-1",
) -> boto3.Session:
    """Create a boto3 Session with optional profile.

    Args:
        profile_name: AWS CLI profile name. None for default/env credentials.
        region_name: Default AWS region.

    Returns:
        Configured boto3.Session.
    """
    kwargs: dict[str, str] = {"region_name": region_name}
    if profile_name:
        kwargs["profile_name"] = profile_name

    session = boto3.Session(**kwargs)  # type: ignore[arg-type]
    logger.info(
        "Created boto3 session (profile=%s, region=%s)",
        profile_name or "default",
        region_name,
    )
    return session


def get_client_config(
    max_attempts: int = DEFAULT_MAX_RETRY_ATTEMPTS,
    connect_timeout: int = 10,
    read_timeout: int = 30,
) -> Config:
    """Create a botocore Config with retry and timeout settings.

    Per R12: standard retry mode with exponential backoff.

    Args:
        max_attempts: Maximum number of retry attempts (default 10).
        connect_timeout: Connection timeout in seconds.
        read_timeout: Read timeout in seconds.

    Returns:
        botocore.config.Config for passing to client creation.
    """
    return Config(
        retries={"max_attempts": max_attempts, "mode": "standard"},
        connect_timeout=connect_timeout,
        read_timeout=read_timeout,
    )


def get_client(
    session: boto3.Session,
    service_name: str,
    region_name: str | None = None,
    max_attempts: int = DEFAULT_MAX_RETRY_ATTEMPTS,
) -> Any:
    """Create a boto3 client with retry configuration.

    Args:
        session: boto3 Session.
        service_name: AWS service name (e.g., 'iam', 'organizations', 'sts').
        region_name: Override region for this client.
        max_attempts: Maximum retry attempts.

    Returns:
        Configured boto3 client.
    """
    config = get_client_config(max_attempts=max_attempts)
    kwargs: dict[str, object] = {"service_name": service_name, "config": config}
    if region_name:
        kwargs["region_name"] = region_name

    client = session.client(**kwargs)  # type: ignore[call-overload]
    logger.debug("Created %s client (region=%s, max_retries=%d)", service_name, region_name, max_attempts)
    return client
