"""Tests for auth module — session factory and assume role.

Tests cover:
- Session creation with and without profile
- Client config has correct retry settings
- get_client returns configured client
- AssumeRole into member account
- AssumeRole failure returns None (skip, don't crash)
- get_caller_identity returns account info
"""

import json

import boto3
from moto import mock_aws

from iamscope.auth.assume_role import assume_collection_role, get_caller_identity
from iamscope.auth.session import get_client, get_client_config, get_session


class TestSessionFactory:
    """Tests for session and client creation."""

    def test_get_session_default(self) -> None:
        """Session created with default profile."""
        session = get_session()
        assert isinstance(session, boto3.Session)

    def test_get_client_config_retries(self) -> None:
        """Client config has correct retry settings."""
        config = get_client_config(max_attempts=5)
        assert config.retries["max_attempts"] == 5
        assert config.retries["mode"] == "standard"

    @mock_aws
    def test_get_client_returns_working_client(self) -> None:
        """get_client returns a functioning boto3 client."""
        session = get_session()
        sts = get_client(session, "sts")
        identity = sts.get_caller_identity()
        assert "Account" in identity


class TestAssumeRole:
    """Tests for AssumeRole into member accounts."""

    @mock_aws
    def test_assume_role_success(self) -> None:
        """Successfully assume role in member account."""
        session = get_session()

        # Create a role we can assume
        iam = session.client("iam")
        trust = json.dumps(
            {
                "Version": "2012-10-17",
                "Statement": [
                    {
                        "Effect": "Allow",
                        "Principal": {"AWS": "*"},
                        "Action": "sts:AssumeRole",
                    }
                ],
            }
        )
        iam.create_role(RoleName="IAMScopeReader", AssumeRolePolicyDocument=trust)

        # Get current account ID
        sts = session.client("sts")
        caller = sts.get_caller_identity()
        account_id = caller["Account"]

        # Assume the role
        assumed = assume_collection_role(session, account_id, "IAMScopeReader")
        assert assumed is not None
        assert isinstance(assumed, boto3.Session)

    def test_assume_role_client_error_returns_none(self, monkeypatch) -> None:
        """ClientError during AssumeRole returns None (skip, don't crash)."""
        from botocore.exceptions import ClientError

        session = get_session()

        def _mock_get_client(sess, service, **kwargs):
            class MockSTS:
                def assume_role(self, **kw):
                    raise ClientError(
                        {"Error": {"Code": "AccessDenied", "Message": "Not allowed"}},
                        "AssumeRole",
                    )

            return MockSTS()

        monkeypatch.setattr("iamscope.auth.assume_role.get_client", _mock_get_client)
        result = assume_collection_role(session, "123456\u003789012", "SomeRole")
        assert result is None

    @mock_aws
    def test_get_caller_identity(self) -> None:
        """get_caller_identity returns account info."""
        session = get_session()
        identity = get_caller_identity(session)

        assert "Account" in identity
        assert "Arn" in identity
        assert len(identity["Account"]) == 12
