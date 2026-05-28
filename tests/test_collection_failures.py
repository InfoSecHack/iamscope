"""Tests for BUG-013: structured collection failure reporting.

These tests verify the `failures` list plumbing end-to-end for the
four collectors that previously swallowed per-region / per-global
exceptions with only a `logger.warning`. Each test drives a collector
with a mock `get_client` that succeeds for one region and raises on
another, then asserts:

1. The collector returned the resources from the successful region
   (partial collection is preserved — we don't fail the whole call).
2. Exactly one `CollectionFailure` record was appended to the shared
   list.
3. The record has the correct `collector`, `account_id`, `region`,
   and `error_class` fields.
4. Passing `failures=None` (or omitting it) is a no-op — the existing
   signature contract is preserved for callers that don't want
   structured reporting.

The `CollectionFailure` dataclass itself is also exercised directly
for its serialization and message-truncation behavior.

These tests do NOT require moto or any real AWS mock — they patch
`get_client` at the collector-module level and control the client's
behavior directly, so they're fast and hermetic.
"""

from __future__ import annotations

from unittest.mock import MagicMock, patch

import boto3
import pytest

from iamscope.collector.failures import (
    CollectionFailure,
    make_failure,
)
from iamscope.collector.kms_collector import collect_kms_keys
from iamscope.collector.lambda_collector import collect_lambda_functions
from iamscope.collector.s3_collector import collect_s3_buckets
from iamscope.collector.secrets_collector import collect_secrets
from iamscope.constants import REGION_GLOBAL

# =====================================================================
# CollectionFailure dataclass unit tests
# =====================================================================


class TestCollectionFailureDataclass:
    """Direct tests of the CollectionFailure record + make_failure helper."""

    def test_to_dict_is_sorted_and_complete(self) -> None:
        f = CollectionFailure(
            collector="lambda",
            account_id="111111111111",
            region="eu-west-1",
            error_class="ClientError",
            error_message="AccessDenied: lambda:ListFunctions",
        )
        d = f.to_dict()
        # Keys must be alphabetical to match the rest of the
        # models.py serialization contract.
        assert list(d.keys()) == [
            "account_id",
            "collector",
            "error_class",
            "error_message",
            "region",
        ]
        assert d["collector"] == "lambda"
        assert d["account_id"] == "111111111111"
        assert d["region"] == "eu-west-1"
        assert d["error_class"] == "ClientError"
        assert d["error_message"] == "AccessDenied: lambda:ListFunctions"

    def test_make_failure_from_short_exception(self) -> None:
        exc = ValueError("boom")
        f = make_failure("kms", "222222222222", "us-east-2", exc)
        assert f.collector == "kms"
        assert f.account_id == "222222222222"
        assert f.region == "us-east-2"
        assert f.error_class == "ValueError"
        assert f.error_message == "boom"

    def test_make_failure_truncates_long_messages(self) -> None:
        # Pathologically long message — scenario.json size must not
        # blow up from a single caught exception.
        long_msg = "x" * 2000
        exc = RuntimeError(long_msg)
        f = make_failure("s3", "333333333333", "global", exc)
        assert len(f.error_message) <= 500
        assert f.error_message.endswith("...")

    def test_is_frozen(self) -> None:
        import dataclasses

        f = CollectionFailure(
            collector="secrets",
            account_id="1",
            region="us-east-1",
            error_class="E",
            error_message="m",
        )
        with pytest.raises(dataclasses.FrozenInstanceError):
            f.collector = "other"  # type: ignore[misc]


# =====================================================================
# Helpers for building mock AWS clients
# =====================================================================


def _raising_client(exc: Exception) -> MagicMock:
    """A MagicMock client that raises on any paginated call."""
    client = MagicMock()
    client.get_paginator.side_effect = exc
    return client


def _empty_paginator_client() -> MagicMock:
    """A MagicMock client whose paginators yield empty pages —
    simulates a region where the API call succeeded but returned
    zero resources."""
    client = MagicMock()
    paginator = MagicMock()
    paginator.paginate.return_value = iter([])
    client.get_paginator.return_value = paginator
    return client


def _get_client_factory(
    raising_region: str,
    exc: Exception,
):
    """Build a `get_client` replacement that raises for
    `raising_region` and returns an empty-paginator mock for any
    other region. Used to simulate one region failing while others
    succeed."""

    def _fake_get_client(
        session: boto3.Session,
        service: str,
        region_name: str = "",
        **kwargs: object,
    ) -> MagicMock:
        if region_name == raising_region:
            return _raising_client(exc)
        return _empty_paginator_client()

    return _fake_get_client


# =====================================================================
# Per-collector plumbing tests
# =====================================================================


class TestLambdaCollectorFailures:
    """Verifies lambda_collector appends structured failures."""

    def test_appends_failure_for_raising_region(self) -> None:
        failures: list[CollectionFailure] = []
        exc = RuntimeError("lambda region boom")
        fake_get_client = _get_client_factory("eu-west-1", exc)
        session = MagicMock(spec=boto3.Session)

        with patch(
            "iamscope.collector.lambda_collector.get_client",
            side_effect=fake_get_client,
        ):
            nodes, edges = collect_lambda_functions(
                session,
                account_id="111111111111",
                regions=["us-east-1", "eu-west-1"],
                failures=failures,
            )

        # Partial collection preserved: us-east-1 returned cleanly
        # (empty), eu-west-1 raised and was captured.
        assert nodes == []
        assert edges == []
        assert len(failures) == 1
        f = failures[0]
        assert f.collector == "lambda"
        assert f.account_id == "111111111111"
        assert f.region == "eu-west-1"
        assert f.error_class == "RuntimeError"
        assert "boom" in f.error_message

    def test_no_failures_list_is_noop(self) -> None:
        """Omitting the failures param must not crash — the pre-BUG-013
        signature is preserved for callers that don't care."""
        exc = RuntimeError("lambda region boom")
        fake_get_client = _get_client_factory("eu-west-1", exc)
        session = MagicMock(spec=boto3.Session)

        with patch(
            "iamscope.collector.lambda_collector.get_client",
            side_effect=fake_get_client,
        ):
            # No failures kwarg at all — MUST NOT raise.
            nodes, edges = collect_lambda_functions(
                session,
                account_id="111111111111",
                regions=["us-east-1", "eu-west-1"],
            )
        assert nodes == []
        assert edges == []


class TestKmsCollectorFailures:
    """Verifies kms_collector appends structured failures (region-level
    only — per-key DescribeKey/GetKeyPolicy failures are BUG-013b and
    NOT covered by this test)."""

    def test_appends_failure_for_raising_region(self) -> None:
        failures: list[CollectionFailure] = []
        exc = RuntimeError("kms region boom")
        fake_get_client = _get_client_factory("ap-southeast-2", exc)
        session = MagicMock(spec=boto3.Session)

        with patch(
            "iamscope.collector.kms_collector.get_client",
            side_effect=fake_get_client,
        ):
            nodes = collect_kms_keys(
                session,
                account_id="444444444444",
                regions=["us-east-1", "ap-southeast-2"],
                failures=failures,
            )

        assert nodes == []
        assert len(failures) == 1
        f = failures[0]
        assert f.collector == "kms"
        assert f.region == "ap-southeast-2"
        assert f.account_id == "444444444444"
        assert f.error_class == "RuntimeError"


class TestSecretsCollectorFailures:
    """Verifies secrets_collector appends structured failures."""

    def test_appends_failure_for_raising_region(self) -> None:
        failures: list[CollectionFailure] = []
        exc = RuntimeError("secrets region boom")
        fake_get_client = _get_client_factory("us-west-2", exc)
        session = MagicMock(spec=boto3.Session)

        with patch(
            "iamscope.collector.secrets_collector.get_client",
            side_effect=fake_get_client,
        ):
            nodes = collect_secrets(
                session,
                account_id="555555555555",
                regions=["us-east-1", "us-west-2"],
                failures=failures,
            )

        assert nodes == []
        assert len(failures) == 1
        f = failures[0]
        assert f.collector == "secrets"
        assert f.region == "us-west-2"
        assert f.account_id == "555555555555"


class TestS3CollectorFailures:
    """Verifies s3_collector appends a global-scope failure on a
    `list_buckets` exception. Unlike the other three collectors, S3
    has no per-region loop — `ListAllMyBuckets` is a single global
    call — so the failure's region is `REGION_GLOBAL` (the canonical
    iamscope sentinel for non-regional scope)."""

    def test_appends_failure_for_list_buckets_error(self) -> None:
        failures: list[CollectionFailure] = []
        exc = RuntimeError("s3 list boom")
        # S3's failure happens directly on client.list_buckets(),
        # not on a paginator. Build a client that raises there.
        client = MagicMock()
        client.list_buckets.side_effect = exc
        session = MagicMock(spec=boto3.Session)

        with patch(
            "iamscope.collector.s3_collector.get_client",
            return_value=client,
        ):
            nodes = collect_s3_buckets(
                session,
                account_id="666666666666",
                failures=failures,
            )

        assert nodes == []
        assert len(failures) == 1
        f = failures[0]
        assert f.collector == "s3"
        assert f.region == REGION_GLOBAL
        assert f.account_id == "666666666666"
        assert f.error_class == "RuntimeError"

    def test_success_path_appends_nothing(self) -> None:
        """Happy path: no failures recorded when list_buckets returns
        cleanly. Guards against a false-positive where any S3 call
        would produce a failure record."""
        failures: list[CollectionFailure] = []
        client = MagicMock()
        client.list_buckets.return_value = {"Buckets": []}
        session = MagicMock(spec=boto3.Session)

        with patch(
            "iamscope.collector.s3_collector.get_client",
            return_value=client,
        ):
            nodes = collect_s3_buckets(
                session,
                account_id="777777777777",
                failures=failures,
            )

        assert nodes == []
        assert failures == []
