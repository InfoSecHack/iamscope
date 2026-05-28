"""BUG-021 regression tests: per-principal parse-failure surfacing.

Before these fixes, the `parse_permission_policy` and
`parse_trust_policy` functions had a `failures` parameter that
collected structured `PolicyParseFailure` records, and the
`AccountData` dataclass had a `policy_parse_failures` field to
receive them — but the per-principal call sites in
`iamscope.collector.account` did NOT pass the list through, AND
some call sites had an inline `try: json.loads; except: continue`
pre-filter that caught decode errors *before* they ever reached
the instrumented parser. Result: malformed inline role trust
policies, inline user permission policies, and inline group
policies were dropped with just a log line, cascading into
false-negative findings downstream (missing trust edges, missing
permission edges, missing escalation paths).

These tests exercise the processor functions directly with
deliberately malformed policy documents and assert that a
structured failure record lands in `result.policy_parse_failures`.
If these tests fail, a future refactor has regressed the rollout
by either (a) dropping the `failures=` kwarg at a call site, or
(b) reintroducing an inline pre-filter that catches the decode
error before it reaches the instrumented parser.
"""

from __future__ import annotations

from iamscope.collector.account import (
    AccountData,
    _parse_role_permissions,
    _process_group,
    _process_role,
    _process_user,
)

_ACCOUNT = "111111111111"


def _role_with_malformed_trust() -> dict:
    """A role dict shaped like what GetAccountAuthorizationDetails
    returns, but with an unparseable trust policy string. The role
    is otherwise valid — we want to prove that a broken trust
    policy produces a structured failure record rather than a
    silent drop + empty `{}` fallback."""
    return {
        "RoleName": "BrokenTrustRole",
        "Arn": f"arn:aws:iam::{_ACCOUNT}:role/BrokenTrustRole",
        "Path": "/",
        "AssumeRolePolicyDocument": "{this is not valid json",
        "RolePolicyList": [],
        "AttachedManagedPolicies": [],
    }


def _role_with_malformed_inline_permission() -> dict:
    """A role with a syntactically broken inline permission policy.
    The trust policy is valid so we can isolate the inline-permission
    failure path."""
    return {
        "RoleName": "BrokenPermRole",
        "Arn": f"arn:aws:iam::{_ACCOUNT}:role/BrokenPermRole",
        "Path": "/",
        "AssumeRolePolicyDocument": {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Effect": "Allow",
                    "Principal": {"AWS": f"arn:aws:iam::{_ACCOUNT}:root"},
                    "Action": "sts:AssumeRole",
                }
            ],
        },
        "RolePolicyList": [
            {
                "PolicyName": "BrokenInline",
                "PolicyDocument": "{not valid json at all",
            },
        ],
        "AttachedManagedPolicies": [],
    }


def _user_with_malformed_inline_permission() -> dict:
    return {
        "UserName": "BrokenUser",
        "Arn": f"arn:aws:iam::{_ACCOUNT}:user/BrokenUser",
        "Path": "/",
        "GroupList": [],
        "UserPolicyList": [
            {
                "PolicyName": "BrokenInline",
                "PolicyDocument": "{oops",
            },
        ],
        "AttachedManagedPolicies": [],
    }


class TestBug021PerPrincipalFailureSurfacing:
    """BUG-021 regression: per-principal call sites must surface
    parse failures through `result.policy_parse_failures`."""

    def test_role_malformed_trust_policy_records_failure(self) -> None:
        result = AccountData(account_id=_ACCOUNT)
        _process_role(
            role=_role_with_malformed_trust(),
            account_id=_ACCOUNT,
            result=result,
            managed_policy_docs={},
            include_service_linked=False,
            include_aws_managed=False,
        )
        # Pre-BUG-021: the inline try/except replaced the malformed
        # doc with `{}` and parse_trust_policy returned [] silently.
        # Post-fix: a structured failure record is appended.
        assert len(result.policy_parse_failures) >= 1, (
            "Expected a structured failure record for the malformed "
            "trust policy, but result.policy_parse_failures is empty"
        )
        f = result.policy_parse_failures[0]
        assert f.parser == "trust_policy"
        assert f.source_arn == f"arn:aws:iam::{_ACCOUNT}:role/BrokenTrustRole"
        assert f.failure_kind == "json_decode_error"

    def test_role_malformed_inline_permission_records_failure(self) -> None:
        result = AccountData(account_id=_ACCOUNT)
        role = _role_with_malformed_inline_permission()
        _parse_role_permissions(
            role=role,
            role_arn=role["Arn"],
            account_id=_ACCOUNT,
            managed_policy_docs={},
            result=result,
        )
        assert len(result.policy_parse_failures) >= 1
        f = result.policy_parse_failures[0]
        assert f.parser == "permission_policy"
        assert f.source_arn == role["Arn"]
        assert f.policy_source == "inline"
        assert f.policy_name == "BrokenInline"
        assert f.failure_kind == "json_decode_error"

    def test_user_malformed_inline_permission_records_failure(self) -> None:
        result = AccountData(account_id=_ACCOUNT)
        _process_user(
            user=_user_with_malformed_inline_permission(),
            account_id=_ACCOUNT,
            result=result,
            managed_policy_docs={},
            group_policies={},
        )
        assert len(result.policy_parse_failures) >= 1
        f = result.policy_parse_failures[0]
        assert f.parser == "permission_policy"
        assert f.source_arn == f"arn:aws:iam::{_ACCOUNT}:user/BrokenUser"
        assert f.policy_source == "inline"
        assert f.policy_name == "BrokenInline"

    def test_group_nondict_policy_records_failure(self) -> None:
        """Groups build their policies via `_build_group_policy_lookup`,
        which decodes inline docs before `_process_group` runs. The
        residual failure mode at the `_process_group` site is a
        non-dict root (e.g. a list), which `parse_permission_policy`
        captures via the `not_a_dict` failure kind. We exercise that
        path by feeding a non-dict doc directly through
        group_policies."""
        result = AccountData(account_id=_ACCOUNT)
        group = {
            "GroupName": "TestGroup",
            "Arn": f"arn:aws:iam::{_ACCOUNT}:group/TestGroup",
            "Path": "/",
        }
        # Simulate a post-decode non-dict root (e.g. a JSON array)
        # reaching the processor. The managed-policy lookup would
        # normally catch this, but the per-principal call path is
        # what's under test here.
        group_policies = {
            "TestGroup": [
                ("WeirdList", ["not", "a", "policy"], "group_inline"),
            ],
        }
        _process_group(
            group=group,
            account_id=_ACCOUNT,
            result=result,
            group_policies=group_policies,
        )
        assert len(result.policy_parse_failures) >= 1
        f = result.policy_parse_failures[0]
        assert f.parser == "permission_policy"
        assert f.source_arn == f"arn:aws:iam::{_ACCOUNT}:group/TestGroup"
        assert f.failure_kind == "not_a_dict"

    def test_valid_role_produces_no_failures(self) -> None:
        """Happy-path guard: a fully-valid role must NOT produce any
        failure records. This catches a class of regression where a
        future refactor accidentally logs a spurious failure on
        well-formed policies."""
        result = AccountData(account_id=_ACCOUNT)
        good_role = {
            "RoleName": "CleanRole",
            "Arn": f"arn:aws:iam::{_ACCOUNT}:role/CleanRole",
            "Path": "/",
            "AssumeRolePolicyDocument": {
                "Version": "2012-10-17",
                "Statement": [
                    {
                        "Effect": "Allow",
                        "Principal": {"AWS": f"arn:aws:iam::{_ACCOUNT}:root"},
                        "Action": "sts:AssumeRole",
                    }
                ],
            },
            "RolePolicyList": [
                {
                    "PolicyName": "CleanInline",
                    "PolicyDocument": {
                        "Version": "2012-10-17",
                        "Statement": [
                            {
                                "Effect": "Allow",
                                "Action": "s3:GetObject",
                                "Resource": "*",
                            }
                        ],
                    },
                }
            ],
            "AttachedManagedPolicies": [],
        }
        _process_role(
            role=good_role,
            account_id=_ACCOUNT,
            result=result,
            managed_policy_docs={},
            include_service_linked=False,
            include_aws_managed=False,
        )
        assert result.policy_parse_failures == []
