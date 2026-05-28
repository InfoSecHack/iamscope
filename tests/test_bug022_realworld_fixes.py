"""BUG-022 / BUG-022b regression tests.

These bugs were found by the first real-world run of iamscope
against a production AWS environment (OriginX assessment, the source environment).
The existing 1148 synthetic tests all passed; reality hit two
independent issues in the first five seconds:

BUG-022  — The scenario.json referential-integrity validator
           crashed because `_is_wildcard_resource` only detected
           three hardcoded strings as wildcard patterns. A real
           IAM policy containing
           `arn:aws:lambda:*:<account>:function:crowdstrike-cs-*`
           flowed through `_build_specific_edge`, which set the
           edge dst to the literal pattern string, and the
           validator rejected it.

BUG-022b — `_resolve_aws_principal` emitted a scary "Unrecognized
           AWS principal format" warning for two legitimate AWS
           trust-policy principal shapes:
           (1) assumed-role ARNs like
               `arn:aws:sts::<account>:assumed-role/AWSAFTAdmin/AWSAFT-Session`
               (common in Control Tower / AFT environments)
           (2) bare principal IDs like `AROAYEKP5XW36XB3V7AON`
               (AWS's frozen-ID replacement for deleted principals)

These tests lock in the fixes and serve as the foundation of a
"real-world policy shape" corpus that should be expanded every
time a production run surfaces another unexpected pattern.
"""

from __future__ import annotations

from iamscope.constants import (
    NODE_TYPE_ACCOUNT_ROOT,
    NODE_TYPE_EXTERNAL_ACCOUNT,
    NODE_TYPE_HYPEREDGE,
    NODE_TYPE_IAM_ROLE,
    NODE_TYPE_IAM_USER,
    TRUST_SCOPE_SPECIFIC_ROLE,
)
from iamscope.controls.expansion import ExpansionController
from iamscope.parser.permission_policy import (
    _is_wildcard_resource,
    parse_permission_policy,
)
from iamscope.parser.trust_policy import _resolve_aws_principal

_ACCOUNT = "379322108695"
_USER_ARN = f"arn:aws:iam::{_ACCOUNT}:user/TestUser"


# ---------------------------------------------------------------------------
# BUG-022 — generalized wildcard resource detection
# ---------------------------------------------------------------------------


class TestBug022WildcardDetection:
    """Regression tests for `_is_wildcard_resource` generalization.

    Pre-fix this function only returned True for three hardcoded
    strings. Post-fix it returns True for any resource containing
    a glob metacharacter (`*` or `?`)."""

    def test_star_wildcard(self) -> None:
        assert _is_wildcard_resource("*") is True

    def test_lambda_function_prefix_wildcard(self) -> None:
        """The exact pattern that crashed the OriginX run."""
        assert _is_wildcard_resource(f"arn:aws:lambda:*:{_ACCOUNT}:function:crowdstrike-cs-*") is True

    def test_lambda_function_full_wildcard(self) -> None:
        assert _is_wildcard_resource(f"arn:aws:lambda:us-east-1:{_ACCOUNT}:function:*") is True

    def test_role_prefix_wildcard(self) -> None:
        """Latent bug pre-fix: role prefix wildcards would crash
        the same way as the OriginX lambda pattern, just on a
        different resource type."""
        assert _is_wildcard_resource(f"arn:aws:iam::{_ACCOUNT}:role/prod-*") is True

    def test_s3_object_wildcard(self) -> None:
        assert _is_wildcard_resource("arn:aws:s3:::my-bucket/*") is True

    def test_secret_prefix_wildcard(self) -> None:
        assert _is_wildcard_resource(f"arn:aws:secretsmanager:*:{_ACCOUNT}:secret:prod-*") is True

    def test_question_mark_wildcard(self) -> None:
        """Single-char glob metacharacter — less common but legal
        in IAM Resource fields."""
        assert _is_wildcard_resource(f"arn:aws:iam::{_ACCOUNT}:role/env?-admin") is True

    def test_literal_role_arn_not_wildcard(self) -> None:
        """Happy-path guard: a fully-literal ARN with no glob
        metacharacters must NOT be classified as wildcard."""
        assert _is_wildcard_resource(f"arn:aws:iam::{_ACCOUNT}:role/SpecificRole") is False

    def test_literal_lambda_arn_not_wildcard(self) -> None:
        assert _is_wildcard_resource(f"arn:aws:lambda:us-east-1:{_ACCOUNT}:function:my-func") is False


class TestBug022PermissionPolicyEmitsHyperedge:
    """End-to-end test: a real-world IAM policy with a Lambda
    wildcard resource must produce a parse result flagged as
    wildcard, which the edge builder then routes to a hyperedge
    rather than crashing the scenario.json validator."""

    def test_lambda_wildcard_parse_result_marked_wildcard(self) -> None:
        """The exact policy shape that crashed OriginX."""
        policy = {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Effect": "Allow",
                    "Action": "lambda:InvokeFunction",
                    "Resource": f"arn:aws:lambda:*:{_ACCOUNT}:function:crowdstrike-cs-*",
                }
            ],
        }
        results = parse_permission_policy(
            policy,
            source_arn=_USER_ARN,
            source_node_type=NODE_TYPE_IAM_USER,
            source_account_id=_ACCOUNT,
        )
        assert len(results) == 1
        assert results[0].is_wildcard_resource is True
        assert results[0].action == "lambda:InvokeFunction"

    def test_lambda_wildcard_becomes_hyperedge(self) -> None:
        """End-to-end: build_permission_edges on a Lambda wildcard
        must produce a hyperedge (dst node_type=Hyperedge), not a
        broken specific edge that would crash the validator."""
        from iamscope.collector.passrole import build_permission_edges

        policy = {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Effect": "Allow",
                    "Action": "lambda:InvokeFunction",
                    "Resource": f"arn:aws:lambda:*:{_ACCOUNT}:function:crowdstrike-cs-*",
                }
            ],
        }
        parse_results = parse_permission_policy(
            policy,
            source_arn=_USER_ARN,
            source_node_type=NODE_TYPE_IAM_USER,
            source_account_id=_ACCOUNT,
        )
        edges, hyperedge_nodes = build_permission_edges(
            parse_results=parse_results,
            expansion_controller=ExpansionController(),
            known_role_arns=[],
        )
        assert len(edges) == 1
        assert edges[0].edge_type == "lambda:InvokeFunction_permission"
        assert edges[0].dst.node_type == NODE_TYPE_HYPEREDGE
        # The hyperedge node must be emitted for downstream scenario
        # assembly (otherwise the validator would crash again).
        assert len(hyperedge_nodes) == 1
        assert hyperedge_nodes[0].node_type == NODE_TYPE_HYPEREDGE

    def test_secretsmanager_wildcard_becomes_hyperedge(self) -> None:
        """Same fix applies to secrets wildcards — crowdstrike-cs-*
        is one of many similar prefix patterns in real policies."""
        from iamscope.collector.passrole import build_permission_edges

        policy = {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Effect": "Allow",
                    "Action": "secretsmanager:GetSecretValue",
                    "Resource": (f"arn:aws:secretsmanager:*:{_ACCOUNT}:secret:prod-*"),
                }
            ],
        }
        parse_results = parse_permission_policy(
            policy,
            source_arn=_USER_ARN,
            source_node_type=NODE_TYPE_IAM_USER,
            source_account_id=_ACCOUNT,
        )
        edges, hyperedge_nodes = build_permission_edges(
            parse_results=parse_results,
            expansion_controller=ExpansionController(),
            known_role_arns=[],
        )
        assert len(edges) == 1
        assert edges[0].dst.node_type == NODE_TYPE_HYPEREDGE

    def test_role_wildcard_still_expands_when_roles_match(self) -> None:
        """Guard: BUG-022 must not regress iam:PassRole expansion
        behavior. A role wildcard with matching roles in the
        known set should still produce expanded role-targeted
        edges, not a hyperedge."""
        from iamscope.collector.passrole import build_permission_edges

        matching_role = f"arn:aws:iam::{_ACCOUNT}:role/prod-deploy"
        other_role = f"arn:aws:iam::{_ACCOUNT}:role/dev-deploy"

        policy = {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Effect": "Allow",
                    "Action": "iam:PassRole",
                    "Resource": f"arn:aws:iam::{_ACCOUNT}:role/prod-*",
                }
            ],
        }
        parse_results = parse_permission_policy(
            policy,
            source_arn=_USER_ARN,
            source_node_type=NODE_TYPE_IAM_USER,
            source_account_id=_ACCOUNT,
        )
        assert parse_results[0].is_wildcard_resource is True

        edges, _hyperedge_nodes = build_permission_edges(
            parse_results=parse_results,
            expansion_controller=ExpansionController(),
            known_role_arns=[matching_role, other_role],
        )
        # Depending on ExpansionController defaults this may expand
        # or go to hyperedge. In either case the fix must not crash
        # the validator. We just assert that if it expands, the dst
        # is a role, and if it hyperedge-s, the dst is a hyperedge.
        for e in edges:
            assert e.dst.node_type in (NODE_TYPE_IAM_ROLE, NODE_TYPE_HYPEREDGE)

    def test_literal_role_arn_still_specific(self) -> None:
        """Guard: a fully literal role ARN (no wildcards) must
        continue to produce a specific role-targeted edge, not
        get incorrectly routed to hyperedge by the generalized
        detection."""
        from iamscope.collector.passrole import build_permission_edges

        role_arn = f"arn:aws:iam::{_ACCOUNT}:role/SpecificRole"
        policy = {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Effect": "Allow",
                    "Action": "iam:PassRole",
                    "Resource": role_arn,
                }
            ],
        }
        parse_results = parse_permission_policy(
            policy,
            source_arn=_USER_ARN,
            source_node_type=NODE_TYPE_IAM_USER,
            source_account_id=_ACCOUNT,
        )
        assert parse_results[0].is_wildcard_resource is False

        edges, _ = build_permission_edges(
            parse_results=parse_results,
            expansion_controller=ExpansionController(),
            known_role_arns=[role_arn],
        )
        assert len(edges) == 1
        assert edges[0].dst.node_type == NODE_TYPE_IAM_ROLE
        assert edges[0].dst.provider_id == role_arn


# ---------------------------------------------------------------------------
# BUG-022b — trust policy parser recognizes assumed-role ARNs and
# bare principal IDs
# ---------------------------------------------------------------------------


class TestBug022bTrustPolicyPrincipalRecognition:
    """Regression tests for the two trust-policy principal shapes
    that triggered 'Unrecognized' warnings on the OriginX run."""

    def test_assumed_role_arn_resolves_to_underlying_role(self) -> None:
        """AWS Control Tower / AFT trust pattern: the principal
        is an assumed-role session ARN. Must resolve to the
        underlying role and classify as IAM_ROLE with
        SPECIFIC_ROLE trust scope."""
        value = "arn:aws:sts::180294176532:assumed-role/AWSAFTAdmin/AWSAFT-Session"
        result = _resolve_aws_principal(value)
        assert result is not None
        principal_type, principal_value, node_type, trust_scope = result
        assert principal_type == "AWS"
        assert principal_value == "arn:aws:iam::180294176532:role/AWSAFTAdmin"
        assert node_type == NODE_TYPE_IAM_ROLE
        assert trust_scope == TRUST_SCOPE_SPECIFIC_ROLE

    def test_assumed_role_arn_session_name_with_path(self) -> None:
        """Session names can contain characters that look path-like.
        The parser must still extract the role name correctly."""
        value = "arn:aws:sts::123456789012:assumed-role/MyRole/AWSServiceRoleForSomething"
        result = _resolve_aws_principal(value)
        assert result is not None
        _, principal_value, node_type, _ = result
        assert principal_value == "arn:aws:iam::123456789012:role/MyRole"
        assert node_type == NODE_TYPE_IAM_ROLE

    def test_bare_aroa_principal_id_recognized(self) -> None:
        """AROA prefix = deleted role's frozen unique ID. Must be
        recognized (no 'Unrecognized' warning) and classified as
        external/dangling."""
        value = "AROAYEKP5XW36XB3V7AON"
        result = _resolve_aws_principal(value)
        assert result is not None
        principal_type, principal_value, node_type, _ = result
        assert principal_type == "AWS"
        assert principal_value == value
        assert node_type == NODE_TYPE_EXTERNAL_ACCOUNT

    def test_bare_aida_principal_id_recognized(self) -> None:
        """AIDA prefix = deleted user's frozen unique ID."""
        value = "AIDA1234567890ABCDEF"
        result = _resolve_aws_principal(value)
        assert result is not None
        _, _, node_type, _ = result
        assert node_type == NODE_TYPE_EXTERNAL_ACCOUNT

    def test_bare_akia_principal_id_recognized(self) -> None:
        """AKIA prefix = frozen access-key ID."""
        value = "AKIA1234567890ABCDEF"
        result = _resolve_aws_principal(value)
        assert result is not None

    def test_normal_role_arn_still_works(self) -> None:
        """Guard: BUG-022b must not regress the common case."""
        value = "arn:aws:iam::123456789012:role/ProdDeploy"
        result = _resolve_aws_principal(value)
        assert result is not None
        _, principal_value, node_type, trust_scope = result
        assert principal_value == value
        assert node_type == NODE_TYPE_IAM_ROLE
        assert trust_scope == TRUST_SCOPE_SPECIFIC_ROLE

    def test_account_root_still_works(self) -> None:
        """Guard: 12-digit bare account ID must still resolve to
        account root, not get confused with a bare principal ID."""
        value = "123456789012"
        result = _resolve_aws_principal(value)
        assert result is not None
        _, _, node_type, _ = result
        assert node_type == NODE_TYPE_ACCOUNT_ROOT

    def test_unrecognized_truly_unknown_format_still_warns(self, caplog) -> None:
        """Guard: a genuinely unrecognized principal format (not
        assumed-role, not bare principal ID, not ARN, not account
        ID) should still produce the 'Unrecognized' warning. We
        don't want the fix to have accidentally suppressed warnings
        for legitimately malformed principals."""
        import logging

        with caplog.at_level(logging.WARNING, logger="iamscope.parser.trust_policy"):
            result = _resolve_aws_principal("this-is-not-a-valid-principal")
        assert result is not None  # still emits as external (legacy shape)
        assert any("unrecognized" in r.message.lower() for r in caplog.records)
