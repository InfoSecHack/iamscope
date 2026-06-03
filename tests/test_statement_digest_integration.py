"""Integration tests for DIG-1: statement_digest wiring through parsers and resolvers.

S05 exit criteria:
- every trust edge from a fresh run has a non-empty digest in allow_controls
- every permission edge from a fresh run has a non-empty digest in allow_controls
- two runs on the same input produce byte-identical digests
- 100% invariant: no edge emitted without a digest
"""

from __future__ import annotations

import json

from iamscope.collector.passrole import build_permission_edges
from iamscope.constants import (
    NODE_TYPE_IAM_ROLE,
    NODE_TYPE_IAM_USER,
    PROVIDER_AWS,
    REGION_GLOBAL,
)
from iamscope.controls.expansion import ExpansionController
from iamscope.models import Node
from iamscope.parser.permission_policy import parse_permission_policy
from iamscope.parser.trust_policy import parse_trust_policy
from iamscope.resolver.cross_account import build_trust_edges

_TRUST_POLICY = {
    "Version": "2012-10-17",
    "Statement": [
        {
            "Effect": "Allow",
            "Principal": {"AWS": "arn:aws:iam::222222\u003222222:root"},
            "Action": "sts:AssumeRole",
        }
    ],
}

_IDENTITY_POLICY = {
    "Version": "2012-10-17",
    "Statement": [
        {
            "Effect": "Allow",
            "Action": "iam:PassRole",
            "Resource": "arn:aws:iam::111111\u003111111:role/LambdaExec",
            "Condition": {"StringEquals": {"iam:PassedToService": "lambda.amazonaws.com"}},
        }
    ],
}


def _role_node() -> Node:
    return Node(
        provider=PROVIDER_AWS,
        node_type=NODE_TYPE_IAM_ROLE,
        provider_id="arn:aws:iam::111111\u003111111:role/TestRole",
        region=REGION_GLOBAL,
        properties={"account_id": "111111\u003111111"},
    )


def _is_sha256_hex(s: str) -> bool:
    """True if s is a lowercase 64-char hex string."""
    if not isinstance(s, str):
        return False
    if len(s) != 64:
        return False
    return all(c in "0123456789abcdef" for c in s)


class TestTrustEdgeDigestPropagation:
    """Trust edges must carry a non-empty SHA-256 digest in allow_controls[0]."""

    def test_trust_edge_has_non_empty_digest(self) -> None:
        """build_trust_edges output carries digest via allow_controls ControlRef."""
        role = _role_node()
        trust_results = parse_trust_policy(
            policy_document=_TRUST_POLICY,
            role_arn=role.provider_id,
            role_account_id="111111\u003111111",
        )
        assert len(trust_results) >= 1
        # Every trust parse result must have a populated digest field.
        for tr in trust_results:
            assert _is_sha256_hex(tr.statement_digest), (
                f"TrustParseResult.statement_digest not a SHA-256 hex: {tr.statement_digest!r}"
            )

        edges = build_trust_edges(trust_results, role)
        assert len(edges) >= 1
        for edge in edges:
            assert "allow_controls" in edge.features
            refs = edge.features["allow_controls"]
            assert isinstance(refs, list)
            assert len(refs) == 1
            cr = refs[0]
            assert cr["control_type"] == "TRUST"
            assert cr["policy_arn"] == role.provider_id
            assert _is_sha256_hex(cr["digest"])


class TestPermissionEdgeDigestPropagation:
    """Permission edges must carry digests across all three emitter branches."""

    def test_permission_edge_has_non_empty_digest(self) -> None:
        """build_permission_edges output carries digest via allow_controls ControlRef."""
        parse_results = parse_permission_policy(
            policy_document=_IDENTITY_POLICY,
            source_arn="arn:aws:iam::111111\u003111111:user/Alice",
            source_node_type=NODE_TYPE_IAM_USER,
            source_account_id="111111\u003111111",
            policy_source="inline",
            policy_name="AliceAdmin",
            policy_arn="",
        )
        assert len(parse_results) >= 1
        for pr in parse_results:
            assert _is_sha256_hex(pr.statement_digest), (
                f"PermissionParseResult.statement_digest not a SHA-256 hex: {pr.statement_digest!r}"
            )

        ec = ExpansionController(global_mode="warn", passrole_mode="expand")
        edges, _ = build_permission_edges(parse_results, ec, [])
        assert len(edges) >= 1
        for edge in edges:
            assert "allow_controls" in edge.features
            refs = edge.features["allow_controls"]
            assert isinstance(refs, list)
            assert len(refs) == 1
            cr = refs[0]
            assert cr["control_type"] == "IDENTITY_POLICY"
            assert _is_sha256_hex(cr["digest"])


class TestDigestStability:
    """Determinism: two runs on the same input produce byte-identical digests."""

    def test_two_runs_same_policy_byte_identical_digest(self) -> None:
        """Parsing the same trust policy twice yields the same digest every run."""
        # Use a deep copy so the two calls cannot share a mutated reference.
        policy_a = json.loads(json.dumps(_TRUST_POLICY))
        policy_b = json.loads(json.dumps(_TRUST_POLICY))

        run_a = parse_trust_policy(
            policy_document=policy_a,
            role_arn="arn:aws:iam::111111\u003111111:role/TestRole",
            role_account_id="111111\u003111111",
        )
        run_b = parse_trust_policy(
            policy_document=policy_b,
            role_arn="arn:aws:iam::111111\u003111111:role/TestRole",
            role_account_id="111111\u003111111",
        )
        assert len(run_a) == len(run_b)
        for tr_a, tr_b in zip(run_a, run_b, strict=True):
            assert tr_a.statement_digest == tr_b.statement_digest
            assert _is_sha256_hex(tr_a.statement_digest)

    def test_two_runs_same_permission_policy_byte_identical_digest(self) -> None:
        """Parsing the same identity policy twice yields the same digest."""
        policy_a = json.loads(json.dumps(_IDENTITY_POLICY))
        policy_b = json.loads(json.dumps(_IDENTITY_POLICY))

        run_a = parse_permission_policy(
            policy_document=policy_a,
            source_arn="arn:aws:iam::111111\u003111111:user/Alice",
            source_node_type=NODE_TYPE_IAM_USER,
            source_account_id="111111\u003111111",
            policy_source="inline",
            policy_name="AliceAdmin",
            policy_arn="",
        )
        run_b = parse_permission_policy(
            policy_document=policy_b,
            source_arn="arn:aws:iam::111111\u003111111:user/Alice",
            source_node_type=NODE_TYPE_IAM_USER,
            source_account_id="111111\u003111111",
            policy_source="inline",
            policy_name="AliceAdmin",
            policy_arn="",
        )
        assert len(run_a) == len(run_b)
        for pr_a, pr_b in zip(run_a, run_b, strict=True):
            assert pr_a.statement_digest == pr_b.statement_digest
            assert _is_sha256_hex(pr_a.statement_digest)


class TestDigestInvariant:
    """100% invariant: every edge emitted from a mixed run has a digest."""

    def test_every_emitted_edge_has_digest(self) -> None:
        """Run a mixed trust + permission pipeline; assert 100% coverage."""
        role = _role_node()
        trust_results = parse_trust_policy(
            policy_document=_TRUST_POLICY,
            role_arn=role.provider_id,
            role_account_id="111111\u003111111",
        )
        trust_edges = build_trust_edges(trust_results, role)

        perm_results = parse_permission_policy(
            policy_document=_IDENTITY_POLICY,
            source_arn="arn:aws:iam::111111\u003111111:user/Alice",
            source_node_type=NODE_TYPE_IAM_USER,
            source_account_id="111111\u003111111",
            policy_source="inline",
            policy_name="AliceAdmin",
            policy_arn="",
        )
        ec = ExpansionController(global_mode="warn", passrole_mode="expand")
        perm_edges, _ = build_permission_edges(perm_results, ec, [])

        all_edges = trust_edges + perm_edges
        assert len(all_edges) >= 2

        for edge in all_edges:
            refs = edge.features.get("allow_controls")
            assert refs is not None, f"Edge missing allow_controls: {edge.edge_type}"
            assert len(refs) == 1
            digest = refs[0].get("digest", "")
            assert _is_sha256_hex(digest), f"Edge digest not a valid SHA-256 hex on {edge.edge_type}: {digest!r}"
