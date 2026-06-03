"""Tests for the secrets_blast_radius reasoner.

Covers:
- Basic validated: non-admin principal with GetSecretValue → validated/high
- Admin-equivalent principal → validated/critical (severity bump)
- Wildcard resource → inconclusive/medium
- SCP blocks → blocked/info
- Boundary blocks → blocked/info
- Partial SCP → inconclusive/medium
- Service principal → no finding (filtered by check 5)
- Multiple principals on same secret → one finding each
- Multiple secrets → findings for each
- Determinism: double run produces identical findings
"""

from __future__ import annotations

import json

from iamscope.constants import (
    CONSTRAINT_TYPE_IDENTITY_DENY,
    CONSTRAINT_TYPE_PERMISSION_BOUNDARY,
    CONSTRAINT_TYPE_SCP,
    NODE_TYPE_AWS_SERVICE,
    NODE_TYPE_IAM_ROLE,
    NODE_TYPE_IAM_USER,
    NODE_TYPE_SECRETS_MANAGER_SECRET,
    PROVIDER_AWS,
    REGION_GLOBAL,
)
from iamscope.models import Constraint, Edge, EdgeConstraint, Node
from iamscope.reasoner import FactGraph, SecretsBlastRadiusReasoner

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

_ACCOUNT = "111111\u003111111"
_ALICE_ARN = f"arn:aws:iam::{_ACCOUNT}:user/Alice"
_ADMIN_ARN = f"arn:aws:iam::{_ACCOUNT}:role/Admin"
_SECRET_1_ARN = f"arn:aws:secretsmanager:us-east-1:{_ACCOUNT}:secret:prod/db-password-abc123"
_SECRET_2_ARN = f"arn:aws:secretsmanager:us-east-1:{_ACCOUNT}:secret:prod/api-key-def456"

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _user(arn: str) -> Node:
    return Node(
        provider=PROVIDER_AWS,
        node_type=NODE_TYPE_IAM_USER,
        provider_id=arn,
        properties={"account_id": _ACCOUNT},
    )


def _role(arn: str) -> Node:
    return Node(
        provider=PROVIDER_AWS,
        node_type=NODE_TYPE_IAM_ROLE,
        provider_id=arn,
        properties={"account_id": _ACCOUNT},
    )


def _secret(arn: str) -> Node:
    return Node(
        provider=PROVIDER_AWS,
        node_type=NODE_TYPE_SECRETS_MANAGER_SECRET,
        provider_id=arn,
        properties={"account_id": _ACCOUNT},
    )


def _service() -> Node:
    return Node(
        provider=PROVIDER_AWS,
        node_type=NODE_TYPE_AWS_SERVICE,
        provider_id="lambda.amazonaws.com",
        properties={},
    )


def _get_secret_edge(
    *,
    src: Node,
    dst_arn: str,
    digest: str = "1" * 64,
    is_wildcard_resource: bool = False,
) -> Edge:
    """Permission edge: src can call secretsmanager:GetSecretValue on dst."""
    return Edge(
        edge_type="secretsmanager:GetSecretValue_permission",
        src=src.to_ref(),
        dst=Node(
            provider=PROVIDER_AWS,
            node_type=NODE_TYPE_SECRETS_MANAGER_SECRET,
            provider_id=dst_arn,
            properties={"account_id": _ACCOUNT},
        ).to_ref(),
        region=REGION_GLOBAL,
        features={
            "allow_controls": [
                {
                    "control_type": "PERMISSION",
                    "policy_arn": f"arn:aws:iam::{_ACCOUNT}:policy/SecretsAccess",
                    "statement_index": 0,
                    "digest": digest,
                    "summary": "secretsmanager:GetSecretValue grant",
                }
            ],
            "effect": "Allow",
            "has_conditions": False,
            "is_wildcard_resource": is_wildcard_resource,
            "layer": "permission",
            "raw_conditions": {},
            "resource_pattern": dst_arn,
            "statement_index": 0,
        },
    )


def _admin_grant_edge(role_arn: str) -> Edge:
    """iam:* self-edge proving admin equivalence."""
    return Edge(
        edge_type="iam:*_permission",
        src=Node(
            provider=PROVIDER_AWS,
            node_type=NODE_TYPE_IAM_ROLE,
            provider_id=role_arn,
            properties={"account_id": _ACCOUNT},
        ).to_ref(),
        dst=Node(
            provider=PROVIDER_AWS,
            node_type=NODE_TYPE_IAM_ROLE,
            provider_id=role_arn,
            properties={"account_id": _ACCOUNT},
        ).to_ref(),
        region=REGION_GLOBAL,
        features={
            "allow_controls": [
                {
                    "control_type": "PERMISSION",
                    "policy_arn": "arn:aws:iam::aws:policy/AdministratorAccess",
                    "statement_index": 0,
                    "digest": "a" * 64,
                    "summary": "iam:*",
                }
            ],
            "effect": "Allow",
            "has_conditions": False,
            "is_wildcard_resource": True,
            "layer": "permission",
            "raw_conditions": {},
            "resource_pattern": "*",
            "statement_index": 0,
        },
    )


def _scp(
    *,
    statement_id: str = "DenyGetSecret",
    parse_status: str = "complete",
) -> Constraint:
    return Constraint(
        provider=PROVIDER_AWS,
        constraint_type=CONSTRAINT_TYPE_SCP,
        scope_type="OU",
        scope_id="ou-prod-12345",
        policy_id="p-deny-getsecret",
        statement_id=statement_id,
        region=REGION_GLOBAL,
        properties={
            "deny_actions": ["secretsmanager:GetSecretValue"],
            "deny_not_actions": [],
            "exception_principal_patterns": [],
            "parse_status": parse_status,
            "policy_name": "DenyGetSecret",
            "resource_patterns": ["*"],
        },
    )


def _boundary() -> Constraint:
    return Constraint(
        provider=PROVIDER_AWS,
        constraint_type=CONSTRAINT_TYPE_PERMISSION_BOUNDARY,
        scope_type="USER",
        scope_id=_ALICE_ARN,
        policy_id=f"arn:aws:iam::{_ACCOUNT}:policy/AliceBoundary",
        statement_id="BoundaryNoSecrets",
        region=REGION_GLOBAL,
        properties={
            "allowed_actions": ["s3:*", "dynamodb:*"],
            "parse_status": "complete",
            "policy_name": "AliceBoundary",
        },
    )


def _identity_deny(
    *,
    statement_id: str = "DenyGetSecret",
    has_conditions: bool = False,
    parse_status: str = "complete",
) -> Constraint:
    return Constraint(
        provider=PROVIDER_AWS,
        constraint_type=CONSTRAINT_TYPE_IDENTITY_DENY,
        scope_type="Principal",
        scope_id=_ALICE_ARN,
        policy_id=f"arn:aws:iam::{_ACCOUNT}:policy/AliceDeny",
        statement_id=statement_id,
        region=REGION_GLOBAL,
        properties={
            "deny_actions": ["secretsmanager:GetSecretValue"],
            "resource_patterns": ["*"],
            "has_conditions": has_conditions,
            "raw_conditions": {"StringLike": {"aws:PrincipalArn": _ALICE_ARN}} if has_conditions else {},
            "parse_status": parse_status,
        },
    )


def _binding(
    *,
    edge_id: str,
    constraint_id: str,
    governance_confidence: str = "complete",
    likely_blocking: bool = True,
) -> EdgeConstraint:
    return EdgeConstraint(
        edge_id=edge_id,
        constraint_id=constraint_id,
        governance_confidence=governance_confidence,
        likely_blocking=likely_blocking,
        binding_reason=f"constraint {constraint_id} affects GetSecretValue",
    )


def _make_facts(
    *,
    nodes: tuple[Node, ...],
    edges: tuple[Edge, ...],
    constraints: tuple[Constraint, ...] = (),
    edge_constraints: tuple[EdgeConstraint, ...] = (),
) -> FactGraph:
    return FactGraph(
        nodes=nodes,
        edges=edges,
        constraints=constraints,
        edge_constraints=edge_constraints,
        scenario_hash="s" * 64,
        edge_budget_exhausted=False,
    )


def _build_alice_reads_secret() -> FactGraph:
    """Alice (non-admin user) has GetSecretValue on Secret1."""
    alice = _user(_ALICE_ARN)
    secret = _secret(_SECRET_1_ARN)
    edge = _get_secret_edge(src=alice, dst_arn=_SECRET_1_ARN)
    return _make_facts(nodes=(alice, secret), edges=(edge,))


def _build_admin_reads_secret() -> FactGraph:
    """Admin role (with iam:*) has GetSecretValue on Secret1."""
    admin = _role(_ADMIN_ARN)
    secret = _secret(_SECRET_1_ARN)
    edge = _get_secret_edge(src=admin, dst_arn=_SECRET_1_ARN, digest="2" * 64)
    admin_grant = _admin_grant_edge(_ADMIN_ARN)
    return _make_facts(nodes=(admin, secret), edges=(edge, admin_grant))


# ---------------------------------------------------------------------------
# Preconditions
# ---------------------------------------------------------------------------


class TestPreconditions:
    def test_empty_graph_skipped(self) -> None:
        empty = FactGraph(
            nodes=(),
            edges=(),
            constraints=(),
            edge_constraints=(),
            scenario_hash="x" * 64,
            edge_budget_exhausted=False,
        )
        ok, reason = SecretsBlastRadiusReasoner().preconditions_met(empty)
        assert not ok
        assert "no SecretsManagerSecret" in reason

    def test_graph_without_secret_skipped(self) -> None:
        facts = _make_facts(nodes=(_user(_ALICE_ARN),), edges=())
        ok, _ = SecretsBlastRadiusReasoner().preconditions_met(facts)
        assert not ok

    def test_graph_with_secret_runs(self) -> None:
        facts = _make_facts(nodes=(_secret(_SECRET_1_ARN),), edges=())
        ok, _ = SecretsBlastRadiusReasoner().preconditions_met(facts)
        assert ok


# ---------------------------------------------------------------------------
# Validated: non-admin → high; admin → critical
# ---------------------------------------------------------------------------


class TestValidatedFindings:
    def test_alice_reads_secret_validated_high(self) -> None:
        findings = SecretsBlastRadiusReasoner().run(_build_alice_reads_secret())
        assert len(findings) == 1
        f = findings[0]
        assert f.verdict.value == "validated"
        assert f.severity == "high"

    def test_admin_reads_secret_validated_critical(self) -> None:
        findings = SecretsBlastRadiusReasoner().run(_build_admin_reads_secret())
        assert len(findings) == 1
        f = findings[0]
        assert f.verdict.value == "validated"
        assert f.severity == "critical"

    def test_source_target_shape(self) -> None:
        f = SecretsBlastRadiusReasoner().run(_build_alice_reads_secret())[0]
        assert f.source.provider_id == _ALICE_ARN
        assert f.target.provider_id == _SECRET_1_ARN

    def test_check_1_passes(self) -> None:
        f = SecretsBlastRadiusReasoner().run(_build_alice_reads_secret())[0]
        c = next(c for c in f.required_checks if c.name == "principal_has_get_secret_value_permission")
        assert c.state.value == "pass"

    def test_check_2_clean_witness_passes(self) -> None:
        f = SecretsBlastRadiusReasoner().run(_build_alice_reads_secret())[0]
        c = next(c for c in f.required_checks if c.name == "permission_edge_targets_clean_witness")
        assert c.state.value == "pass"


# ---------------------------------------------------------------------------
# Inconclusive: wildcard resource
# ---------------------------------------------------------------------------


class TestWildcardInconclusive:
    def test_wildcard_resource_inconclusive_medium(self) -> None:
        alice = _user(_ALICE_ARN)
        secret = _secret(_SECRET_1_ARN)
        edge = _get_secret_edge(
            src=alice,
            dst_arn=_SECRET_1_ARN,
            is_wildcard_resource=True,
        )
        facts = _make_facts(nodes=(alice, secret), edges=(edge,))
        findings = SecretsBlastRadiusReasoner().run(facts)
        assert len(findings) == 1
        f = findings[0]
        assert f.verdict.value == "inconclusive"
        assert f.severity == "medium"


# ---------------------------------------------------------------------------
# Blocked: SCP or boundary
# ---------------------------------------------------------------------------


class TestSCPBlockers:
    def test_scp_complete_blocks(self) -> None:
        facts = _build_alice_reads_secret()
        edge = next(e for e in facts.edges if e.edge_type.startswith("secretsmanager"))
        scp = _scp()
        binding = _binding(edge_id=edge.edge_id, constraint_id=scp.constraint_id)
        facts2 = FactGraph(
            nodes=facts.nodes,
            edges=facts.edges,
            constraints=(scp,),
            edge_constraints=(binding,),
            scenario_hash=facts.scenario_hash,
            edge_budget_exhausted=False,
        )
        findings = SecretsBlastRadiusReasoner().run(facts2)
        assert len(findings) == 1
        assert findings[0].verdict.value == "blocked"
        assert findings[0].severity == "info"

    def test_scp_partial_inconclusive(self) -> None:
        facts = _build_alice_reads_secret()
        edge = next(e for e in facts.edges if e.edge_type.startswith("secretsmanager"))
        scp = _scp(parse_status="partial")
        binding = _binding(
            edge_id=edge.edge_id,
            constraint_id=scp.constraint_id,
            governance_confidence="partial",
            likely_blocking=True,
        )
        facts2 = FactGraph(
            nodes=facts.nodes,
            edges=facts.edges,
            constraints=(scp,),
            edge_constraints=(binding,),
            scenario_hash=facts.scenario_hash,
            edge_budget_exhausted=False,
        )
        findings = SecretsBlastRadiusReasoner().run(facts2)
        assert len(findings) == 1
        assert findings[0].verdict.value == "inconclusive"
        assert findings[0].severity == "medium"


class TestBoundaryBlockers:
    def test_boundary_blocks(self) -> None:
        facts = _build_alice_reads_secret()
        edge = next(e for e in facts.edges if e.edge_type.startswith("secretsmanager"))
        boundary = _boundary()
        binding = _binding(edge_id=edge.edge_id, constraint_id=boundary.constraint_id)
        facts2 = FactGraph(
            nodes=facts.nodes,
            edges=facts.edges,
            constraints=(boundary,),
            edge_constraints=(binding,),
            scenario_hash=facts.scenario_hash,
            edge_budget_exhausted=False,
        )
        findings = SecretsBlastRadiusReasoner().run(facts2)
        assert len(findings) == 1
        assert findings[0].verdict.value == "blocked"


class TestIdentityDenyBlockers:
    def test_complete_identity_deny_blocks(self) -> None:
        facts = _build_alice_reads_secret()
        edge = next(e for e in facts.edges if e.edge_type.startswith("secretsmanager"))
        deny = _identity_deny()
        binding = _binding(edge_id=edge.edge_id, constraint_id=deny.constraint_id)
        facts2 = FactGraph(
            nodes=facts.nodes,
            edges=facts.edges,
            constraints=(deny,),
            edge_constraints=(binding,),
            scenario_hash=facts.scenario_hash,
            edge_budget_exhausted=False,
        )
        findings = SecretsBlastRadiusReasoner().run(facts2)
        assert len(findings) == 1
        f = findings[0]
        assert f.verdict.value == "blocked"
        assert f.severity == "info"
        check = next(c for c in f.required_checks if c.name == "no_identity_deny_blocks_get_secret_value")
        assert check.state.value == "fail"
        assert any(b.kind == "identity_deny" for b in f.blockers_observed)

    def test_needs_review_identity_deny_is_inconclusive(self) -> None:
        facts = _build_alice_reads_secret()
        edge = next(e for e in facts.edges if e.edge_type.startswith("secretsmanager"))
        deny = _identity_deny(
            statement_id="ConditionalDenyGetSecret",
            has_conditions=True,
        )
        binding = _binding(
            edge_id=edge.edge_id,
            constraint_id=deny.constraint_id,
            governance_confidence="needs_review",
            likely_blocking=True,
        )
        facts2 = FactGraph(
            nodes=facts.nodes,
            edges=facts.edges,
            constraints=(deny,),
            edge_constraints=(binding,),
            scenario_hash=facts.scenario_hash,
            edge_budget_exhausted=False,
        )
        findings = SecretsBlastRadiusReasoner().run(facts2)
        assert len(findings) == 1
        f = findings[0]
        assert f.verdict.value == "inconclusive"
        assert f.severity == "medium"
        check = next(c for c in f.required_checks if c.name == "no_identity_deny_blocks_get_secret_value")
        assert check.state.value == "unknown"


# ---------------------------------------------------------------------------
# Filter: service principals
# ---------------------------------------------------------------------------


class TestPrincipalFilter:
    def test_service_principal_filtered(self) -> None:
        """A service principal with GetSecretValue should not produce a finding."""
        svc = _service()
        secret = _secret(_SECRET_1_ARN)
        edge = _get_secret_edge(src=svc, dst_arn=_SECRET_1_ARN)
        facts = _make_facts(nodes=(svc, secret), edges=(edge,))
        findings = SecretsBlastRadiusReasoner().run(facts)
        assert len(findings) == 0


# ---------------------------------------------------------------------------
# Multiple principals + secrets
# ---------------------------------------------------------------------------


class TestMultiplePrincipals:
    def test_two_principals_two_findings(self) -> None:
        """Alice and Admin both read Secret1 → 2 findings."""
        alice = _user(_ALICE_ARN)
        admin = _role(_ADMIN_ARN)
        secret = _secret(_SECRET_1_ARN)
        alice_edge = _get_secret_edge(src=alice, dst_arn=_SECRET_1_ARN, digest="1" * 64)
        admin_edge = _get_secret_edge(src=admin, dst_arn=_SECRET_1_ARN, digest="2" * 64)
        admin_grant = _admin_grant_edge(_ADMIN_ARN)
        facts = _make_facts(
            nodes=(alice, admin, secret),
            edges=(alice_edge, admin_edge, admin_grant),
        )
        findings = SecretsBlastRadiusReasoner().run(facts)
        assert len(findings) == 2
        severities = {f.source.provider_id: f.severity for f in findings}
        assert severities[_ALICE_ARN] == "high"
        assert severities[_ADMIN_ARN] == "critical"


class TestMultipleSecrets:
    def test_alice_reads_two_secrets(self) -> None:
        """Alice has GetSecretValue on both Secret1 and Secret2 → 2 findings."""
        alice = _user(_ALICE_ARN)
        secret_1 = _secret(_SECRET_1_ARN)
        secret_2 = _secret(_SECRET_2_ARN)
        edge_1 = _get_secret_edge(src=alice, dst_arn=_SECRET_1_ARN, digest="1" * 64)
        edge_2 = _get_secret_edge(src=alice, dst_arn=_SECRET_2_ARN, digest="2" * 64)
        facts = _make_facts(
            nodes=(alice, secret_1, secret_2),
            edges=(edge_1, edge_2),
        )
        findings = SecretsBlastRadiusReasoner().run(facts)
        assert len(findings) == 2
        targets = sorted(f.target.provider_id for f in findings)
        assert targets == sorted([_SECRET_1_ARN, _SECRET_2_ARN])


# ---------------------------------------------------------------------------
# Determinism
# ---------------------------------------------------------------------------


class TestDeterminism:
    def test_double_run_same_findings(self) -> None:
        f1 = SecretsBlastRadiusReasoner().run(_build_alice_reads_secret())
        f2 = SecretsBlastRadiusReasoner().run(_build_alice_reads_secret())
        assert len(f1) == len(f2) == 1
        assert f1[0].finding_id == f2[0].finding_id
        assert f1[0].evidence.bundle_digest == f2[0].evidence.bundle_digest


# ---------------------------------------------------------------------------
# KMS v2: _kms_policy_allows_decrypt helper tests
# ---------------------------------------------------------------------------


class TestKmsPolicyAllowsDecrypt:
    """Unit tests for the _kms_policy_allows_decrypt helper function."""

    _ALICE = _ALICE_ARN
    _ACCOUNT = "111111\u003111111"
    _KEY_ARN = f"arn:aws:kms:us-east-1:{_ACCOUNT}:key/abc-123"

    def _call(self, policy_dict: dict) -> tuple:
        from iamscope.reasoner.secrets_blast_radius import (
            _kms_policy_allows_decrypt,
        )

        return _kms_policy_allows_decrypt(
            policy_json=json.dumps(policy_dict),
            principal_arn=self._ALICE,
            principal_account_id=self._ACCOUNT,
            key_arn=self._KEY_ARN,
        )

    def test_account_root_delegation_passes(self) -> None:
        """Principal: arn:...:root for same account → PASS."""
        policy = {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Effect": "Allow",
                    "Principal": {"AWS": f"arn:aws:iam::{self._ACCOUNT}:root"},
                    "Action": "kms:*",
                    "Resource": "*",
                }
            ],
        }
        state, reason = self._call(policy)
        assert state.value == "pass"

    def test_specific_principal_grant_passes(self) -> None:
        """Principal: arn:...:user/Alice exactly matches → PASS."""
        policy = {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Effect": "Allow",
                    "Principal": {"AWS": self._ALICE},
                    "Action": "kms:Decrypt",
                    "Resource": "*",
                }
            ],
        }
        state, _ = self._call(policy)
        assert state.value == "pass"

    def test_wildcard_principal_passes(self) -> None:
        """Principal: * → PASS."""
        policy = {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Effect": "Allow",
                    "Principal": "*",
                    "Action": "kms:Decrypt",
                    "Resource": "*",
                }
            ],
        }
        state, _ = self._call(policy)
        assert state.value == "pass"

    def test_wildcard_action_passes(self) -> None:
        """Action: * → PASS (covers kms:Decrypt)."""
        policy = {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Effect": "Allow",
                    "Principal": {"AWS": self._ALICE},
                    "Action": "*",
                    "Resource": "*",
                }
            ],
        }
        state, _ = self._call(policy)
        assert state.value == "pass"

    def test_specific_resource_arn_passes(self) -> None:
        """Resource matching key's ARN → PASS."""
        policy = {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Effect": "Allow",
                    "Principal": {"AWS": self._ALICE},
                    "Action": "kms:Decrypt",
                    "Resource": self._KEY_ARN,
                }
            ],
        }
        state, _ = self._call(policy)
        assert state.value == "pass"

    def test_no_matching_allow_fails(self) -> None:
        """Policy has an Allow but for a different principal → FAIL."""
        policy = {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Effect": "Allow",
                    "Principal": {"AWS": f"arn:aws:iam::{self._ACCOUNT}:user/Bob"},
                    "Action": "kms:Decrypt",
                    "Resource": "*",
                }
            ],
        }
        state, reason = self._call(policy)
        assert state.value == "fail"
        assert "no KMS policy Allow" in reason

    def test_malformed_json_unknown(self) -> None:
        """Malformed JSON → UNKNOWN (refuses to guess)."""
        from iamscope.reasoner.secrets_blast_radius import (
            _kms_policy_allows_decrypt,
        )

        state, reason = _kms_policy_allows_decrypt(
            policy_json="not valid json {{{",
            principal_arn=self._ALICE,
            principal_account_id=self._ACCOUNT,
            key_arn=self._KEY_ARN,
        )
        assert state.value == "unknown"
        assert "malformed" in reason.lower()

    def test_deny_statement_unknown(self) -> None:
        """BUG-009b: a Deny statement is only meaningful if it's
        RELEVANT to our target (principal, kms:Decrypt, key_arn).
        This test uses a Deny on `kms:Decrypt` explicitly so the
        relevance filter catches it. A relevant, conditioned Deny
        produces UNKNOWN; a relevant, unconditioned Deny produces
        FAIL; an irrelevant Deny (e.g., `kms:Delete*`) is skipped
        and the evaluation falls through to the Allow loop — that
        last case is covered by a separate BUG-009b test below.

        Pre-BUG-009b this test used `kms:Delete*` as the Deny and
        asserted UNKNOWN, which encoded the bug: the reasoner was
        flipping to UNKNOWN on an irrelevant Deny. Post-fix the
        correct answer is PASS (the Allow for `kms:*` covers
        decrypt). The test has been updated to use a clearly-
        relevant Deny so it still exercises the "Deny → UNKNOWN"
        path for the conditional case.
        """
        policy = {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Effect": "Allow",
                    "Principal": {"AWS": self._ALICE},
                    "Action": "kms:*",
                    "Resource": "*",
                },
                {
                    # Relevant Deny with a Condition → UNKNOWN
                    # (runtime-dependent).
                    "Effect": "Deny",
                    "Principal": "*",
                    "Action": "kms:Decrypt",
                    "Resource": "*",
                    "Condition": {
                        "StringEquals": {"aws:SourceVpc": "vpc-xxx"},
                    },
                },
            ],
        }
        state, reason = self._call(policy)
        assert state.value == "unknown"
        assert "deny" in reason.lower()

    def test_conditioned_allow_unknown(self) -> None:
        """Matching Allow with Condition block → UNKNOWN."""
        policy = {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Effect": "Allow",
                    "Principal": {"AWS": self._ALICE},
                    "Action": "kms:Decrypt",
                    "Resource": "*",
                    "Condition": {
                        "StringEquals": {"aws:SourceVpc": "vpc-123"},
                    },
                }
            ],
        }
        state, reason = self._call(policy)
        assert state.value == "unknown"
        assert "condition" in reason.lower()

    def test_not_principal_unknown(self) -> None:
        """NotPrincipal clause → UNKNOWN (harder to reason about)."""
        policy = {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Effect": "Allow",
                    "NotPrincipal": {"AWS": f"arn:aws:iam::{self._ACCOUNT}:user/Bob"},
                    "Action": "kms:Decrypt",
                    "Resource": "*",
                }
            ],
        }
        state, reason = self._call(policy)
        assert state.value == "unknown"
        assert "notprincipal" in reason.lower() or "not" in reason.lower()

    def test_empty_policy_unknown(self) -> None:
        """Empty string policy → UNKNOWN."""
        from iamscope.reasoner.secrets_blast_radius import (
            _kms_policy_allows_decrypt,
        )

        state, reason = _kms_policy_allows_decrypt(
            policy_json="",
            principal_arn=self._ALICE,
            principal_account_id=self._ACCOUNT,
            key_arn=self._KEY_ARN,
        )
        assert state.value == "unknown"


# ---------------------------------------------------------------------------
# KMS v2: integration tests against the reasoner
# ---------------------------------------------------------------------------


_KEY_ARN = f"arn:aws:kms:us-east-1:{_ACCOUNT}:key/abc-123"


def _kms_key_node(policy: dict) -> Node:
    return Node(
        provider=PROVIDER_AWS,
        node_type="KMSKey",
        provider_id=_KEY_ARN,
        properties={
            "account_id": _ACCOUNT,
            "key_id": _KEY_ARN,
            "key_manager": "CUSTOMER",
            "key_policy": json.dumps(policy),
        },
    )


def _secret_with_kms(kms_key_id: str) -> Node:
    return Node(
        provider=PROVIDER_AWS,
        node_type=NODE_TYPE_SECRETS_MANAGER_SECRET,
        provider_id=_SECRET_1_ARN,
        properties={"account_id": _ACCOUNT, "kms_key_id": kms_key_id},
    )


class TestKmsIntegration:
    """Reasoner-level tests for v2 KMS check integration."""

    def test_aws_managed_default_still_validated(self) -> None:
        """Secret with no kms_key_id → check 6 PASSes, finding is validated."""
        findings = SecretsBlastRadiusReasoner().run(_build_alice_reads_secret())
        assert len(findings) == 1
        assert findings[0].verdict.value == "validated"
        assert findings[0].severity == "high"

    def test_cmk_with_account_root_delegation_validated(self) -> None:
        """CMK policy with account-root delegation → check 6 PASS → validated."""
        alice = _user(_ALICE_ARN)
        secret = _secret_with_kms(_KEY_ARN)
        kms = _kms_key_node(
            {
                "Version": "2012-10-17",
                "Statement": [
                    {
                        "Effect": "Allow",
                        "Principal": {"AWS": f"arn:aws:iam::{_ACCOUNT}:root"},
                        "Action": "kms:*",
                        "Resource": "*",
                    }
                ],
            }
        )
        edge = _get_secret_edge(src=alice, dst_arn=_SECRET_1_ARN)
        facts = _make_facts(nodes=(alice, secret, kms), edges=(edge,))
        findings = SecretsBlastRadiusReasoner().run(facts)
        assert len(findings) == 1
        assert findings[0].verdict.value == "validated"
        assert findings[0].severity == "high"

    def test_cmk_blocks_principal_precondition_only(self) -> None:
        """CMK policy grants only Bob → check 6 FAIL → precondition_only/medium."""
        alice = _user(_ALICE_ARN)
        secret = _secret_with_kms(_KEY_ARN)
        kms = _kms_key_node(
            {
                "Version": "2012-10-17",
                "Statement": [
                    {
                        "Effect": "Allow",
                        "Principal": {"AWS": f"arn:aws:iam::{_ACCOUNT}:user/Bob"},
                        "Action": "kms:Decrypt",
                        "Resource": "*",
                    }
                ],
            }
        )
        edge = _get_secret_edge(src=alice, dst_arn=_SECRET_1_ARN)
        facts = _make_facts(nodes=(alice, secret, kms), edges=(edge,))
        findings = SecretsBlastRadiusReasoner().run(facts)
        assert len(findings) == 1
        assert findings[0].verdict.value == "precondition_only"
        assert findings[0].severity == "medium"

    def test_cmk_with_conditions_inconclusive(self) -> None:
        """CMK policy has matching Allow with Condition → check 6 UNKNOWN → inconclusive."""
        alice = _user(_ALICE_ARN)
        secret = _secret_with_kms(_KEY_ARN)
        kms = _kms_key_node(
            {
                "Version": "2012-10-17",
                "Statement": [
                    {
                        "Effect": "Allow",
                        "Principal": {"AWS": f"arn:aws:iam::{_ACCOUNT}:root"},
                        "Action": "kms:*",
                        "Resource": "*",
                        "Condition": {"StringEquals": {"aws:SourceVpc": "vpc-xxx"}},
                    }
                ],
            }
        )
        edge = _get_secret_edge(src=alice, dst_arn=_SECRET_1_ARN)
        facts = _make_facts(nodes=(alice, secret, kms), edges=(edge,))
        findings = SecretsBlastRadiusReasoner().run(facts)
        assert len(findings) == 1
        assert findings[0].verdict.value == "inconclusive"
        assert findings[0].severity == "medium"

    def test_cmk_not_in_graph_inconclusive(self) -> None:
        """Secret references a KMS key that isn't in the graph → UNKNOWN → inconclusive."""
        alice = _user(_ALICE_ARN)
        secret = _secret_with_kms(_KEY_ARN)  # no matching KMSKey node
        edge = _get_secret_edge(src=alice, dst_arn=_SECRET_1_ARN)
        facts = _make_facts(nodes=(alice, secret), edges=(edge,))
        findings = SecretsBlastRadiusReasoner().run(facts)
        assert len(findings) == 1
        assert findings[0].verdict.value == "inconclusive"
        assert findings[0].severity == "medium"

    def test_aws_managed_alias_still_validated(self) -> None:
        """Secret with kms_key_id='alias/aws/secretsmanager' → PASS → validated."""
        alice = _user(_ALICE_ARN)
        secret = _secret_with_kms("alias/aws/secretsmanager")
        edge = _get_secret_edge(src=alice, dst_arn=_SECRET_1_ARN)
        facts = _make_facts(nodes=(alice, secret), edges=(edge,))
        findings = SecretsBlastRadiusReasoner().run(facts)
        assert len(findings) == 1
        assert findings[0].verdict.value == "validated"


# ---------------------------------------------------------------------------
# BUG-013b: degraded KMS nodes with fetch-failure markers
# ---------------------------------------------------------------------------


def _kms_key_node_fetch_failed() -> Node:
    """Build a KMSKey node as the collector would produce it when
    GetKeyPolicy raised during collection: empty key_policy string,
    plus the new `kms_policy_fetch_failed=True` marker that the
    reasoner consults to distinguish this case from "customer legit
    has no policy set"."""
    return Node(
        provider=PROVIDER_AWS,
        node_type="KMSKey",
        provider_id=_KEY_ARN,
        properties={
            "account_id": _ACCOUNT,
            "key_id": _KEY_ARN,
            "key_manager": "CUSTOMER",
            "key_policy": "",
            "kms_policy_fetch_failed": True,
            "kms_metadata_fetch_failed": False,
        },
    )


class TestKmsPolicyFetchFailedMarker:
    """BUG-013b: the reasoner must distinguish "collector couldn't
    fetch the policy" from "customer legitimately has no policy set",
    even though both cases flow through to the same verdict
    (INCONCLUSIVE). The distinction matters because the operator
    action is different: one requires investigating collector IAM
    permissions, the other requires investigating the key itself."""

    def test_fetch_failed_still_inconclusive(self) -> None:
        """Degraded KMS node → check 6 UNKNOWN → verdict INCONCLUSIVE.
        Verdict is unchanged from the pre-fix behavior — this guards
        against accidentally escalating or de-escalating the verdict
        while adjusting the reason string."""
        alice = _user(_ALICE_ARN)
        secret = _secret_with_kms(_KEY_ARN)
        kms = _kms_key_node_fetch_failed()
        edge = _get_secret_edge(src=alice, dst_arn=_SECRET_1_ARN)
        facts = _make_facts(nodes=(alice, secret, kms), edges=(edge,))
        findings = SecretsBlastRadiusReasoner().run(facts)
        assert len(findings) == 1
        assert findings[0].verdict.value == "inconclusive"

    def test_fetch_failed_reason_is_actionable(self) -> None:
        """The check 6 reason must mention the collector failure and
        the specific IAM permission to investigate. This is what makes
        the finding actionable for the operator."""
        alice = _user(_ALICE_ARN)
        secret = _secret_with_kms(_KEY_ARN)
        kms = _kms_key_node_fetch_failed()
        edge = _get_secret_edge(src=alice, dst_arn=_SECRET_1_ARN)
        facts = _make_facts(nodes=(alice, secret, kms), edges=(edge,))
        findings = SecretsBlastRadiusReasoner().run(facts)
        check_6 = next(
            c for c in findings[0].required_checks if c.name == "kms_key_policy_allows_decrypt_for_principal"
        )
        assert check_6.state.value == "unknown"
        reason = check_6.reason.lower()
        # Must mention the failure mechanism...
        assert "fetch" in reason or "collection" in reason
        # ...and the specific IAM action to investigate.
        assert "kms:getkeypolicy" in reason or "getkeypolicy" in reason

    def test_fetch_failed_reason_differs_from_legit_empty(self) -> None:
        """Pre-fix guard: a CMK with `kms_policy_fetch_failed=True`
        must produce a *different* reason string from a CMK with a
        legitimately empty policy string (flag=False). Both should be
        UNKNOWN, but the reasons must be distinguishable so operators
        can route the investigation correctly."""
        alice = _user(_ALICE_ARN)
        secret = _secret_with_kms(_KEY_ARN)
        edge = _get_secret_edge(src=alice, dst_arn=_SECRET_1_ARN)

        # Case A: legit empty (flag=False)
        legit_empty = Node(
            provider=PROVIDER_AWS,
            node_type="KMSKey",
            provider_id=_KEY_ARN,
            properties={
                "account_id": _ACCOUNT,
                "key_id": _KEY_ARN,
                "key_manager": "CUSTOMER",
                "key_policy": "",
                "kms_policy_fetch_failed": False,
            },
        )
        facts_a = _make_facts(nodes=(alice, secret, legit_empty), edges=(edge,))
        finding_a = SecretsBlastRadiusReasoner().run(facts_a)[0]
        reason_a = next(
            c.reason for c in finding_a.required_checks if c.name == "kms_key_policy_allows_decrypt_for_principal"
        )

        # Case B: fetch failed (flag=True)
        facts_b = _make_facts(
            nodes=(alice, secret, _kms_key_node_fetch_failed()),
            edges=(edge,),
        )
        finding_b = SecretsBlastRadiusReasoner().run(facts_b)[0]
        reason_b = next(
            c.reason for c in finding_b.required_checks if c.name == "kms_key_policy_allows_decrypt_for_principal"
        )

        assert reason_a != reason_b
        assert "empty" in reason_a.lower()
        assert "fetch" in reason_b.lower() or "collection" in reason_b.lower()


# ---------------------------------------------------------------------------
# BUG-007/8/9: KMS evaluator wildcard matching (fnmatch semantics)
# ---------------------------------------------------------------------------


class TestKmsEvaluatorWildcards:
    """Regression tests for the BUG-007/8/9 cluster: the KMS evaluator
    previously used exact string comparison for principals, resources,
    and actions, producing false negatives on very common wildcard
    patterns like `arn:aws:kms:us-east-1:*:key/*` (cross-account key
    sharing) or `arn:aws:iam::<acct>:role/prod-*` (scoped principal
    grants). The v0.2.30 fix uses `fnmatch.fnmatchcase` for all three
    fields, consistent with the rest of the iamscope codebase
    (passrole, permission_policy, permission_boundary, fact_graph).

    Each test drives `_kms_policy_allows_decrypt` directly with a
    representative real-world policy shape and asserts PASS."""

    _ALICE_ARN = "arn:aws:iam::111111\u003111111:user/Alice"
    _ACCOUNT = "111111\u003111111"
    _KEY_ARN = "arn:aws:kms:us-east-1:111111\u003111111:key/abc-123-def"

    def _call(
        self,
        policy: dict,
        key_arn: str | None = None,
    ) -> tuple[str, str]:
        from iamscope.reasoner.secrets_blast_radius import (
            _kms_policy_allows_decrypt,
        )

        state, reason = _kms_policy_allows_decrypt(
            policy_json=json.dumps(policy),
            principal_arn=self._ALICE_ARN,
            principal_account_id=self._ACCOUNT,
            key_arn=key_arn or self._KEY_ARN,
        )
        return state.value, reason

    # BUG-007: principal wildcard patterns
    def test_principal_role_wildcard_in_account(self) -> None:
        """`arn:aws:iam::<acct>:role/*` — grant to all roles in the
        account. Alice is a user not a role, so this should NOT match.
        Guards against over-matching — the fnmatch must not be so
        loose that it grants to principals outside the pattern."""
        policy = {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Effect": "Allow",
                    "Principal": {
                        "AWS": "arn:aws:iam::111111\u003111111:role/*",
                    },
                    "Action": "kms:Decrypt",
                    "Resource": "*",
                }
            ],
        }
        state, _ = self._call(policy)
        # Alice is a user, not a role, so the role/* pattern
        # should not fnmatch the user ARN. No other Allow
        # statement → FAIL (no matching Allow).
        assert state == "fail"

    def test_principal_prefix_wildcard_matches_user(self) -> None:
        """`arn:aws:iam::<acct>:user/Al*` — prefix scoped to users
        starting with 'Al'. Alice matches → PASS. This is the core
        BUG-007 case — the pre-fix evaluator would have returned FAIL
        even though the policy clearly grants Alice access."""
        policy = {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Effect": "Allow",
                    "Principal": {
                        "AWS": "arn:aws:iam::111111\u003111111:user/Al*",
                    },
                    "Action": "kms:Decrypt",
                    "Resource": "*",
                }
            ],
        }
        state, _ = self._call(policy)
        assert state == "pass"

    def test_principal_cross_account_wildcard(self) -> None:
        """`arn:aws:iam::*:user/Alice` — org-wide grant for users
        named Alice in any account. Alice's specific ARN fnmatches
        this pattern → PASS."""
        policy = {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Effect": "Allow",
                    "Principal": {
                        "AWS": "arn:aws:iam::*:user/Alice",
                    },
                    "Action": "kms:Decrypt",
                    "Resource": "*",
                }
            ],
        }
        state, _ = self._call(policy)
        assert state == "pass"

    # BUG-008: resource wildcard patterns
    def test_resource_cross_account_kms_wildcard(self) -> None:
        """`arn:aws:kms:us-east-1:*:key/*` — cross-account boilerplate.
        The candidate key_arn is in account 111111\u003111111 which matches
        the account wildcard → PASS. This is the single most common
        KMS Resource pattern in real-world multi-account orgs and the
        pre-fix evaluator would have returned FAIL."""
        policy = {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Effect": "Allow",
                    "Principal": {"AWS": self._ALICE_ARN},
                    "Action": "kms:Decrypt",
                    "Resource": "arn:aws:kms:us-east-1:*:key/*",
                }
            ],
        }
        state, _ = self._call(policy)
        assert state == "pass"

    def test_resource_region_wildcard(self) -> None:
        """`arn:aws:kms:*:<acct>:key/<uuid>` — region wildcard on a
        specific key ID. Matches because `*` spans 'us-east-1'."""
        policy = {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Effect": "Allow",
                    "Principal": {"AWS": self._ALICE_ARN},
                    "Action": "kms:Decrypt",
                    "Resource": "arn:aws:kms:*:111111\u003111111:key/abc-123-def",
                }
            ],
        }
        state, _ = self._call(policy)
        assert state == "pass"

    def test_resource_key_id_prefix_wildcard(self) -> None:
        """`arn:aws:kms:us-east-1:<acct>:key/abc-*` — scoped by
        key-ID prefix. Matches the specific key_arn."""
        policy = {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Effect": "Allow",
                    "Principal": {"AWS": self._ALICE_ARN},
                    "Action": "kms:Decrypt",
                    "Resource": "arn:aws:kms:us-east-1:111111\u003111111:key/abc-*",
                }
            ],
        }
        state, _ = self._call(policy)
        assert state == "pass"

    def test_resource_wildcard_does_not_over_match(self) -> None:
        """`arn:aws:kms:us-west-2:<acct>:key/*` — scoped to a
        different region than the candidate key. Must NOT match.
        Guards against the fnmatch being too permissive."""
        policy = {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Effect": "Allow",
                    "Principal": {"AWS": self._ALICE_ARN},
                    "Action": "kms:Decrypt",
                    "Resource": "arn:aws:kms:us-west-2:111111\u003111111:key/*",
                }
            ],
        }
        state, _ = self._call(policy)
        assert state == "fail"

    # BUG-009: action wildcard patterns
    def test_action_partial_wildcard_decrypt(self) -> None:
        """`kms:De*` — scoped wildcard that covers Decrypt. Must
        match. Pre-fix evaluator would have returned FAIL because
        the set intersection missed this pattern."""
        policy = {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Effect": "Allow",
                    "Principal": {"AWS": self._ALICE_ARN},
                    "Action": "kms:De*",
                    "Resource": "*",
                }
            ],
        }
        state, _ = self._call(policy)
        assert state == "pass"

    def test_action_wildcard_does_not_over_match(self) -> None:
        """`kms:En*` — covers Encrypt but not Decrypt. Must NOT
        match. Guards against action wildcards being treated as
        too broad."""
        policy = {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Effect": "Allow",
                    "Principal": {"AWS": self._ALICE_ARN},
                    "Action": "kms:En*",
                    "Resource": "*",
                }
            ],
        }
        state, _ = self._call(policy)
        assert state == "fail"

    # Realistic combined scenario
    def test_realistic_cross_account_sharing_policy(self) -> None:
        """Real-world shape: an account root delegates to all roles
        matching a prefix, with cross-account KMS resource wildcard,
        and action-level wildcard. This is the shape that would have
        maximally exercised all three pre-fix bugs at once. Should
        PASS cleanly."""
        policy = {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Sid": "CrossAccountDecrypt",
                    "Effect": "Allow",
                    "Principal": {
                        "AWS": "arn:aws:iam::111111\u003111111:user/*",
                    },
                    "Action": [
                        "kms:Decrypt",
                        "kms:DescribeKey",
                        "kms:GenerateDataKey*",
                    ],
                    "Resource": "arn:aws:kms:us-east-1:*:key/*",
                }
            ],
        }
        state, _ = self._call(policy)
        assert state == "pass"


# ---------------------------------------------------------------------------
# BUG-009: ambiguity flags must only trigger on statements relevant
# to the target (principal, kms:Decrypt, key_arn). Pre-BUG-009 the
# evaluator set had_ambiguity=True on ANY Allow with a Condition or
# Not* clause, causing unrelated conditional statements to flip
# findings from FAIL → UNKNOWN, which bubbled up from
# `check 6 FAIL → PRECONDITION_ONLY` to
# `check 6 UNKNOWN → INCONCLUSIVE`.
# ---------------------------------------------------------------------------


class TestKmsEvaluatorBug009RelevanceFirst:
    """BUG-009 regression suite: ambiguity flags must not fire on
    KMS policy statements that are irrelevant to the target."""

    _ACCOUNT = "111111\u003111111"
    _ALICE = f"arn:aws:iam::{_ACCOUNT}:user/Alice"
    _KEY_ARN = f"arn:aws:kms:us-east-1:{_ACCOUNT}:key/target-key"

    def _eval(self, policy: dict) -> tuple[str, str]:
        """Small helper — calls the evaluator, returns (state_value, reason)."""
        from iamscope.reasoner.secrets_blast_radius import (
            _kms_policy_allows_decrypt,
        )

        state, reason = _kms_policy_allows_decrypt(
            policy_json=json.dumps(policy),
            principal_arn=self._ALICE,
            principal_account_id=self._ACCOUNT,
            key_arn=self._KEY_ARN,
        )
        return state.value, reason

    def test_unrelated_conditional_allow_does_not_mask_fail(self) -> None:
        """A conditional Allow for kms:Encrypt (NOT decrypt) must
        not mark the evaluation ambiguous. The correct result for a
        policy with ONLY this statement is FAIL, not UNKNOWN."""
        policy = {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Effect": "Allow",
                    "Principal": {"AWS": "*"},
                    "Action": "kms:Encrypt",  # irrelevant
                    "Resource": "*",
                    "Condition": {"StringEquals": {"aws:SourceVpc": "vpc-xxx"}},
                }
            ],
        }
        state, _ = self._eval(policy)
        assert state == "fail", "Unrelated kms:Encrypt Condition should not contaminate kms:Decrypt evaluation"

    def test_unrelated_conditional_allow_different_principal(self) -> None:
        """A conditional Allow for kms:Decrypt to a DIFFERENT
        principal must not mark the evaluation ambiguous for us."""
        policy = {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Effect": "Allow",
                    "Principal": {"AWS": f"arn:aws:iam::{self._ACCOUNT}:user/Bob"},
                    "Action": "kms:Decrypt",
                    "Resource": "*",
                    "Condition": {"StringEquals": {"aws:SourceVpc": "vpc-xxx"}},
                }
            ],
        }
        state, _ = self._eval(policy)
        assert state == "fail"

    def test_unrelated_conditional_allow_different_resource(self) -> None:
        """A conditional Allow for kms:Decrypt on a DIFFERENT key
        must not mark the evaluation ambiguous for our key."""
        other_key = f"arn:aws:kms:us-east-1:{self._ACCOUNT}:key/other-key"
        policy = {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Effect": "Allow",
                    "Principal": {"AWS": self._ALICE},
                    "Action": "kms:Decrypt",
                    "Resource": other_key,
                    "Condition": {"StringEquals": {"aws:SourceVpc": "vpc-xxx"}},
                }
            ],
        }
        state, _ = self._eval(policy)
        assert state == "fail"

    def test_relevant_conditional_allow_still_unknown(self) -> None:
        """The narrow fix must NOT regress the legitimate case: a
        conditional Allow that actually targets our (principal,
        action, resource) tuple must still produce UNKNOWN."""
        policy = {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Effect": "Allow",
                    "Principal": {"AWS": self._ALICE},
                    "Action": "kms:Decrypt",
                    "Resource": self._KEY_ARN,
                    "Condition": {"StringEquals": {"aws:SourceVpc": "vpc-xxx"}},
                }
            ],
        }
        state, reason = self._eval(policy)
        assert state == "unknown"
        assert "condition" in reason.lower()

    def test_unrelated_not_principal_does_not_mask_fail(self) -> None:
        """NotPrincipal on a statement for a different action must
        not contaminate our decrypt evaluation."""
        policy = {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Effect": "Allow",
                    "NotPrincipal": {"AWS": "arn:aws:iam::999999\u003999999:root"},
                    "Action": "kms:Encrypt",  # irrelevant action
                    "Resource": "*",
                }
            ],
        }
        state, _ = self._eval(policy)
        assert state == "fail"

    def test_multiple_unrelated_conditionals_with_one_clean_allow(self) -> None:
        """Mixed policy: several unrelated conditional Allows plus
        one clean unconditional Allow for our target → PASS. This
        is the real-world shape of many production KMS policies."""
        policy = {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Effect": "Allow",
                    "Principal": {"AWS": "*"},
                    "Action": "kms:Encrypt",
                    "Resource": "*",
                    "Condition": {"StringEquals": {"aws:SourceVpc": "vpc-1"}},
                },
                {
                    "Effect": "Allow",
                    "Principal": {"AWS": f"arn:aws:iam::{self._ACCOUNT}:user/Bob"},
                    "Action": "kms:Decrypt",
                    "Resource": "*",
                    "Condition": {"StringEquals": {"aws:SourceVpc": "vpc-2"}},
                },
                {
                    # The clean, matching Allow.
                    "Effect": "Allow",
                    "Principal": {"AWS": self._ALICE},
                    "Action": "kms:Decrypt",
                    "Resource": self._KEY_ARN,
                },
            ],
        }
        state, _ = self._eval(policy)
        assert state == "pass"


# ---------------------------------------------------------------------------
# BUG-009b: the Deny pre-pass must apply relevance filters before
# flagging ambiguity. Real-world KMS policies routinely have Deny
# statements for unrelated operations (encrypt-only restrictions,
# rotation restrictions, region locks) that should not contaminate
# decrypt evaluation.
# ---------------------------------------------------------------------------


class TestKmsEvaluatorBug009bDenyRelevance:
    """BUG-009b regression suite: Deny statements must only affect
    evaluation when they're relevant to our (principal, kms:Decrypt,
    key_arn) target."""

    _ACCOUNT = "111111\u003111111"
    _ALICE = f"arn:aws:iam::{_ACCOUNT}:user/Alice"
    _KEY_ARN = f"arn:aws:kms:us-east-1:{_ACCOUNT}:key/target-key"

    def _eval(self, policy: dict) -> tuple[str, str]:
        from iamscope.reasoner.secrets_blast_radius import (
            _kms_policy_allows_decrypt,
        )

        state, reason = _kms_policy_allows_decrypt(
            policy_json=json.dumps(policy),
            principal_arn=self._ALICE,
            principal_account_id=self._ACCOUNT,
            key_arn=self._KEY_ARN,
        )
        return state.value, reason

    def test_irrelevant_deny_action_does_not_mask_pass(self) -> None:
        """Deny for kms:Encrypt (irrelevant to decrypt) must not
        flip a clean Allow to UNKNOWN. Pre-fix this returned
        UNKNOWN; post-fix it returns PASS."""
        policy = {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Effect": "Allow",
                    "Principal": {"AWS": self._ALICE},
                    "Action": "kms:Decrypt",
                    "Resource": "*",
                },
                {
                    "Effect": "Deny",
                    "Principal": "*",
                    "Action": "kms:Encrypt",
                    "Resource": "*",
                },
            ],
        }
        state, _ = self._eval(policy)
        assert state == "pass"

    def test_irrelevant_deny_principal_does_not_mask_pass(self) -> None:
        """Deny targeting a different principal must not flip a
        clean Allow for Alice to UNKNOWN."""
        policy = {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Effect": "Allow",
                    "Principal": {"AWS": self._ALICE},
                    "Action": "kms:Decrypt",
                    "Resource": "*",
                },
                {
                    "Effect": "Deny",
                    "Principal": {"AWS": f"arn:aws:iam::{self._ACCOUNT}:user/Bob"},
                    "Action": "kms:Decrypt",
                    "Resource": "*",
                },
            ],
        }
        state, _ = self._eval(policy)
        assert state == "pass"

    def test_irrelevant_deny_resource_does_not_mask_pass(self) -> None:
        """Deny targeting a different key must not flip a clean
        Allow for our key to UNKNOWN."""
        other_key = f"arn:aws:kms:us-east-1:{self._ACCOUNT}:key/other-key"
        policy = {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Effect": "Allow",
                    "Principal": {"AWS": self._ALICE},
                    "Action": "kms:Decrypt",
                    "Resource": "*",
                },
                {
                    "Effect": "Deny",
                    "Principal": "*",
                    "Action": "kms:Decrypt",
                    "Resource": other_key,
                },
            ],
        }
        state, _ = self._eval(policy)
        assert state == "pass"

    def test_relevant_unconditional_deny_fails(self) -> None:
        """A relevant Deny with no Condition must produce FAIL.
        This is a NEW correct behavior post-BUG-009b — previously
        any Deny returned UNKNOWN, flipping check 6 → INCONCLUSIVE.
        Post-fix this correctly produces FAIL, which verdict Rule
        2.5 routes to PRECONDITION_ONLY."""
        policy = {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Effect": "Allow",
                    "Principal": {"AWS": self._ALICE},
                    "Action": "kms:Decrypt",
                    "Resource": "*",
                },
                {
                    "Effect": "Deny",
                    "Principal": "*",
                    "Action": "kms:Decrypt",
                    "Resource": self._KEY_ARN,
                },
            ],
        }
        state, reason = self._eval(policy)
        assert state == "fail"
        assert "deny" in reason.lower()

    def test_relevant_deny_with_not_action_unknown(self) -> None:
        """A Deny with NotAction is a reasoning minefield — the
        statement semantically says 'deny everything except these
        actions', which trivially covers kms:Decrypt unless
        kms:Decrypt is on the NotAction list. Conservative UNKNOWN."""
        policy = {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Effect": "Allow",
                    "Principal": {"AWS": self._ALICE},
                    "Action": "kms:*",
                    "Resource": "*",
                },
                {
                    "Effect": "Deny",
                    "Principal": "*",
                    "NotAction": ["kms:Encrypt"],
                    "Resource": "*",
                },
            ],
        }
        state, reason = self._eval(policy)
        assert state == "unknown"
        assert "notaction" in reason.lower() or "deny" in reason.lower()

    def test_relevant_deny_with_not_principal_unknown(self) -> None:
        """A Deny with NotPrincipal → conservative UNKNOWN."""
        policy = {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Effect": "Allow",
                    "Principal": {"AWS": self._ALICE},
                    "Action": "kms:*",
                    "Resource": "*",
                },
                {
                    "Effect": "Deny",
                    "NotPrincipal": {"AWS": f"arn:aws:iam::{self._ACCOUNT}:user/Bob"},
                    "Action": "kms:Decrypt",
                    "Resource": "*",
                },
            ],
        }
        state, _ = self._eval(policy)
        assert state == "unknown"

    def test_multiple_denys_some_relevant(self) -> None:
        """Mixed policy: several irrelevant Denys (rotation, region,
        encrypt restrictions) and one unconditional Allow for our
        target. Real-world KMS policy shape. Must produce PASS."""
        policy = {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Effect": "Deny",
                    "Principal": "*",
                    "Action": "kms:ScheduleKeyDeletion",
                    "Resource": "*",
                },
                {
                    "Effect": "Deny",
                    "Principal": "*",
                    "Action": "kms:DisableKey",
                    "Resource": "*",
                },
                {
                    "Effect": "Deny",
                    "Principal": "*",
                    "Action": "kms:Encrypt",
                    "Resource": "*",
                    "Condition": {"StringNotEquals": {"aws:RequestedRegion": "us-east-1"}},
                },
                {
                    "Effect": "Allow",
                    "Principal": {"AWS": self._ALICE},
                    "Action": "kms:Decrypt",
                    "Resource": "*",
                },
            ],
        }
        state, _ = self._eval(policy)
        assert state == "pass"

    def test_deny_with_wildcard_action_still_catches_decrypt(self) -> None:
        """Regression guard: a wildcard Deny with `kms:*` DOES
        cover kms:Decrypt and must be caught by the relevance
        filter. This is the 'Deny is relevant' path."""
        policy = {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Effect": "Allow",
                    "Principal": {"AWS": self._ALICE},
                    "Action": "kms:Decrypt",
                    "Resource": "*",
                },
                {
                    "Effect": "Deny",
                    "Principal": {"AWS": self._ALICE},
                    "Action": "kms:*",
                    "Resource": "*",
                },
            ],
        }
        state, _ = self._eval(policy)
        assert state == "fail"


# ---------------------------------------------------------------------------
# BUG-023: dangling-reference secret targets must demote findings to
# INCONCLUSIVE rather than producing over-confident VALIDATED verdicts.
# ---------------------------------------------------------------------------


class TestBug023DanglingSecretDemotion:
    """A synthetic secret node with is_dangling_reference=True must
    route check 6 to UNKNOWN so the finding comes out INCONCLUSIVE."""

    def _make_dangling_rds_secret(self) -> Node:
        """Build a secret node in the shape that
        `_materialize_dangling_endpoints` in pipeline.py would produce
        for an rds! secret referenced by IAM policy but not returned
        by ListSecrets."""
        return Node(
            provider=PROVIDER_AWS,
            node_type=NODE_TYPE_SECRETS_MANAGER_SECRET,
            provider_id=(f"arn:aws:secretsmanager:us-east-1:{_ACCOUNT}:secret:rds!cluster-abc123"),
            properties={
                "account_id": _ACCOUNT,
                "is_synthetic": True,
                "is_dangling_reference": True,
                "collection_status": "not_collected",
                "dangling_reason": ("referenced by IAM policy but not returned by collection — may be rds! secret"),
            },
        )

    def test_dangling_rds_secret_finding_is_inconclusive(self) -> None:
        """End-to-end: the reasoner runs on a graph containing a
        synthetic dangling rds! secret and a GetSecretValue edge
        targeting it. The finding must come out INCONCLUSIVE, not
        VALIDATED, because the target wasn't actually collected."""
        alice = _user(_ALICE_ARN)
        secret = self._make_dangling_rds_secret()
        edge = _get_secret_edge(src=alice, dst_arn=secret.provider_id)
        facts = _make_facts(nodes=(alice, secret), edges=(edge,))

        findings = SecretsBlastRadiusReasoner().run(facts)
        assert len(findings) == 1
        assert findings[0].verdict.value == "inconclusive"

    def test_dangling_check_6_reason_mentions_dangling(self) -> None:
        """The check 6 reason string must explain that the target
        wasn't collected so the operator reading the finding knows
        what to investigate next."""
        alice = _user(_ALICE_ARN)
        secret = self._make_dangling_rds_secret()
        edge = _get_secret_edge(src=alice, dst_arn=secret.provider_id)
        facts = _make_facts(nodes=(alice, secret), edges=(edge,))
        findings = SecretsBlastRadiusReasoner().run(facts)

        check_6 = next(
            c for c in findings[0].required_checks if c.name == "kms_key_policy_allows_decrypt_for_principal"
        )
        assert check_6.state.value == "unknown"
        reason = check_6.reason.lower()
        assert "dangling" in reason or "not returned by collection" in reason
        # Must also mention the rds! context or the uncollected
        # target framing so the operator knows why.
        assert "rds" in reason or "uncollected" in reason or "not returned" in reason

    def test_real_secret_still_validated(self) -> None:
        """Regression guard: the BUG-023 fix must not affect real
        (non-dangling) secrets — they should continue to produce
        VALIDATED verdicts when all checks pass."""
        findings = SecretsBlastRadiusReasoner().run(_build_alice_reads_secret())
        assert len(findings) == 1
        assert findings[0].verdict.value == "validated"
