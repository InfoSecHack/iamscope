"""Tests for the s3_bucket_takeover reasoner.

Covers:
- Preconditions: empty, no buckets, no principals, both present
- Validated: user → bucket, role → bucket (both source types)
- Wildcard resource inconclusive, hyperedge iterates all buckets
- SCP complete blocks, SCP partial inconclusive
- Permission boundary blocks
- Service principal filtered (no finding)
- Root filtered (no finding)
- Multiple (principal, bucket) pairs
- Determinism
"""

from __future__ import annotations

from iamscope.constants import (
    CONSTRAINT_TYPE_PERMISSION_BOUNDARY,
    CONSTRAINT_TYPE_SCP,
    NODE_TYPE_HYPEREDGE,
    NODE_TYPE_IAM_ROLE,
    NODE_TYPE_IAM_USER,
    NODE_TYPE_S3_BUCKET,
    PROVIDER_AWS,
    REGION_GLOBAL,
)
from iamscope.models import Constraint, Edge, EdgeConstraint, Node
from iamscope.reasoner import FactGraph, S3BucketTakeoverReasoner

_ACCOUNT = "111111\u003111111"
_ALICE_ARN = f"arn:aws:iam::{_ACCOUNT}:user/Alice"
_BOB_ARN = f"arn:aws:iam::{_ACCOUNT}:user/Bob"
_ROLE_ARN = f"arn:aws:iam::{_ACCOUNT}:role/DeployerRole"
_ROOT_ARN = f"arn:aws:iam::{_ACCOUNT}:root"
_SERVICE_ARN = "lambda.amazonaws.com"
_BUCKET_A = "arn:aws:s3:::corp-secrets"
_BUCKET_B = "arn:aws:s3:::public-assets"
_HYPEREDGE_ARN = f"__hyperedge__:wildcard_permission:{_ACCOUNT}"


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


def _bucket(arn: str) -> Node:
    return Node(
        provider=PROVIDER_AWS,
        node_type=NODE_TYPE_S3_BUCKET,
        provider_id=arn,
        region=REGION_GLOBAL,
        properties={"account_id": _ACCOUNT, "bucket_name": arn.split(":::")[-1]},
    )


def _pbp_edge(
    *,
    src: Node,
    bucket_arn: str,
    digest: str = "1" * 64,
    is_wildcard_resource: bool = False,
    dst_is_hyperedge: bool = False,
) -> Edge:
    """Permission edge: principal → bucket for s3:PutBucketPolicy."""
    if dst_is_hyperedge:
        dst_node = Node(
            provider=PROVIDER_AWS,
            node_type=NODE_TYPE_HYPEREDGE,
            provider_id=_HYPEREDGE_ARN,
            properties={},
        )
    else:
        dst_node = Node(
            provider=PROVIDER_AWS,
            node_type=NODE_TYPE_S3_BUCKET,
            provider_id=bucket_arn,
            region=REGION_GLOBAL,
            properties={"account_id": _ACCOUNT},
        )
    return Edge(
        edge_type="s3:PutBucketPolicy_permission",
        src=src.to_ref(),
        dst=dst_node.to_ref(),
        region=REGION_GLOBAL,
        features={
            "allow_controls": [
                {
                    "control_type": "PERMISSION",
                    "policy_arn": f"arn:aws:iam::{_ACCOUNT}:policy/S3Mgmt",
                    "statement_index": 0,
                    "digest": digest,
                    "summary": "s3:PutBucketPolicy grant",
                }
            ],
            "effect": "Allow",
            "has_conditions": False,
            "is_wildcard_resource": is_wildcard_resource,
            "layer": "permission",
            "raw_conditions": {},
            "resource_pattern": ("*" if is_wildcard_resource else bucket_arn),
            "statement_index": 0,
        },
    )


def _scp(
    *,
    statement_id: str = "DenyPutBucketPolicy",
    parse_status: str = "complete",
) -> Constraint:
    return Constraint(
        provider=PROVIDER_AWS,
        constraint_type=CONSTRAINT_TYPE_SCP,
        scope_type="OU",
        scope_id="ou-prod-12345",
        policy_id="p-deny-putbucketpolicy",
        statement_id=statement_id,
        region=REGION_GLOBAL,
        properties={
            "deny_actions": ["s3:PutBucketPolicy"],
            "deny_not_actions": [],
            "exception_principal_patterns": [],
            "parse_status": parse_status,
            "policy_name": "DenyPutBucketPolicy",
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
        statement_id="BoundaryNoS3Mgmt",
        region=REGION_GLOBAL,
        properties={
            "allowed_actions": ["ec2:*", "dynamodb:*"],
            "parse_status": "complete",
            "policy_name": "AliceBoundary",
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
        binding_reason=f"constraint {constraint_id} affects PutBucketPolicy",
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


def _build_alice_to_bucket_a() -> FactGraph:
    alice = _user(_ALICE_ARN)
    bucket = _bucket(_BUCKET_A)
    edge = _pbp_edge(src=alice, bucket_arn=_BUCKET_A)
    return _make_facts(nodes=(alice, bucket), edges=(edge,))


# ---------------------------------------------------------------------------
# Preconditions
# ---------------------------------------------------------------------------


class TestPreconditions:
    def test_empty_graph_skipped(self) -> None:
        facts = FactGraph(
            nodes=(),
            edges=(),
            constraints=(),
            edge_constraints=(),
            scenario_hash="x" * 64,
            edge_budget_exhausted=False,
        )
        ok, reason = S3BucketTakeoverReasoner().preconditions_met(facts)
        assert not ok
        assert "S3Bucket" in reason

    def test_principals_only_skipped(self) -> None:
        facts = _make_facts(nodes=(_user(_ALICE_ARN),), edges=())
        ok, reason = S3BucketTakeoverReasoner().preconditions_met(facts)
        assert not ok
        assert "S3Bucket" in reason

    def test_buckets_only_skipped(self) -> None:
        facts = _make_facts(nodes=(_bucket(_BUCKET_A),), edges=())
        ok, reason = S3BucketTakeoverReasoner().preconditions_met(facts)
        assert not ok
        assert "IAMUser" in reason or "IAMRole" in reason

    def test_both_present_runs(self) -> None:
        facts = _make_facts(
            nodes=(_user(_ALICE_ARN), _bucket(_BUCKET_A)),
            edges=(),
        )
        ok, _ = S3BucketTakeoverReasoner().preconditions_met(facts)
        assert ok


# ---------------------------------------------------------------------------
# Validated findings — user + role sources
# ---------------------------------------------------------------------------


class TestValidatedFindings:
    def test_user_to_bucket_validated_critical(self) -> None:
        findings = S3BucketTakeoverReasoner().run(_build_alice_to_bucket_a())
        assert len(findings) == 1
        assert findings[0].verdict.value == "validated"
        assert findings[0].severity == "critical"
        assert findings[0].source.provider_id == _ALICE_ARN
        assert findings[0].target.provider_id == _BUCKET_A

    def test_role_to_bucket_validated_critical(self) -> None:
        """Roles are valid sources (v1 includes users AND roles)."""
        role = _role(_ROLE_ARN)
        bucket = _bucket(_BUCKET_A)
        edge = _pbp_edge(src=role, bucket_arn=_BUCKET_A)
        facts = _make_facts(nodes=(role, bucket), edges=(edge,))
        findings = S3BucketTakeoverReasoner().run(facts)
        assert len(findings) == 1
        assert findings[0].source.provider_id == _ROLE_ARN
        assert findings[0].verdict.value == "validated"
        assert findings[0].severity == "critical"

    def test_all_five_checks_present(self) -> None:
        f = S3BucketTakeoverReasoner().run(_build_alice_to_bucket_a())[0]
        check_names = [c.name for c in f.required_checks]
        assert len(check_names) == 5
        assert "principal_has_put_bucket_policy_permission" in check_names
        assert "witness_edge_is_clean" in check_names
        assert "no_scp_blocks_put_bucket_policy" in check_names
        assert "no_boundary_blocks_put_bucket_policy" in check_names
        assert "principal_is_actionable" in check_names

    def test_title_mentions_takeover(self) -> None:
        f = S3BucketTakeoverReasoner().run(_build_alice_to_bucket_a())[0]
        assert "takeover" in f.title.lower()
        assert "s3" in f.title.lower()

    def test_trace_steps_contiguous(self) -> None:
        """Trace step numbering must be 1,2,3,4,5 (invariant)."""
        f = S3BucketTakeoverReasoner().run(_build_alice_to_bucket_a())[0]
        steps = [t.step for t in f.evidence.reasoning_trace]
        assert steps == [1, 2, 3, 4, 5]


# ---------------------------------------------------------------------------
# Wildcard / hyperedge inconclusive
# ---------------------------------------------------------------------------


class TestWildcardInconclusive:
    def test_wildcard_resource_inconclusive_high(self) -> None:
        alice = _user(_ALICE_ARN)
        bucket = _bucket(_BUCKET_A)
        edge = _pbp_edge(
            src=alice,
            bucket_arn=_BUCKET_A,
            is_wildcard_resource=True,
        )
        facts = _make_facts(nodes=(alice, bucket), edges=(edge,))
        findings = S3BucketTakeoverReasoner().run(facts)
        assert len(findings) == 1
        assert findings[0].verdict.value == "inconclusive"
        assert findings[0].severity == "high"

    def test_hyperedge_iterates_all_buckets(self) -> None:
        alice = _user(_ALICE_ARN)
        bucket_a = _bucket(_BUCKET_A)
        bucket_b = _bucket(_BUCKET_B)
        edge = _pbp_edge(
            src=alice,
            bucket_arn="ignored",
            dst_is_hyperedge=True,
        )
        facts = _make_facts(
            nodes=(alice, bucket_a, bucket_b),
            edges=(edge,),
        )
        findings = S3BucketTakeoverReasoner().run(facts)
        assert len(findings) == 2
        targets = sorted(f.target.provider_id for f in findings)
        assert targets == sorted([_BUCKET_A, _BUCKET_B])
        for f in findings:
            assert f.verdict.value == "inconclusive"
            assert f.severity == "high"


# ---------------------------------------------------------------------------
# Blockers
# ---------------------------------------------------------------------------


class TestSCPBlockers:
    def test_scp_complete_blocks(self) -> None:
        facts = _build_alice_to_bucket_a()
        edge = next(e for e in facts.edges if e.edge_type == "s3:PutBucketPolicy_permission")
        scp = _scp()
        binding = _binding(
            edge_id=edge.edge_id,
            constraint_id=scp.constraint_id,
        )
        facts2 = FactGraph(
            nodes=facts.nodes,
            edges=facts.edges,
            constraints=(scp,),
            edge_constraints=(binding,),
            scenario_hash=facts.scenario_hash,
            edge_budget_exhausted=False,
        )
        findings = S3BucketTakeoverReasoner().run(facts2)
        assert len(findings) == 1
        assert findings[0].verdict.value == "blocked"
        assert findings[0].severity == "info"

    def test_scp_partial_inconclusive(self) -> None:
        facts = _build_alice_to_bucket_a()
        edge = next(e for e in facts.edges if e.edge_type == "s3:PutBucketPolicy_permission")
        scp = _scp(parse_status="partial")
        binding = _binding(
            edge_id=edge.edge_id,
            constraint_id=scp.constraint_id,
            governance_confidence="partial",
        )
        facts2 = FactGraph(
            nodes=facts.nodes,
            edges=facts.edges,
            constraints=(scp,),
            edge_constraints=(binding,),
            scenario_hash=facts.scenario_hash,
            edge_budget_exhausted=False,
        )
        findings = S3BucketTakeoverReasoner().run(facts2)
        assert len(findings) == 1
        assert findings[0].verdict.value == "inconclusive"
        assert findings[0].severity == "high"


class TestBoundaryBlockers:
    def test_boundary_blocks(self) -> None:
        facts = _build_alice_to_bucket_a()
        edge = next(e for e in facts.edges if e.edge_type == "s3:PutBucketPolicy_permission")
        boundary = _boundary()
        binding = _binding(
            edge_id=edge.edge_id,
            constraint_id=boundary.constraint_id,
        )
        facts2 = FactGraph(
            nodes=facts.nodes,
            edges=facts.edges,
            constraints=(boundary,),
            edge_constraints=(binding,),
            scenario_hash=facts.scenario_hash,
            edge_budget_exhausted=False,
        )
        findings = S3BucketTakeoverReasoner().run(facts2)
        assert len(findings) == 1
        assert findings[0].verdict.value == "blocked"


# ---------------------------------------------------------------------------
# Actionability filter (check 5)
# ---------------------------------------------------------------------------


class TestActionabilityFilter:
    def test_root_filtered(self) -> None:
        """Root accounts are not actionable (infrastructure, not attacker)."""
        root = Node(
            provider=PROVIDER_AWS,
            node_type=NODE_TYPE_IAM_USER,
            provider_id=_ROOT_ARN,
            properties={"account_id": _ACCOUNT},
        )
        bucket = _bucket(_BUCKET_A)
        edge = _pbp_edge(src=root, bucket_arn=_BUCKET_A)
        facts = _make_facts(nodes=(root, bucket), edges=(edge,))
        findings = S3BucketTakeoverReasoner().run(facts)
        assert len(findings) == 0

    def test_service_principal_filtered(self) -> None:
        """Service principals (*.amazonaws.com) are infrastructure."""
        service = Node(
            provider=PROVIDER_AWS,
            node_type=NODE_TYPE_IAM_ROLE,
            provider_id=_SERVICE_ARN,
            properties={"account_id": _ACCOUNT},
        )
        bucket = _bucket(_BUCKET_A)
        edge = _pbp_edge(src=service, bucket_arn=_BUCKET_A)
        facts = _make_facts(nodes=(service, bucket), edges=(edge,))
        findings = S3BucketTakeoverReasoner().run(facts)
        assert len(findings) == 0


# ---------------------------------------------------------------------------
# Multiple pairs
# ---------------------------------------------------------------------------


class TestMultiplePairs:
    def test_two_users_one_bucket(self) -> None:
        alice = _user(_ALICE_ARN)
        bob = _user(_BOB_ARN)
        bucket = _bucket(_BUCKET_A)
        facts = _make_facts(
            nodes=(alice, bob, bucket),
            edges=(
                _pbp_edge(src=alice, bucket_arn=_BUCKET_A, digest="1" * 64),
                _pbp_edge(src=bob, bucket_arn=_BUCKET_A, digest="2" * 64),
            ),
        )
        findings = S3BucketTakeoverReasoner().run(facts)
        assert len(findings) == 2

    def test_one_user_two_buckets(self) -> None:
        alice = _user(_ALICE_ARN)
        bucket_a = _bucket(_BUCKET_A)
        bucket_b = _bucket(_BUCKET_B)
        facts = _make_facts(
            nodes=(alice, bucket_a, bucket_b),
            edges=(
                _pbp_edge(src=alice, bucket_arn=_BUCKET_A, digest="1" * 64),
                _pbp_edge(src=alice, bucket_arn=_BUCKET_B, digest="2" * 64),
            ),
        )
        findings = S3BucketTakeoverReasoner().run(facts)
        assert len(findings) == 2


# ---------------------------------------------------------------------------
# Determinism
# ---------------------------------------------------------------------------


class TestDeterminism:
    def test_double_run_same_findings(self) -> None:
        f1 = S3BucketTakeoverReasoner().run(_build_alice_to_bucket_a())
        f2 = S3BucketTakeoverReasoner().run(_build_alice_to_bucket_a())
        assert len(f1) == len(f2) == 1
        assert f1[0].finding_id == f2[0].finding_id
        assert f1[0].evidence.bundle_digest == f2[0].evidence.bundle_digest
