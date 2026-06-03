"""Pinning tests for cross-reasoner consistency post-processor.

Tests the orchestration-level fix for AR-1 (admin_reachability vs
assume_role_chain contradictory verdicts on the same source→target).

Scope: unit tests of apply_cross_reasoner_demotions() operating on
hand-constructed Finding objects. Real-reasoner end-to-end flows are
covered by the existing admin_reachability and assume_role_chain
tests plus the full integration suite.

Path-matching contract under test: a VALIDATED admin_reachability
finding is demoted to INCONCLUSIVE iff there exists a BLOCKED
assume_role_chain finding with the same (source.provider_id,
target.provider_id) AND at least one overlapping edge_id between the
two findings' evidence.edge_refs. Endpoint-pair match alone is
insufficient — admin_reachability may reach the same target via a
different path that the blocked assume_role_chain finding does not
represent.
"""

from __future__ import annotations

from iamscope.constants import (
    NODE_TYPE_IAM_ROLE,
    NODE_TYPE_IAM_USER,
    PROVIDER_AWS,
)
from iamscope.models import NodeRef
from iamscope.reasoner.cross_reasoner_consistency import (
    apply_cross_reasoner_demotions,
)
from iamscope.reasoner.evidence import EvidenceBundle, TraceEntry
from iamscope.reasoner.verdict import (
    Blocker,
    Check,
    CheckState,
    Finding,
    Verdict,
)

_ACCOUNT = "111111\u003111111"
_ALICE = f"arn:aws:iam::{_ACCOUNT}:user/Alice"
_ADMIN = f"arn:aws:iam::{_ACCOUNT}:role/Admin"


def _noderef(arn: str, node_type: str) -> NodeRef:
    return NodeRef(provider=PROVIDER_AWS, node_type=node_type, provider_id=arn)


def _bundle(edge_refs: tuple[str, ...]) -> EvidenceBundle:
    return EvidenceBundle(
        statement_digests=(),
        statement_sources={},
        edge_refs=edge_refs,
        constraint_refs=(),
        edge_constraint_refs=(),
        node_refs=(),
        condition_context_assumed=(),
        reasoning_trace=(
            TraceEntry(
                step=1,
                action="stub",
                inputs=(),
                result="PASS",
                reason="test fixture",
            ),
        ),
    )


def _admin_reach_validated(source_arn: str, target_arn: str, edge_refs: tuple[str, ...]) -> Finding:
    return Finding(
        pattern_id="admin_reachability",
        pattern_version="1",
        source=_noderef(source_arn, NODE_TYPE_IAM_USER),
        target=_noderef(target_arn, NODE_TYPE_IAM_ROLE),
        verdict=Verdict.VALIDATED,
        severity="high",
        title="principal reaches admin-equivalent role",
        required_checks=(
            Check(
                name="reaches_at_least_one_admin",
                description="BFS reached admin role",
                state=CheckState.PASS,
                evidence_refs=edge_refs,
                reason="admin reached via path",
            ),
        ),
        blockers_observed=(),
        assumptions=(),
        evidence=_bundle(edge_refs),
        scenario_hash="a" * 64,
    )


def _arc_blocked(
    source_arn: str,
    target_arn: str,
    edge_refs: tuple[str, ...],
    blocked_edge_id: str,
) -> Finding:
    return Finding(
        pattern_id="assume_role_chain",
        pattern_version="1",
        source=_noderef(source_arn, NODE_TYPE_IAM_USER),
        target=_noderef(target_arn, NODE_TYPE_IAM_ROLE),
        verdict=Verdict.BLOCKED,
        severity="info",
        title="chain blocked by SCP",
        required_checks=(
            Check(
                name="chain_is_open",
                description="every hop admitted",
                state=CheckState.FAIL,
                evidence_refs=edge_refs,
                reason="SCP denies sts:AssumeRole on hop",
            ),
        ),
        blockers_observed=(
            Blocker(
                kind="scp",
                constraint_id="c-deny-assumerole",
                edge_id=blocked_edge_id,
                reason="SCP denies sts:AssumeRole",
            ),
        ),
        assumptions=(),
        evidence=_bundle(edge_refs),
        scenario_hash="a" * 64,
    )


def _arc_validated(source_arn: str, target_arn: str, edge_refs: tuple[str, ...]) -> Finding:
    return Finding(
        pattern_id="assume_role_chain",
        pattern_version="1",
        source=_noderef(source_arn, NODE_TYPE_IAM_USER),
        target=_noderef(target_arn, NODE_TYPE_IAM_ROLE),
        verdict=Verdict.VALIDATED,
        severity="high",
        title="chain reaches target",
        required_checks=(
            Check(
                name="chain_is_open",
                description="every hop admitted",
                state=CheckState.PASS,
                evidence_refs=edge_refs,
                reason="chain open",
            ),
        ),
        blockers_observed=(),
        assumptions=(),
        evidence=_bundle(edge_refs),
        scenario_hash="a" * 64,
    )


def test_single_blocked_path_demoted() -> None:
    """Alice → DevOps → Admin, SCP blocks hop 2. Both reasoners traverse
    the same path; assume_role_chain emits BLOCKED; admin_reachability
    emits VALIDATED (it does not consult SCPs). Post-processor must
    demote the admin_reachability finding to INCONCLUSIVE with a
    cross_reasoner_blocked blocker, and leave the assume_role_chain
    finding unchanged."""
    ar_edges = (
        "edge-perm-alice-devops",
        "edge-trust-alice-devops",
        "edge-perm-devops-admin",
        "edge-trust-devops-admin",
        "edge-admin-grant",
    )
    arc_edges = ar_edges[:4]  # assume_role_chain does not include admin-grant

    ar = _admin_reach_validated(_ALICE, _ADMIN, ar_edges)
    arc = _arc_blocked(
        _ALICE,
        _ADMIN,
        arc_edges,
        blocked_edge_id="edge-perm-devops-admin",
    )
    out = apply_cross_reasoner_demotions([ar, arc])

    ar_out = next(f for f in out if f.pattern_id == "admin_reachability")
    assert ar_out.verdict is Verdict.INCONCLUSIVE
    assert len(ar_out.blockers_observed) == 1
    blocker = ar_out.blockers_observed[0]
    assert blocker.kind == "cross_reasoner_blocked"
    assert "assume_role_chain" in blocker.reason

    arc_out = next(f for f in out if f.pattern_id == "assume_role_chain")
    assert arc_out.verdict is Verdict.BLOCKED
    assert arc_out.finding_id == arc.finding_id


def test_mixed_paths_alternate_valid_preserved() -> None:
    """Critical correctness test. Alice reaches Admin via two paths:
    - Path A (DevOps): assume_role_chain picks this, finds it BLOCKED
    - Path B (Lambda): admin_reachability picks this, finds it VALIDATED
    The endpoints match on both findings, but the edge_refs do NOT
    overlap. Endpoint-pair matching alone would incorrectly demote
    admin_reachability. Edge-refs overlap matching preserves the
    validated finding — because the alternate path is genuinely open."""
    ar_path_edges = (
        "edge-perm-alice-lambda",
        "edge-trust-alice-lambda",
        "edge-perm-lambda-admin",
        "edge-trust-lambda-admin",
        "edge-admin-grant",
    )
    arc_path_edges = (
        "edge-perm-alice-devops",
        "edge-trust-alice-devops",
        "edge-perm-devops-admin",
        "edge-trust-devops-admin",
    )
    # Sanity: paths are disjoint.
    assert not (set(ar_path_edges) & set(arc_path_edges))

    ar = _admin_reach_validated(_ALICE, _ADMIN, ar_path_edges)
    arc = _arc_blocked(
        _ALICE,
        _ADMIN,
        arc_path_edges,
        blocked_edge_id="edge-perm-devops-admin",
    )
    out = apply_cross_reasoner_demotions([ar, arc])

    ar_out = next(f for f in out if f.pattern_id == "admin_reachability")
    assert ar_out.verdict is Verdict.VALIDATED
    assert ar_out.blockers_observed == ()
    assert ar_out.finding_id == ar.finding_id


def test_no_blocker_regression() -> None:
    """Baseline: standard two-hop chain, no SCP, assume_role_chain is
    VALIDATED. admin_reachability's VALIDATED verdict must pass through
    unchanged — no demotion occurs without a BLOCKED ARC finding."""
    edge_refs = (
        "edge-perm-alice-devops",
        "edge-trust-alice-devops",
        "edge-perm-devops-admin",
        "edge-trust-devops-admin",
        "edge-admin-grant",
    )
    ar = _admin_reach_validated(_ALICE, _ADMIN, edge_refs)
    arc = _arc_validated(_ALICE, _ADMIN, edge_refs[:4])
    out = apply_cross_reasoner_demotions([ar, arc])

    ar_out = next(f for f in out if f.pattern_id == "admin_reachability")
    assert ar_out.verdict is Verdict.VALIDATED
    assert ar_out.blockers_observed == ()
    assert ar_out.finding_id == ar.finding_id
