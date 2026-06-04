"""S10 tests: cross_account_trust reasoner — 9 fixtures + determinism.

Per plan §4A.5:
- Fixtures A–F cover the canonical 6-check verdict mapping cases
- Fixture G covers parse_status=unsupported / needs_review
- Fixture H covers multi-statement trust dedup (no false duplicates)
- Fixture Z covers same-org cross-account severity downgrade
- TestDeterminism asserts double-run byte-identical Findings

Each fixture is a Python builder that constructs a small fact graph
from code, runs the reasoner, and asserts the verdict + severity +
finding_id structure. Per S10 plan row, byte-level findings.json
fixtures are deferred to S13 (which extends the golden findings test
suite). S10's pinning is at the value level (verdict, severity,
finding_id format, check states, evidence bundle digest format).
"""

from __future__ import annotations

from typing import Any

from iamscope.constants import (
    ACTION_CLASS_STS_ASSUME_ROLE,
    CONSTRAINT_TYPE_PERMISSION_BOUNDARY,
    CONSTRAINT_TYPE_SCP,
    CONSTRAINT_TYPE_TRUST_CONDITION,
    NAKED_BROAD,
    NAKED_CONDITIONED,
    NAKED_CRITICAL,
    NAKED_INTRA_ACCOUNT,
    NAKED_NARROW,
    NODE_TYPE_ACCOUNT_ROOT,
    NODE_TYPE_IAM_ROLE,
    NODE_TYPE_IAM_USER,
    PROBE_KIND_RUNTIME,
    PROBE_STATE_CONFOUNDED_SKIP,
    PROBE_STATE_PROBED_CORRELATED_DENIED,
    PROBE_STATE_PROBED_CORRELATED_DISAGREEMENT,
    PROVIDER_AWS,
    REGION_GLOBAL,
    SEVERITY_CRITICAL,
    SEVERITY_HIGH,
    SEVERITY_INFO,
    SEVERITY_MEDIUM,
    VALIDATED_STATE_DENIED,
)
from iamscope.models import Constraint, Edge, EdgeConstraint, Node
from iamscope.reasoner import (
    CheckState,
    CrossAccountTrustReasoner,
    FactGraph,
    Verdict,
)
from iamscope.truth.probe_overlay import ProbeRecord

NODE_TYPE_OIDC_PROVIDER = "OIDCProvider"

# Canonical test ARNs.
_TARGET_ACCOUNT = "111111\u003111111"
_EXTERNAL_ACCOUNT = "999999\u003999999"
_TARGET_ROLE_ARN = f"arn:aws:iam::{_TARGET_ACCOUNT}:role/ProdAdmin"
_EXTERNAL_ROOT_ARN = f"arn:aws:iam::{_EXTERNAL_ACCOUNT}:root"
_EXTERNAL_ROLE_ARN = f"arn:aws:iam::{_EXTERNAL_ACCOUNT}:role/Specific"
_INTRA_USER_ARN = f"arn:aws:iam::{_TARGET_ACCOUNT}:user/Bob"
_OIDC_PROVIDER_ARN = f"arn:aws:iam::{_TARGET_ACCOUNT}:oidc-provider/token.actions.githubusercontent.com"
_WILDCARD_PRINCIPAL = "arn:aws:iam:::*"


# ---------------------------------------------------------------------------
# Builders
# ---------------------------------------------------------------------------


def _target_role_node() -> Node:
    return Node(
        provider=PROVIDER_AWS,
        node_type=NODE_TYPE_IAM_ROLE,
        provider_id=_TARGET_ROLE_ARN,
        region=REGION_GLOBAL,
        properties={
            "account_id": _TARGET_ACCOUNT,
            "is_synthetic": False,
            "path": "/",
        },
    )


def _account_root_node(
    account_id: str,
    *,
    org_member: bool = False,
) -> Node:
    """Synthetic AccountPrincipalSet node — represents `arn:aws:iam::N:root`."""
    return Node(
        provider=PROVIDER_AWS,
        node_type=NODE_TYPE_ACCOUNT_ROOT,
        provider_id=f"arn:aws:iam::{account_id}:root",
        region=REGION_GLOBAL,
        properties={
            "account_id": account_id,
            "is_synthetic": True,
            "org_member": org_member,
            "principal_count": 50,
        },
    )


def _wildcard_principal_node() -> Node:
    """Synthetic node for `Principal: *` — `arn:aws:iam:::*`.

    Represents the AWS-wide wildcard principal. Always external (no org).
    """
    return Node(
        provider=PROVIDER_AWS,
        node_type=NODE_TYPE_ACCOUNT_ROOT,
        provider_id=_WILDCARD_PRINCIPAL,
        region=REGION_GLOBAL,
        properties={
            "is_synthetic": True,
            "org_member": False,
            "wildcard": True,
        },
    )


def _external_role_node() -> Node:
    return Node(
        provider=PROVIDER_AWS,
        node_type=NODE_TYPE_IAM_ROLE,
        provider_id=_EXTERNAL_ROLE_ARN,
        region=REGION_GLOBAL,
        properties={
            "account_id": _EXTERNAL_ACCOUNT,
            "is_synthetic": True,
            "org_member": False,
        },
    )


def _intra_user_node() -> Node:
    return Node(
        provider=PROVIDER_AWS,
        node_type=NODE_TYPE_IAM_USER,
        provider_id=_INTRA_USER_ARN,
        region=REGION_GLOBAL,
        properties={
            "account_id": _TARGET_ACCOUNT,
            "is_synthetic": False,
            "org_member": True,
        },
    )


def _oidc_provider_node() -> Node:
    return Node(
        provider=PROVIDER_AWS,
        node_type=NODE_TYPE_OIDC_PROVIDER,
        provider_id=_OIDC_PROVIDER_ARN,
        region=REGION_GLOBAL,
        properties={
            "account_id": _TARGET_ACCOUNT,
            "is_synthetic": False,
            "org_member": False,
        },
    )


def _trust_edge(
    *,
    src: Node,
    dst: Node,
    naked_trust: str | None,
    cross_account: bool,
    has_external_id: bool = False,
    has_mfa_condition: bool = False,
    has_org_id_condition: bool = False,
    digest: str = "deadbeef" * 8,
    statement_index: int = 0,
) -> Edge:
    """Build a trust edge with the given features.

    The `digest` becomes a `ControlRef` in `allow_controls`, which the
    reasoner reads for the evidence bundle's statement_digests.
    """
    features: dict[str, Any] = {
        "allow_controls": [
            {
                "control_type": "TRUST",
                "policy_arn": dst.provider_id,
                "statement_index": statement_index,
                "digest": digest,
                "summary": f"trust policy for {dst.provider_id}",
            }
        ],
        "cross_account": cross_account,
        "effect": "Allow",
        "has_external_id": has_external_id,
        "has_mfa_condition": has_mfa_condition,
        "has_org_id_condition": has_org_id_condition,
        "has_source_account_condition": False,
        "has_source_ip_condition": False,
        "has_source_vpc_condition": False,
        "is_wildcard_principal": (src.provider_id == _WILDCARD_PRINCIPAL),
        "layer": "trust",
        "principal_type": "AWS",
        "raw_conditions": {},
        "source_policy": "TrustPolicy",
        "statement_index": statement_index,
        "trust_scope": "account_root",
    }
    if naked_trust is not None:
        features["naked_trust"] = naked_trust
    return Edge(
        edge_type="sts:AssumeRole_trust",
        src=src.to_ref(),
        dst=dst.to_ref(),
        region=REGION_GLOBAL,
        features=features,
    )


def _edge_constraint(
    *,
    edge_id: str,
    constraint_id: str,
    governance_confidence: str,
    likely_blocking: bool,
    binding_reason: str = "test SCP binding",
) -> EdgeConstraint:
    return EdgeConstraint(
        edge_id=edge_id,
        constraint_id=constraint_id,
        governance_confidence=governance_confidence,
        likely_blocking=likely_blocking,
        binding_reason=binding_reason,
    )


def _constraint(
    *,
    constraint_id: str,
    constraint_type: str,
    parse_status: str = "complete",
) -> Constraint:
    return Constraint(
        provider=PROVIDER_AWS,
        constraint_type=constraint_type,
        scope_type="OU",
        scope_id="ou-prod-12345",
        policy_id=constraint_id,
        statement_id=constraint_id,
        region=REGION_GLOBAL,
        properties={
            "deny_actions": ["sts:AssumeRole"],
            "deny_not_actions": [],
            "exception_principal_patterns": [],
            "parse_status": parse_status,
            "policy_name": constraint_id,
            "resource_patterns": ["*"],
        },
    )


def _make_facts(
    *,
    nodes: tuple[Node, ...],
    edges: tuple[Edge, ...],
    constraints: tuple[Constraint, ...] = (),
    edge_constraints: tuple[EdgeConstraint, ...] = (),
    scenario_hash: str = "deadbeef" * 8,
) -> FactGraph:
    return FactGraph(
        nodes=nodes,
        edges=edges,
        constraints=constraints,
        edge_constraints=edge_constraints,
        scenario_hash=scenario_hash,
        edge_budget_exhausted=False,
    )


def _is_sha256_hex(s: str) -> bool:
    return isinstance(s, str) and len(s) == 64 and all(c in "0123456789abcdef" for c in s)


def _probe_record(
    edge_id: str,
    probe_state: str,
    *,
    confounded: bool = False,
    controls: tuple[str, ...] = (),
) -> ProbeRecord:
    return ProbeRecord(
        probe_id=f"probe-{probe_state}",
        edge_id=edge_id,
        action_class=ACTION_CLASS_STS_ASSUME_ROLE,
        probe_kind=PROBE_KIND_RUNTIME,
        probe_state=probe_state,
        probed_at_utc="2026-01-01T00:00:00Z",
        authorization_ref=None,
        confounded=confounded,
        confounded_reason="test confounder" if confounded else "",
        contributing_control_refs=controls,
        simulator_state=None,
        runtime_state=VALIDATED_STATE_DENIED,
        cloudtrail_state=None,
        notes_digest=None,
    )


def _with_probe(facts: FactGraph, probe: ProbeRecord) -> FactGraph:
    return FactGraph(
        nodes=facts.nodes,
        edges=facts.edges,
        constraints=facts.constraints,
        edge_constraints=facts.edge_constraints,
        scenario_hash=facts.scenario_hash,
        edge_budget_exhausted=facts.edge_budget_exhausted,
        probe_records_by_edge={probe.edge_id: (probe,)},
    )


# ---------------------------------------------------------------------------
# Preconditions
# ---------------------------------------------------------------------------


class TestPreconditions:
    """preconditions_met gates execution on classified trust edges."""

    def test_no_trust_edges_skips(self) -> None:
        facts = _make_facts(nodes=(), edges=())
        reasoner = CrossAccountTrustReasoner()
        ran, reason = reasoner.preconditions_met(facts)
        assert ran is False
        assert "no trust edges" in reason

    def test_unclassified_trust_edges_skip(self) -> None:
        """Trust edges without naked_trust feature → skip."""
        target = _target_role_node()
        external = _account_root_node(_EXTERNAL_ACCOUNT)
        edge = _trust_edge(
            src=external,
            dst=target,
            naked_trust=None,  # no classification
            cross_account=True,
        )
        facts = _make_facts(nodes=(target, external), edges=(edge,))
        reasoner = CrossAccountTrustReasoner()
        ran, reason = reasoner.preconditions_met(facts)
        assert ran is False
        assert "naked_trust classification" in reason

    def test_classified_trust_edge_runs(self) -> None:
        target = _target_role_node()
        external = _account_root_node(_EXTERNAL_ACCOUNT)
        edge = _trust_edge(
            src=external,
            dst=target,
            naked_trust=NAKED_BROAD,
            cross_account=True,
        )
        facts = _make_facts(nodes=(target, external), edges=(edge,))
        reasoner = CrossAccountTrustReasoner()
        ran, reason = reasoner.preconditions_met(facts)
        assert ran is True


# ---------------------------------------------------------------------------
# Fixture A: critical_naked_wildcard_principal → validated/critical
# ---------------------------------------------------------------------------


class TestFixtureACriticalNakedWildcardPrincipal:
    """Wildcard principal trust with no conditions → CRITICAL_NAKED → critical."""

    def _build(self) -> tuple[FactGraph, Edge]:
        target = _target_role_node()
        wildcard_src = _wildcard_principal_node()
        edge = _trust_edge(
            src=wildcard_src,
            dst=target,
            naked_trust=NAKED_CRITICAL,
            cross_account=True,
        )
        facts = _make_facts(nodes=(target, wildcard_src), edges=(edge,))
        return facts, edge

    def test_emits_validated_critical(self) -> None:
        facts, edge = self._build()
        findings = CrossAccountTrustReasoner().run(facts)
        assert len(findings) == 1
        f = findings[0]
        assert f.verdict is Verdict.VALIDATED
        assert f.severity == SEVERITY_CRITICAL
        assert f.pattern_id == "cross_account_trust"
        assert f.pattern_version == "1.0.0"

    def test_finding_id_is_sha256_hex(self) -> None:
        facts, _ = self._build()
        f = CrossAccountTrustReasoner().run(facts)[0]
        assert _is_sha256_hex(f.finding_id)

    def test_all_required_checks_pass(self) -> None:
        facts, _ = self._build()
        f = CrossAccountTrustReasoner().run(facts)[0]
        for chk in f.required_checks:
            assert chk.state is CheckState.PASS

    def test_evidence_bundle_has_statement_digest(self) -> None:
        facts, _ = self._build()
        f = CrossAccountTrustReasoner().run(facts)[0]
        assert len(f.evidence.statement_digests) == 1
        assert _is_sha256_hex(f.evidence.bundle_digest)


# ---------------------------------------------------------------------------
# Fixture B: broad_naked_blocked_by_scp → blocked/info
# ---------------------------------------------------------------------------


class TestFixtureBBroadNakedBlockedBySCP:
    """SCP with complete confidence blocks the trust → blocked/info."""

    _SCP_CONSTRAINT_ID = _constraint(
        constraint_id="scp_constraint_xyz",
        constraint_type=CONSTRAINT_TYPE_SCP,
    ).constraint_id

    def _build(self) -> FactGraph:
        target = _target_role_node()
        external = _account_root_node(_EXTERNAL_ACCOUNT)
        edge = _trust_edge(
            src=external,
            dst=target,
            naked_trust=NAKED_BROAD,
            cross_account=True,
        )
        scp = _constraint(
            constraint_id="scp_constraint_xyz",
            constraint_type=CONSTRAINT_TYPE_SCP,
        )
        ec = _edge_constraint(
            edge_id=edge.edge_id,
            constraint_id=scp.constraint_id,
            governance_confidence="complete",
            likely_blocking=True,
            binding_reason="SCP DenyAssumeRole at OU ou-prod",
        )
        return _make_facts(
            nodes=(target, external),
            edges=(edge,),
            constraints=(scp,),
            edge_constraints=(ec,),
        )

    def test_emits_blocked_info(self) -> None:
        findings = CrossAccountTrustReasoner().run(self._build())
        assert len(findings) == 1
        f = findings[0]
        assert f.verdict is Verdict.BLOCKED
        assert f.severity == SEVERITY_INFO

    def test_blocker_attributes_scp(self) -> None:
        f = CrossAccountTrustReasoner().run(self._build())[0]
        assert len(f.blockers_observed) == 1
        b = f.blockers_observed[0]
        assert b.kind == "scp"
        assert b.constraint_id == self._SCP_CONSTRAINT_ID

    def test_constraint_id_in_evidence(self) -> None:
        f = CrossAccountTrustReasoner().run(self._build())[0]
        assert self._SCP_CONSTRAINT_ID in f.evidence.constraint_refs


class TestTrustEdgeBindingTypeFiltering:
    """Only parent constraints typed as SCP can affect the SCP trust-edge check."""

    def _build_with_binding_type(self, constraint_type: str) -> FactGraph:
        target = _target_role_node()
        external = _account_root_node(_EXTERNAL_ACCOUNT)
        edge = _trust_edge(
            src=external,
            dst=target,
            naked_trust=NAKED_BROAD,
            cross_account=True,
        )
        constraint = _constraint(
            constraint_id=f"{constraint_type.lower()}_constraint_xyz",
            constraint_type=constraint_type,
        )
        binding = _edge_constraint(
            edge_id=edge.edge_id,
            constraint_id=constraint.constraint_id,
            governance_confidence="complete",
            likely_blocking=True,
            binding_reason=f"{constraint_type} binding on trust edge",
        )
        return _make_facts(
            nodes=(target, external),
            edges=(edge,),
            constraints=(constraint,),
            edge_constraints=(binding,),
        )

    def test_permission_boundary_binding_does_not_create_scp_blocker(self) -> None:
        finding = CrossAccountTrustReasoner().run(self._build_with_binding_type(CONSTRAINT_TYPE_PERMISSION_BOUNDARY))[0]
        check_4 = next(c for c in finding.required_checks if c.name == "no_scp_blocks_sts_assumerole")
        assert finding.verdict is Verdict.VALIDATED
        assert check_4.state is CheckState.PASS
        assert not any(blocker.kind == "scp" for blocker in finding.blockers_observed)

    def test_trust_condition_binding_does_not_create_scp_unknown(self) -> None:
        finding = CrossAccountTrustReasoner().run(self._build_with_binding_type(CONSTRAINT_TYPE_TRUST_CONDITION))[0]
        check_4 = next(c for c in finding.required_checks if c.name == "no_scp_blocks_sts_assumerole")
        assert finding.verdict is Verdict.VALIDATED
        assert check_4.state is CheckState.PASS
        assert not any(blocker.kind == "scp" for blocker in finding.blockers_observed)

    def test_actual_scp_binding_still_blocks(self) -> None:
        finding = CrossAccountTrustReasoner().run(self._build_with_binding_type(CONSTRAINT_TYPE_SCP))[0]
        check_4 = next(c for c in finding.required_checks if c.name == "no_scp_blocks_sts_assumerole")
        assert finding.verdict is Verdict.BLOCKED
        assert finding.severity == SEVERITY_INFO
        assert check_4.state is CheckState.FAIL
        assert any(blocker.kind == "scp" for blocker in finding.blockers_observed)


# ---------------------------------------------------------------------------
# Fixture C: narrow_naked_weak_conditions → validated/medium
# ---------------------------------------------------------------------------


class TestFixtureCNarrowNakedWeakConditions:
    """Trust with sts:ExternalId only → NARROW_NAKED → validated/medium."""

    def _build(self) -> FactGraph:
        target = _target_role_node()
        external = _external_role_node()
        edge = _trust_edge(
            src=external,
            dst=target,
            naked_trust=NAKED_NARROW,
            cross_account=True,
            has_external_id=True,
        )
        return _make_facts(nodes=(target, external), edges=(edge,))

    def test_emits_validated_medium(self) -> None:
        findings = CrossAccountTrustReasoner().run(self._build())
        assert len(findings) == 1
        f = findings[0]
        assert f.verdict is Verdict.VALIDATED
        assert f.severity == SEVERITY_MEDIUM

    def test_narrow_naked_does_emit_finding(self) -> None:
        """Negative regression: a reasoner that skips NARROW_NAKED produces zero findings.

        This test fails loudly if the reasoner ever stops emitting
        findings for NARROW_NAKED, which is plan §4A.6 failure mode 2.
        """
        findings = CrossAccountTrustReasoner().run(self._build())
        assert len(findings) > 0


# ---------------------------------------------------------------------------
# Fixture D: conditioned_no_finding → no finding emitted
# ---------------------------------------------------------------------------


class TestFixtureDConditionedNoFinding:
    """Trust with strong conditions (OrgID + MFA) → CONDITIONED → no finding."""

    def _build(self) -> FactGraph:
        target = _target_role_node()
        external = _external_role_node()
        edge = _trust_edge(
            src=external,
            dst=target,
            naked_trust=NAKED_CONDITIONED,
            cross_account=True,
            has_org_id_condition=True,
            has_mfa_condition=True,
        )
        return _make_facts(nodes=(target, external), edges=(edge,))

    def test_no_finding_emitted(self) -> None:
        findings = CrossAccountTrustReasoner().run(self._build())
        assert findings == []


# ---------------------------------------------------------------------------
# Fixture E: scp_partial_forces_inconclusive → inconclusive/high
# ---------------------------------------------------------------------------


class TestFixtureESCPPartialForcesInconclusive:
    """SCP with parse_status=partial → governance_confidence=partial → inconclusive."""

    def _build(self) -> FactGraph:
        target = _target_role_node()
        external = _account_root_node(_EXTERNAL_ACCOUNT)
        edge = _trust_edge(
            src=external,
            dst=target,
            naked_trust=NAKED_CRITICAL,
            cross_account=True,
        )
        scp = _constraint(
            constraint_id="scp_partial_xyz",
            constraint_type=CONSTRAINT_TYPE_SCP,
            parse_status="partial",
        )
        ec = _edge_constraint(
            edge_id=edge.edge_id,
            constraint_id=scp.constraint_id,
            governance_confidence="partial",
            likely_blocking=False,
            binding_reason="SCP parse partial — could not evaluate fully",
        )
        return _make_facts(
            nodes=(target, external),
            edges=(edge,),
            constraints=(scp,),
            edge_constraints=(ec,),
        )

    def test_emits_inconclusive_high(self) -> None:
        findings = CrossAccountTrustReasoner().run(self._build())
        assert len(findings) == 1
        f = findings[0]
        assert f.verdict is Verdict.INCONCLUSIVE
        assert f.severity == SEVERITY_HIGH

    def test_check_4_is_unknown(self) -> None:
        """The SCP check (#4) should be in UNKNOWN state, not FAIL."""
        f = CrossAccountTrustReasoner().run(self._build())[0]
        check_4 = next(c for c in f.required_checks if c.name == "no_scp_blocks_sts_assumerole")
        assert check_4.state is CheckState.UNKNOWN


# ---------------------------------------------------------------------------
# Fixture F: oidc_broad_no_sub → validated/high
# ---------------------------------------------------------------------------


class TestFixtureFOIDCBroadNoSub:
    """OIDC trust without :sub condition → BROAD_NAKED → validated/high."""

    def _build(self) -> FactGraph:
        target = _target_role_node()
        oidc = _oidc_provider_node()
        edge = _trust_edge(
            src=oidc,
            dst=target,
            naked_trust=NAKED_BROAD,
            cross_account=True,
        )
        return _make_facts(nodes=(target, oidc), edges=(edge,))

    def test_emits_validated_high(self) -> None:
        findings = CrossAccountTrustReasoner().run(self._build())
        assert len(findings) == 1
        f = findings[0]
        assert f.verdict is Verdict.VALIDATED
        assert f.severity == SEVERITY_HIGH


# ---------------------------------------------------------------------------
# Fixture G: unsupported_scp_forces_inconclusive
# ---------------------------------------------------------------------------


class TestFixtureGUnsupportedSCPForcesInconclusive:
    """SCP with parse_status=unsupported → needs_review binding → inconclusive."""

    def _build(self) -> FactGraph:
        target = _target_role_node()
        external = _account_root_node(_EXTERNAL_ACCOUNT)
        edge = _trust_edge(
            src=external,
            dst=target,
            naked_trust=NAKED_CRITICAL,
            cross_account=True,
        )
        scp = _constraint(
            constraint_id="scp_unsupported_xyz",
            constraint_type=CONSTRAINT_TYPE_SCP,
            parse_status="unsupported",
        )
        ec = _edge_constraint(
            edge_id=edge.edge_id,
            constraint_id=scp.constraint_id,
            governance_confidence="needs_review",
            likely_blocking=False,
            binding_reason="SCP uses unsupported syntax — manual review required",
        )
        return _make_facts(
            nodes=(target, external),
            edges=(edge,),
            constraints=(scp,),
            edge_constraints=(ec,),
        )

    def test_emits_inconclusive_high(self) -> None:
        f = CrossAccountTrustReasoner().run(self._build())[0]
        assert f.verdict is Verdict.INCONCLUSIVE
        assert f.severity == SEVERITY_HIGH

    def test_needs_review_does_not_promote_to_blocked(self) -> None:
        """Plan §4A.6 failure mode 3 regression guard.

        A reasoner that interprets `needs_review` as "probably blocking"
        produces a `blocked` verdict and lets the client dismiss the
        finding in the rebuttal meeting. The correct answer is
        `inconclusive`.
        """
        f = CrossAccountTrustReasoner().run(self._build())[0]
        assert f.verdict is not Verdict.BLOCKED


# ---------------------------------------------------------------------------
# Fixture H: multi_statement_dedup
# ---------------------------------------------------------------------------


class TestFixtureHMultiStatementDedup:
    """Role with two trust statements (one intra-account, one cross-account).

    Reasoner emits exactly ONE finding — for the cross-account
    statement only. Plan §4A.6 failure mode 4 regression guard.
    """

    def _build(self) -> FactGraph:
        target = _target_role_node()
        intra_user = _intra_user_node()
        external = _account_root_node(_EXTERNAL_ACCOUNT)
        # Intra-account trust statement (early-exits on check 1).
        edge_intra = _trust_edge(
            src=intra_user,
            dst=target,
            naked_trust=NAKED_INTRA_ACCOUNT,
            cross_account=False,
            statement_index=0,
            digest="0123456789abcdef" * 4,
        )
        # Cross-account trust statement (emits finding).
        edge_cross = _trust_edge(
            src=external,
            dst=target,
            naked_trust=NAKED_BROAD,
            cross_account=True,
            statement_index=1,
            digest="fedcba9876543210" * 4,
        )
        return _make_facts(
            nodes=(target, intra_user, external),
            edges=(edge_intra, edge_cross),
        )

    def test_exactly_one_finding(self) -> None:
        findings = CrossAccountTrustReasoner().run(self._build())
        assert len(findings) == 1

    def test_finding_is_for_cross_account_edge(self) -> None:
        """The finding's source must be the external account, not the intra user."""
        f = CrossAccountTrustReasoner().run(self._build())[0]
        assert f.source.provider_id == _EXTERNAL_ROOT_ARN
        # And the cited statement digest must be the cross-account one.
        assert "fedcba9876543210" * 4 in f.evidence.statement_digests


# ---------------------------------------------------------------------------
# Fixture Z: same_org_downgrade
# ---------------------------------------------------------------------------


class TestFixtureZSameOrgDowngrade:
    """Same-org cross-account trust → severity downgraded by one level.

    Plan §4A.6 failure mode 1 regression guard. The reasoner must
    detect `org_member=True` on the source synthetic node and downgrade
    severity by one level (critical→high in this fixture).
    """

    def _build(self) -> FactGraph:
        target = _target_role_node()
        # Same-org source: 222 is in the collected org.
        external_but_in_org = _account_root_node(
            _EXTERNAL_ACCOUNT,
            org_member=True,
        )
        edge = _trust_edge(
            src=external_but_in_org,
            dst=target,
            naked_trust=NAKED_CRITICAL,
            cross_account=True,
        )
        return _make_facts(
            nodes=(target, external_but_in_org),
            edges=(edge,),
        )

    def test_emits_validated_with_downgraded_severity(self) -> None:
        f = CrossAccountTrustReasoner().run(self._build())[0]
        assert f.verdict is Verdict.VALIDATED
        # CRITICAL_NAKED would normally be `critical`, but same-org
        # downgrades to `high`.
        assert f.severity == SEVERITY_HIGH

    def test_finding_still_emitted_not_eliminated(self) -> None:
        """Same-org is a downgrade, not elimination."""
        findings = CrossAccountTrustReasoner().run(self._build())
        assert len(findings) == 1


class TestSourceOrgMembershipDerivation:
    """Concrete source principals can inherit org status from account-root metadata."""

    def _build(self) -> FactGraph:
        target = _target_role_node()
        source_user = Node(
            provider=PROVIDER_AWS,
            node_type=NODE_TYPE_IAM_USER,
            provider_id=f"arn:aws:iam::{_EXTERNAL_ACCOUNT}:user/env22-alice",
            region=REGION_GLOBAL,
            properties={
                "account_id": _EXTERNAL_ACCOUNT,
                "is_synthetic": False,
            },
        )
        source_account_root = _account_root_node(_EXTERNAL_ACCOUNT, org_member=True)
        edge = _trust_edge(
            src=source_user,
            dst=target,
            naked_trust=NAKED_CRITICAL,
            cross_account=True,
        )
        return _make_facts(
            nodes=(target, source_user, source_account_root),
            edges=(edge,),
        )

    def test_derives_same_org_from_source_account_root(self) -> None:
        f = CrossAccountTrustReasoner().run(self._build())[0]

        assert f.verdict is Verdict.VALIDATED
        assert f.severity == SEVERITY_HIGH
        org_trace = next(t for t in f.evidence.reasoning_trace if t.action == "evaluate_source_org_membership")
        assert "source account root" in org_trace.reason
        assert org_trace.result == "SAME_ORG"


# ---------------------------------------------------------------------------
# Determinism: double-run byte-equality
# ---------------------------------------------------------------------------


class TestDeterminism:
    """Two runs over the same FactGraph produce byte-identical Findings.

    Plan §4A.6 failure mode 5: a reasoner that iterates trust edges in
    source order rather than deterministic edge_id order will produce
    different finding_ids across runs because bundle_digest reflects
    trace entry order. The S10 sort in fact_graph.py guards against
    this; this test catches a regression if the sort is removed or
    bypassed.
    """

    def _build(self) -> FactGraph:
        target = _target_role_node()
        ext_a = _account_root_node("111111\u003111111", org_member=True)
        ext_b = _account_root_node("222222\u003222222", org_member=False)
        ext_c = _account_root_node("333333\u003333333", org_member=False)
        edge_a = _trust_edge(
            src=ext_a,
            dst=target,
            naked_trust=NAKED_CRITICAL,
            cross_account=True,
            digest="aaaa" * 16,
        )
        edge_b = _trust_edge(
            src=ext_b,
            dst=target,
            naked_trust=NAKED_BROAD,
            cross_account=True,
            digest="bbbb" * 16,
        )
        edge_c = _trust_edge(
            src=ext_c,
            dst=target,
            naked_trust=NAKED_NARROW,
            cross_account=True,
            has_external_id=True,
            digest="cccc" * 16,
        )
        return _make_facts(
            nodes=(target, ext_a, ext_b, ext_c),
            edges=(edge_a, edge_b, edge_c),
        )

    def test_double_run_produces_identical_findings(self) -> None:
        facts = self._build()
        run_1 = CrossAccountTrustReasoner().run(facts)
        run_2 = CrossAccountTrustReasoner().run(facts)
        assert len(run_1) == len(run_2)
        for f1, f2 in zip(run_1, run_2, strict=True):
            assert f1 == f2  # Frozen-dataclass equality (compare=False on cache)

    def test_double_run_produces_identical_finding_ids(self) -> None:
        facts = self._build()
        ids_1 = tuple(f.finding_id for f in CrossAccountTrustReasoner().run(facts))
        ids_2 = tuple(f.finding_id for f in CrossAccountTrustReasoner().run(facts))
        assert ids_1 == ids_2

    def test_double_run_produces_identical_bundle_digests(self) -> None:
        """The deepest determinism guarantee — bundle digests are stable.

        bundle_digest is part of the finding_id formula. If trace entry
        order differs across runs, this test fails before the
        finding_id equality test does, surfacing the root cause.
        """
        facts = self._build()
        digests_1 = tuple(f.evidence.bundle_digest for f in CrossAccountTrustReasoner().run(facts))
        digests_2 = tuple(f.evidence.bundle_digest for f in CrossAccountTrustReasoner().run(facts))
        assert digests_1 == digests_2


# ---------------------------------------------------------------------------
# Probe overlay runtime truth
# ---------------------------------------------------------------------------


class TestProbeOverlayRuntimeTruth:
    def _validated_case(self) -> tuple[FactGraph, Edge]:
        target = _target_role_node()
        external = _account_root_node(_EXTERNAL_ACCOUNT)
        edge = _trust_edge(
            src=external,
            dst=target,
            naked_trust=NAKED_BROAD,
            cross_account=True,
        )
        facts = _make_facts(nodes=(target, external), edges=(edge,))
        return facts, edge

    def test_denied_probe_blocks_validated_trust(self) -> None:
        facts, edge = self._validated_case()
        probe = _probe_record(
            edge.edge_id,
            PROBE_STATE_PROBED_CORRELATED_DENIED,
            controls=("p-deny-cross-account",),
        )

        finding = CrossAccountTrustReasoner().run(_with_probe(facts, probe))[0]

        assert finding.verdict is Verdict.BLOCKED
        assert finding.severity == SEVERITY_INFO
        assert any(b.kind == "probe_overlay" for b in finding.blockers_observed)
        check = next(c for c in finding.required_checks if c.name == "probe_overlay_runtime_truth")
        assert check.state is CheckState.FAIL
        trace = finding.evidence.reasoning_trace[-2]
        assert trace.action == "apply_probe_overlay"
        assert probe.probe_id in trace.inputs
        assert probe.probe_state in trace.inputs
        assert "p-deny-cross-account" in trace.inputs

    def test_confounded_probe_makes_validated_trust_inconclusive(self) -> None:
        facts, edge = self._validated_case()
        probe = _probe_record(
            edge.edge_id,
            PROBE_STATE_CONFOUNDED_SKIP,
            confounded=True,
            controls=("p-inherited",),
        )

        finding = CrossAccountTrustReasoner().run(_with_probe(facts, probe))[0]

        assert finding.verdict is Verdict.INCONCLUSIVE
        check = next(c for c in finding.required_checks if c.name == "probe_overlay_runtime_truth")
        assert check.state is CheckState.UNKNOWN
        assert "p-inherited" in finding.evidence.constraint_refs

    def test_disagreement_probe_makes_validated_trust_inconclusive(self) -> None:
        facts, edge = self._validated_case()
        probe = _probe_record(edge.edge_id, PROBE_STATE_PROBED_CORRELATED_DISAGREEMENT)

        finding = CrossAccountTrustReasoner().run(_with_probe(facts, probe))[0]

        assert finding.verdict is Verdict.INCONCLUSIVE
        check = next(c for c in finding.required_checks if c.name == "probe_overlay_runtime_truth")
        assert check.state is CheckState.UNKNOWN

    def test_no_overlay_keeps_existing_finding_byte_identical(self) -> None:
        facts, _edge = self._validated_case()
        copied = FactGraph(
            nodes=facts.nodes,
            edges=facts.edges,
            constraints=facts.constraints,
            edge_constraints=facts.edge_constraints,
            scenario_hash=facts.scenario_hash,
            edge_budget_exhausted=facts.edge_budget_exhausted,
            probe_records_by_edge={},
        )

        original = CrossAccountTrustReasoner().run(facts)[0]
        with_empty_overlay = CrossAccountTrustReasoner().run(copied)[0]

        assert with_empty_overlay == original
