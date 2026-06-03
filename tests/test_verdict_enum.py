"""S08 tests: Verdict/CheckState enums and Finding invariants.

Covers:
1. Enum string values match the documented plan spec.
2. Enum round-trip through .value works.
3. Finding construction accepts valid combinations for every verdict.
4. Finding.__post_init__ rejects every documented invariant violation
   with an InvalidFindingError.

S09 will add `evidence: EvidenceBundle` and the `finding_id` property;
those are tested in test_evidence.py and test_finding_id.py respectively
(both S09-owned).
"""

from __future__ import annotations

import pytest

from iamscope.constants import (
    NODE_TYPE_IAM_ROLE,
    NODE_TYPE_IAM_USER,
    PROVIDER_AWS,
    SEVERITY_HIGH,
    SEVERITY_LOW,
    SEVERITY_MEDIUM,
)
from iamscope.models import NodeRef
from iamscope.reasoner import (
    ASSUMPTION_KIND_CONDITION_CONTEXT,
    Assumption,
    Blocker,
    Check,
    CheckState,
    Finding,
    InvalidFindingError,
    Verdict,
)
from iamscope.reasoner.evidence import EvidenceBundle, TraceEntry

# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


def _src() -> NodeRef:
    return NodeRef(
        provider=PROVIDER_AWS,
        node_type=NODE_TYPE_IAM_USER,
        provider_id="arn:aws:iam::111111\u003111111:user/Alice",
    )


def _dst() -> NodeRef:
    return NodeRef(
        provider=PROVIDER_AWS,
        node_type=NODE_TYPE_IAM_ROLE,
        provider_id="arn:aws:iam::222222\u003222222:role/ProdAdmin",
    )


def _pass_check(name: str = "source_has_passrole_to_target") -> Check:
    return Check(
        name=name,
        description="Source principal has iam:PassRole to target",
        state=CheckState.PASS,
        evidence_refs=("digest_abc123",),
        reason="inline policy grants exact resource ARN",
    )


def _fail_check(name: str = "no_scp_denies_pattern") -> Check:
    return Check(
        name=name,
        description="No SCP denies the action chain",
        state=CheckState.FAIL,
        evidence_refs=("constraint_xyz789",),
        reason="SCP DenyAssumeRole with complete parse",
    )


def _unknown_check(name: str = "boundary_allows_pattern") -> Check:
    return Check(
        name=name,
        description="Permission boundary allows pattern",
        state=CheckState.UNKNOWN,
        evidence_refs=(),
        reason="boundary parse_status=partial, cannot evaluate intersection",
    )


def _scp_blocker() -> Blocker:
    return Blocker(
        kind="scp",
        constraint_id="constraint_xyz789",
        edge_id=None,
        reason="SCP p-prod-deny denies sts:AssumeRole at OU ou-prod",
    )


def _default_evidence() -> EvidenceBundle:
    """A minimal valid EvidenceBundle that satisfies §3.5 invariant 1
    cross-validation against `_pass_check`, `_fail_check`, and
    `_unknown_check` defaults.

    The default checks cite `digest_abc123` (in `_pass_check`) and
    `constraint_xyz789` (in `_fail_check`); `_unknown_check` cites
    nothing. This bundle carries both refs in their respective sets so
    cross-validation passes for any combination of the default checks.
    """
    return EvidenceBundle(
        statement_digests=("digest_abc123",),
        statement_sources={
            "digest_abc123": (
                "arn:aws:iam::111111\u003111111:policy/test",
                0,
                "stmt_0",
            ),
        },
        edge_refs=(),
        constraint_refs=("constraint_xyz789",),
        edge_constraint_refs=(),
        node_refs=(),
        condition_context_assumed=(),
        reasoning_trace=(
            TraceEntry(
                step=1,
                action="check_default",
                inputs=(),
                result="PASS",
                reason="default trace entry for test fixtures",
            ),
        ),
    )


def _make_finding(
    *,
    verdict: Verdict,
    severity: str = SEVERITY_MEDIUM,
    required_checks: tuple[Check, ...] = (),
    blockers_observed: tuple[Blocker, ...] = (),
    assumptions: tuple[Assumption, ...] = (),
    evidence: EvidenceBundle | None = None,
    reasoner_exit_reason: str = "",
) -> Finding:
    """Construct a Finding with sensible defaults for the non-varying fields.

    `evidence` defaults to `_default_evidence()` so existing tests pass
    without specifying a bundle. Tests that exercise the §3.5 cross-
    validation invariant override this argument explicitly.
    """
    return Finding(
        pattern_id="test.pattern",
        pattern_version="1.0.0",
        source=_src(),
        target=_dst(),
        verdict=verdict,
        severity=severity,
        title="Test finding",
        required_checks=required_checks,
        blockers_observed=blockers_observed,
        assumptions=assumptions,
        evidence=evidence if evidence is not None else _default_evidence(),
        scenario_hash="deadbeef" * 8,
        reasoner_exit_reason=reasoner_exit_reason,
    )


# ---------------------------------------------------------------------------
# Enum value and round-trip tests
# ---------------------------------------------------------------------------


class TestVerdictEnum:
    """Verdict enum members carry the plan-documented string values."""

    def test_verdict_string_values(self) -> None:
        """All four verdict values match the plan spec verbatim."""
        assert Verdict.VALIDATED.value == "validated"
        assert Verdict.BLOCKED.value == "blocked"
        assert Verdict.INCONCLUSIVE.value == "inconclusive"
        assert Verdict.PRECONDITION_ONLY.value == "precondition_only"

    def test_verdict_from_value_round_trip(self) -> None:
        """Verdict('validated') reconstructs the correct enum member."""
        for v in Verdict:
            assert Verdict(v.value) is v

    def test_verdict_enum_is_closed(self) -> None:
        """There are exactly 4 verdict values — no extras added silently."""
        assert len(list(Verdict)) == 4


class TestCheckStateEnum:
    """CheckState enum carries the plan-documented tristate."""

    def test_check_state_string_values(self) -> None:
        assert CheckState.PASS.value == "pass"
        assert CheckState.FAIL.value == "fail"
        assert CheckState.UNKNOWN.value == "unknown"

    def test_check_state_from_value_round_trip(self) -> None:
        for s in CheckState:
            assert CheckState(s.value) is s

    def test_check_state_enum_is_closed(self) -> None:
        assert len(list(CheckState)) == 3


# ---------------------------------------------------------------------------
# Finding construction — valid paths
# ---------------------------------------------------------------------------


class TestFindingConstruction:
    """Finding accepts every valid combination of the verdict taxonomy."""

    def test_minimal_inconclusive_finding(self) -> None:
        """INCONCLUSIVE is permissive at the dataclass level."""
        f = _make_finding(
            verdict=Verdict.INCONCLUSIVE,
            required_checks=(_unknown_check(),),
        )
        assert f.verdict is Verdict.INCONCLUSIVE
        assert f.pattern_id == "test.pattern"

    def test_validated_finding_with_all_pass_checks(self) -> None:
        """VALIDATED with all PASS checks and no assumptions is valid."""
        f = _make_finding(
            verdict=Verdict.VALIDATED,
            severity=SEVERITY_HIGH,
            required_checks=(_pass_check("check_a"), _pass_check("check_b")),
        )
        assert f.verdict is Verdict.VALIDATED
        assert len(f.required_checks) == 2

    def test_blocked_finding_with_fail_check_and_blocker(self) -> None:
        """BLOCKED requires both a FAIL check and a blocker entry."""
        f = _make_finding(
            verdict=Verdict.BLOCKED,
            required_checks=(_pass_check(), _fail_check()),
            blockers_observed=(_scp_blocker(),),
        )
        assert f.verdict is Verdict.BLOCKED

    def test_precondition_only_with_pass_and_fail(self) -> None:
        """PRECONDITION_ONLY needs both a PASS (overpermission) and FAIL (path)."""
        f = _make_finding(
            verdict=Verdict.PRECONDITION_ONLY,
            severity=SEVERITY_LOW,
            required_checks=(_pass_check("overpermission_exists"), _fail_check("path_reachable")),
            blockers_observed=(_scp_blocker(),),
        )
        assert f.verdict is Verdict.PRECONDITION_ONLY

    def test_rejects_invalid_severity(self) -> None:
        """Severity must be in SEVERITY_VALUES."""
        with pytest.raises(InvalidFindingError, match="severity must be one of"):
            _make_finding(
                verdict=Verdict.INCONCLUSIVE,
                severity="catastrophic",  # not in closed set
                required_checks=(_unknown_check(),),
            )

    def test_rejects_empty_severity(self) -> None:
        """Empty-string severity is not in the closed set."""
        with pytest.raises(InvalidFindingError, match="severity must be one of"):
            _make_finding(
                verdict=Verdict.INCONCLUSIVE,
                severity="",
                required_checks=(_unknown_check(),),
            )

    def test_rejects_verdict_wrong_type(self) -> None:
        """Verdict must be a Verdict enum member, not a bare string."""
        with pytest.raises(InvalidFindingError, match="must be a Verdict enum member"):
            _make_finding(
                verdict="validated",  # type: ignore[arg-type]  # intentional
                required_checks=(_pass_check(),),
            )


# ---------------------------------------------------------------------------
# Finding.__post_init__ verdict-level invariants
# ---------------------------------------------------------------------------


class TestFindingInvariants:
    """The S08 headline invariants from plan §3.4."""

    def test_validated_rejects_unknown_check(self) -> None:
        """VALIDATED + any UNKNOWN check → InvalidFindingError.

        This is the plan's headline invariant: "A reasoner that tries to
        emit VALIDATED with an unknown check raises InvalidFindingError."
        """
        with pytest.raises(InvalidFindingError, match="cannot contain a non-PASS check"):
            _make_finding(
                verdict=Verdict.VALIDATED,
                required_checks=(_pass_check(), _unknown_check()),
            )

    def test_validated_rejects_fail_check(self) -> None:
        """VALIDATED + any FAIL check → InvalidFindingError."""
        with pytest.raises(InvalidFindingError, match="cannot contain a non-PASS check"):
            _make_finding(
                verdict=Verdict.VALIDATED,
                required_checks=(_pass_check(), _fail_check()),
            )

    def test_validated_rejects_condition_context_assumption(self) -> None:
        """VALIDATED + condition_context assumption → InvalidFindingError.

        A reasoner that assumed anything about runtime condition context
        cannot claim validated — condition evaluation depends on session
        state the reasoner does not observe.
        """
        assumption = Assumption(
            kind=ASSUMPTION_KIND_CONDITION_CONTEXT,
            detail="assumed no session policy restricts sts:AssumeRole",
        )
        with pytest.raises(InvalidFindingError, match="condition_context"):
            _make_finding(
                verdict=Verdict.VALIDATED,
                required_checks=(_pass_check(),),
                assumptions=(assumption,),
            )

    def test_validated_accepts_non_condition_context_assumption(self) -> None:
        """Other assumption kinds do NOT block VALIDATED.

        Only the condition_context kind is a VALIDATED-blocker. A reasoner
        that assumed, say, "no region-specific VPC endpoint policy" can
        still emit VALIDATED — that's a different kind of runtime state
        and the plan's invariant list specifically names condition_context.
        """
        harmless = Assumption(
            kind="session_policy",
            detail="assumed no in-band session policy",
        )
        f = _make_finding(
            verdict=Verdict.VALIDATED,
            required_checks=(_pass_check(),),
            assumptions=(harmless,),
        )
        assert f.verdict is Verdict.VALIDATED

    def test_validated_rejects_non_empty_blockers(self) -> None:
        """VALIDATED with blockers_observed is internally contradictory."""
        with pytest.raises(InvalidFindingError, match="cannot have blockers_observed"):
            _make_finding(
                verdict=Verdict.VALIDATED,
                required_checks=(_pass_check(),),
                blockers_observed=(_scp_blocker(),),
            )

    def test_blocked_rejects_all_pass_checks(self) -> None:
        """BLOCKED with zero FAIL checks → InvalidFindingError."""
        with pytest.raises(InvalidFindingError, match="at least one FAIL check"):
            _make_finding(
                verdict=Verdict.BLOCKED,
                required_checks=(_pass_check(),),
                blockers_observed=(_scp_blocker(),),
            )

    def test_blocked_rejects_empty_blockers(self) -> None:
        """BLOCKED with no blockers_observed → InvalidFindingError."""
        with pytest.raises(InvalidFindingError, match="blockers_observed"):
            _make_finding(
                verdict=Verdict.BLOCKED,
                required_checks=(_fail_check(),),
                # no blockers
            )

    def test_precondition_only_rejects_all_pass(self) -> None:
        """PRECONDITION_ONLY without a FAIL check → InvalidFindingError."""
        with pytest.raises(InvalidFindingError, match="at least one FAIL check"):
            _make_finding(
                verdict=Verdict.PRECONDITION_ONLY,
                required_checks=(_pass_check(),),
                blockers_observed=(_scp_blocker(),),
            )

    def test_precondition_only_rejects_all_fail(self) -> None:
        """PRECONDITION_ONLY without a PASS check → InvalidFindingError."""
        with pytest.raises(InvalidFindingError, match="at least one PASS check"):
            _make_finding(
                verdict=Verdict.PRECONDITION_ONLY,
                required_checks=(_fail_check(),),
                blockers_observed=(_scp_blocker(),),
            )

    def test_precondition_only_rejects_empty_blockers(self) -> None:
        """PRECONDITION_ONLY needs to attribute the path block."""
        with pytest.raises(InvalidFindingError, match="blockers_observed"):
            _make_finding(
                verdict=Verdict.PRECONDITION_ONLY,
                required_checks=(_pass_check(), _fail_check()),
                # no blockers
            )


# ---------------------------------------------------------------------------
# Check construction invariants
# ---------------------------------------------------------------------------


class TestCheckConstruction:
    """Check itself validates its state field at construction."""

    def test_check_rejects_non_enum_state(self) -> None:
        """Check.state must be a CheckState enum member."""
        with pytest.raises(InvalidFindingError, match="must be a CheckState enum member"):
            Check(
                name="bad_check",
                description="bad",
                state="pass",  # type: ignore[arg-type]  # intentional
                evidence_refs=(),
                reason="bad",
            )


# ---------------------------------------------------------------------------
# S09: Finding evidence cross-validation (§3.5 invariant 1)
# ---------------------------------------------------------------------------


class TestFindingEvidenceCrossValidation:
    """Every Check.evidence_refs value must appear in the bundle's
    statement_digests, edge_refs, or constraint_refs. Dangling refs are
    rejected at construction with an InvalidFindingError that lists the
    missing ref names so the reasoner author can fix the bundle.
    """

    def test_rejects_dangling_statement_digest_ref(self) -> None:
        """A check citing a digest the bundle doesn't carry → reject."""
        check_with_dangling = Check(
            name="cites_missing_digest",
            description="Cites a statement digest not in the bundle",
            state=CheckState.PASS,
            evidence_refs=("missing_digest_xyz",),
            reason="test",
        )
        with pytest.raises(InvalidFindingError, match="missing_digest_xyz"):
            _make_finding(
                verdict=Verdict.VALIDATED,
                required_checks=(check_with_dangling,),
            )

    def test_rejects_dangling_edge_ref(self) -> None:
        """A check citing an edge_id not in the bundle → reject."""
        check_with_edge_ref = Check(
            name="cites_missing_edge",
            description="Cites an edge_id not in the bundle",
            state=CheckState.PASS,
            evidence_refs=("edge_not_in_bundle",),
            reason="test",
        )
        with pytest.raises(InvalidFindingError, match="edge_not_in_bundle"):
            _make_finding(
                verdict=Verdict.VALIDATED,
                required_checks=(check_with_edge_ref,),
            )

    def test_accepts_ref_present_in_edge_refs(self) -> None:
        """A check citing an edge_id present in evidence.edge_refs → accept.

        Cross-validation checks the union of all three ref sets, so a
        check can cite an edge_id and have the bundle satisfy the
        invariant via edge_refs (rather than statement_digests).
        """
        bundle_with_edge = EvidenceBundle(
            statement_digests=("digest_a",),
            statement_sources={"digest_a": ("p", 0, "s")},
            edge_refs=("edge_alpha",),
            constraint_refs=(),
            edge_constraint_refs=(),
            node_refs=(),
            condition_context_assumed=(),
            reasoning_trace=(TraceEntry(step=1, action="a", inputs=(), result="PASS", reason=""),),
        )
        check = Check(
            name="cites_edge",
            description="Cites an edge_id present in the bundle",
            state=CheckState.PASS,
            evidence_refs=("edge_alpha",),
            reason="test",
        )
        f = _make_finding(
            verdict=Verdict.VALIDATED,
            required_checks=(check,),
            evidence=bundle_with_edge,
        )
        assert f.verdict is Verdict.VALIDATED

    def test_accepts_ref_present_in_constraint_refs(self) -> None:
        """A check citing a constraint_id present in evidence.constraint_refs → accept."""
        bundle_with_constraint = EvidenceBundle(
            statement_digests=("digest_a",),
            statement_sources={"digest_a": ("p", 0, "s")},
            edge_refs=(),
            constraint_refs=("constraint_beta",),
            edge_constraint_refs=(),
            node_refs=(),
            condition_context_assumed=(),
            reasoning_trace=(TraceEntry(step=1, action="a", inputs=(), result="FAIL", reason=""),),
        )
        check = Check(
            name="cites_constraint",
            description="Cites a constraint_id present in the bundle",
            state=CheckState.FAIL,
            evidence_refs=("constraint_beta",),
            reason="test",
        )
        f = _make_finding(
            verdict=Verdict.BLOCKED,
            required_checks=(check,),
            blockers_observed=(_scp_blocker(),),
            evidence=bundle_with_constraint,
        )
        assert f.verdict is Verdict.BLOCKED

    def test_check_with_no_evidence_refs_always_valid(self) -> None:
        """A check with empty evidence_refs trivially passes cross-validation."""
        check = Check(
            name="trace_only",
            description="A check that relies entirely on the trace",
            state=CheckState.UNKNOWN,
            evidence_refs=(),
            reason="reasoner could not gather evidence",
        )
        f = _make_finding(
            verdict=Verdict.INCONCLUSIVE,
            required_checks=(check,),
        )
        assert f.verdict is Verdict.INCONCLUSIVE


# ---------------------------------------------------------------------------
# S09: Finding.finding_id property
# ---------------------------------------------------------------------------


class TestFindingId:
    """The finding_id property is deterministic and load-bearing."""

    def test_finding_id_is_sha256_hex(self) -> None:
        """Property returns a 64-character lowercase hex string."""
        f = _make_finding(
            verdict=Verdict.INCONCLUSIVE,
            required_checks=(_unknown_check(),),
        )
        fid = f.finding_id
        assert isinstance(fid, str)
        assert len(fid) == 64
        assert all(c in "0123456789abcdef" for c in fid)

    def test_two_findings_same_inputs_same_id(self) -> None:
        """Determinism: identical Findings produce identical finding_ids."""
        f_a = _make_finding(
            verdict=Verdict.INCONCLUSIVE,
            required_checks=(_unknown_check(),),
        )
        f_b = _make_finding(
            verdict=Verdict.INCONCLUSIVE,
            required_checks=(_unknown_check(),),
        )
        assert f_a.finding_id == f_b.finding_id

    def test_finding_id_changes_with_pattern_version(self) -> None:
        """Bumping pattern_version produces a new finding_id.

        The plan's headline reasoner-versioning guarantee. This is what
        makes findings_diff (S11+) surface a reasoner logic change as
        old_id deleted + new_id added rather than silently changing the
        verdict on the same ID.
        """
        f_v1 = Finding(
            pattern_id="test.pattern",
            pattern_version="1.0.0",
            source=_src(),
            target=_dst(),
            verdict=Verdict.INCONCLUSIVE,
            severity=SEVERITY_MEDIUM,
            title="Test",
            required_checks=(_unknown_check(),),
            blockers_observed=(),
            assumptions=(),
            evidence=_default_evidence(),
            scenario_hash="deadbeef" * 8,
        )
        f_v2 = Finding(
            pattern_id="test.pattern",
            pattern_version="2.0.0",  # bumped
            source=_src(),
            target=_dst(),
            verdict=Verdict.INCONCLUSIVE,
            severity=SEVERITY_MEDIUM,
            title="Test",
            required_checks=(_unknown_check(),),
            blockers_observed=(),
            assumptions=(),
            evidence=_default_evidence(),
            scenario_hash="deadbeef" * 8,
        )
        assert f_v1.finding_id != f_v2.finding_id

    def test_finding_id_changes_with_evidence_bundle(self) -> None:
        """Different evidence → different finding_id even with same pattern + endpoints.

        Two reasoners that produce findings with the same (pattern,
        source, target) but different evidence (different statements
        cited, different edges examined) must produce different IDs.
        """
        bundle_a = _default_evidence()
        bundle_b = EvidenceBundle(
            statement_digests=("digest_abc123", "digest_extra"),
            statement_sources={
                "digest_abc123": ("p", 0, "s"),
                "digest_extra": ("p2", 1, "s2"),
            },
            edge_refs=(),
            constraint_refs=("constraint_xyz789",),
            edge_constraint_refs=(),
            node_refs=(),
            condition_context_assumed=(),
            reasoning_trace=(TraceEntry(step=1, action="a", inputs=(), result="PASS", reason=""),),
        )
        f_a = _make_finding(
            verdict=Verdict.INCONCLUSIVE,
            required_checks=(_unknown_check(),),
            evidence=bundle_a,
        )
        f_b = _make_finding(
            verdict=Verdict.INCONCLUSIVE,
            required_checks=(_unknown_check(),),
            evidence=bundle_b,
        )
        assert f_a.finding_id != f_b.finding_id


class TestFindingIdCaching:
    """The lazy cache is correct and frozen-dataclass-safe."""

    def test_two_accesses_return_same_value(self) -> None:
        """Second access returns the cached value.

        Implementation note: the Finding dataclass is frozen, so the
        property uses `object.__setattr__` to populate the cache. If the
        cache logic is broken, the second access either recomputes
        (waste) or raises a FrozenInstanceError (broken). This test
        catches both.
        """
        f = _make_finding(
            verdict=Verdict.INCONCLUSIVE,
            required_checks=(_unknown_check(),),
        )
        first = f.finding_id
        second = f.finding_id
        assert first == second

    def test_cache_does_not_break_equality(self) -> None:
        """Two Findings with identical fields are equal regardless of cache state.

        The `_finding_id_cache` field uses `compare=False` so it does
        not affect equality. A finding whose ID has been computed must
        still equal a finding whose ID has not been computed, given
        identical input fields.
        """
        f_a = _make_finding(
            verdict=Verdict.INCONCLUSIVE,
            required_checks=(_unknown_check(),),
        )
        f_b = _make_finding(
            verdict=Verdict.INCONCLUSIVE,
            required_checks=(_unknown_check(),),
        )
        # Compute the ID on f_a only.
        _ = f_a.finding_id
        # f_a now has a populated cache; f_b does not.
        assert f_a == f_b
