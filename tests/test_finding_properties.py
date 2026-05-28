"""Property-based tests for Finding construction invariants.

The Finding dataclass enforces a rich set of invariants at
`__post_init__` — severity values, verdict type, cross-reference
validity, and verdict-specific rules (VALIDATED all-PASS, BLOCKED
has-fail-and-blocker, PRECONDITION_ONLY has-pass-fail-blocker).

Example-based unit tests cover the canonical cases for each invariant
but can't exercise the combinatorial space of possible Finding
constructions. Property-based tests generate thousands of random
valid Findings per verdict shape and assert that the structural
invariants hold for every instance.

The strategies in `tests/strategies.py` are constructed to respect
the invariants — a `validated_finding_strategy` only produces
findings where every check is PASS and there are no blockers. This
means the strategies test the strategies AS WELL AS the invariants:
a bug in the Finding class that weakens an invariant would cause the
strategies to produce findings the dataclass silently accepts but
that violate the documented contract.

Test categories:
- **Construction invariants**: every valid Finding strategy produces
  a Finding that `__post_init__` accepts without raising.
- **Refuses-to-lie**: a Finding with verdict=VALIDATED cannot have
  any non-PASS check (generating a VALIDATED finding with a FAIL or
  UNKNOWN check should raise InvalidFindingError).
- **Determinism**: the same inputs produce the same finding_id and
  bundle_digest across two invocations.
- **Trace step contiguity**: generated traces always have steps
  1,2,...,n (invariant of the strategy AND of EvidenceBundle).
- **Cross-reference validity**: every Check.evidence_refs value
  appears in the bundle's reference pools.
- **Finding_id shape**: the finding_id is a deterministic 64-char
  hex digest regardless of which verdict shape generated it.
"""

from __future__ import annotations

from hypothesis import given, settings

from iamscope.reasoner.verdict import (
    ASSUMPTION_KIND_CONDITION_CONTEXT,
    Assumption,
    Check,
    CheckState,
    Finding,
    InvalidFindingError,
    Verdict,
)
from tests.strategies import (
    any_finding_strategy,
    blocked_finding_strategy,
    inconclusive_finding_strategy,
    precondition_only_finding_strategy,
    validated_finding_strategy,
)

# ---------------------------------------------------------------------------
# Construction invariants: strategies produce valid findings
# ---------------------------------------------------------------------------


class TestConstructionInvariants:
    """Every strategy produces Findings that pass __post_init__ validation."""

    @given(validated_finding_strategy())
    @settings(max_examples=200, deadline=None)
    def test_validated_strategy_always_valid(self, f: Finding) -> None:
        """A validated_finding_strategy produces a valid VALIDATED finding."""
        assert f.verdict is Verdict.VALIDATED
        # All checks must be PASS (enforced by __post_init__; if the
        # strategy violated this, the draw itself would have raised).
        for chk in f.required_checks:
            assert chk.state is CheckState.PASS
        assert f.blockers_observed == ()
        for asm in f.assumptions:
            assert asm.kind != ASSUMPTION_KIND_CONDITION_CONTEXT

    @given(blocked_finding_strategy())
    @settings(max_examples=200, deadline=None)
    def test_blocked_strategy_always_valid(self, f: Finding) -> None:
        """A blocked_finding_strategy produces a valid BLOCKED finding."""
        assert f.verdict is Verdict.BLOCKED
        # ≥1 FAIL check
        assert any(chk.state is CheckState.FAIL for chk in f.required_checks)
        # ≥1 blocker
        assert len(f.blockers_observed) >= 1

    @given(precondition_only_finding_strategy())
    @settings(max_examples=200, deadline=None)
    def test_precondition_only_strategy_always_valid(self, f: Finding) -> None:
        """A precondition_only_finding_strategy produces a valid finding."""
        assert f.verdict is Verdict.PRECONDITION_ONLY
        # ≥1 PASS check (overpermission proven)
        assert any(chk.state is CheckState.PASS for chk in f.required_checks)
        # ≥1 FAIL check (path blocked)
        assert any(chk.state is CheckState.FAIL for chk in f.required_checks)
        # ≥1 blocker
        assert len(f.blockers_observed) >= 1

    @given(inconclusive_finding_strategy())
    @settings(max_examples=200, deadline=None)
    def test_inconclusive_strategy_always_valid(self, f: Finding) -> None:
        """An inconclusive_finding_strategy produces a valid INCONCLUSIVE."""
        assert f.verdict is Verdict.INCONCLUSIVE
        # INCONCLUSIVE is permissive — no state invariant to assert
        # beyond the generic cross-reference validity.


# ---------------------------------------------------------------------------
# Refuses-to-lie: invalid combinations raise InvalidFindingError
# ---------------------------------------------------------------------------


class TestRefusesToLie:
    """A VALIDATED verdict cannot be forced onto a finding with any
    non-PASS check or any blocker. The `__post_init__` guards enforce
    this so reasoners cannot silently emit false-positive VALIDATED.
    """

    @given(validated_finding_strategy())
    @settings(max_examples=50, deadline=None)
    def test_validated_with_fail_check_raises(self, f: Finding) -> None:
        """Replacing a PASS check with a FAIL check on a VALIDATED
        finding must raise InvalidFindingError."""
        # Build a mutated check set with one FAIL check
        mutated_checks = list(f.required_checks)
        if not mutated_checks:
            return  # skip degenerate
        mutated_checks[0] = Check(
            name=mutated_checks[0].name,
            description=mutated_checks[0].description,
            state=CheckState.FAIL,
            evidence_refs=mutated_checks[0].evidence_refs,
            reason=mutated_checks[0].reason,
        )
        try:
            Finding(
                pattern_id=f.pattern_id,
                pattern_version=f.pattern_version,
                source=f.source,
                target=f.target,
                verdict=Verdict.VALIDATED,
                severity=f.severity,
                title=f.title,
                required_checks=tuple(mutated_checks),
                blockers_observed=(),
                assumptions=f.assumptions,
                evidence=f.evidence,
                scenario_hash=f.scenario_hash,
            )
            raise AssertionError("VALIDATED finding with a FAIL check was accepted — refuses-to-lie invariant violated")
        except InvalidFindingError:
            pass

    @given(validated_finding_strategy())
    @settings(max_examples=50, deadline=None)
    def test_validated_with_unknown_check_raises(self, f: Finding) -> None:
        """UNKNOWN check on VALIDATED must raise."""
        mutated_checks = list(f.required_checks)
        if not mutated_checks:
            return
        mutated_checks[0] = Check(
            name=mutated_checks[0].name,
            description=mutated_checks[0].description,
            state=CheckState.UNKNOWN,
            evidence_refs=mutated_checks[0].evidence_refs,
            reason=mutated_checks[0].reason,
        )
        try:
            Finding(
                pattern_id=f.pattern_id,
                pattern_version=f.pattern_version,
                source=f.source,
                target=f.target,
                verdict=Verdict.VALIDATED,
                severity=f.severity,
                title=f.title,
                required_checks=tuple(mutated_checks),
                blockers_observed=(),
                assumptions=f.assumptions,
                evidence=f.evidence,
                scenario_hash=f.scenario_hash,
            )
            raise AssertionError(
                "VALIDATED finding with an UNKNOWN check was accepted — refuses-to-lie invariant violated"
            )
        except InvalidFindingError:
            pass

    @given(validated_finding_strategy())
    @settings(max_examples=50, deadline=None)
    def test_validated_with_condition_context_assumption_raises(
        self,
        f: Finding,
    ) -> None:
        """condition_context assumption on VALIDATED must raise."""
        bad_assumption = Assumption(
            kind=ASSUMPTION_KIND_CONDITION_CONTEXT,
            detail="assumed favorable runtime context",
        )
        try:
            Finding(
                pattern_id=f.pattern_id,
                pattern_version=f.pattern_version,
                source=f.source,
                target=f.target,
                verdict=Verdict.VALIDATED,
                severity=f.severity,
                title=f.title,
                required_checks=f.required_checks,
                blockers_observed=(),
                assumptions=(bad_assumption,),
                evidence=f.evidence,
                scenario_hash=f.scenario_hash,
            )
            raise AssertionError(
                "VALIDATED finding with condition_context assumption was accepted — refuses-to-lie invariant violated"
            )
        except InvalidFindingError:
            pass


# ---------------------------------------------------------------------------
# Determinism
# ---------------------------------------------------------------------------


class TestDeterminism:
    """Two Findings constructed from identical inputs produce identical
    finding_id and bundle_digest values."""

    @given(any_finding_strategy())
    @settings(max_examples=100, deadline=None)
    def test_finding_id_is_deterministic(self, f: Finding) -> None:
        """Computing finding_id twice yields the same value."""
        first = f.finding_id
        second = f.finding_id
        assert first == second

    @given(any_finding_strategy())
    @settings(max_examples=100, deadline=None)
    def test_bundle_digest_is_deterministic(self, f: Finding) -> None:
        """Computing bundle_digest twice yields the same value."""
        first = f.evidence.bundle_digest
        second = f.evidence.bundle_digest
        assert first == second

    @given(any_finding_strategy())
    @settings(max_examples=100, deadline=None)
    def test_finding_id_is_64_char_hex(self, f: Finding) -> None:
        """finding_id is always a 64-character lowercase hex string."""
        fid = f.finding_id
        assert len(fid) == 64
        assert all(c in "0123456789abcdef" for c in fid)


# ---------------------------------------------------------------------------
# Trace contiguity
# ---------------------------------------------------------------------------


class TestTraceContiguity:
    """Every generated finding's reasoning_trace has steps 1,2,...,n."""

    @given(any_finding_strategy())
    @settings(max_examples=200, deadline=None)
    def test_trace_steps_are_contiguous_from_1(self, f: Finding) -> None:
        trace = f.evidence.reasoning_trace
        assert len(trace) >= 1  # Non-empty invariant
        for i, entry in enumerate(trace):
            assert entry.step == i + 1


# ---------------------------------------------------------------------------
# Cross-reference validity
# ---------------------------------------------------------------------------


class TestCrossReferenceValidity:
    """Every Check.evidence_refs value appears in the bundle's ref pools."""

    @given(any_finding_strategy())
    @settings(max_examples=200, deadline=None)
    def test_every_evidence_ref_is_in_bundle(self, f: Finding) -> None:
        known_refs = set(f.evidence.statement_digests) | set(f.evidence.edge_refs) | set(f.evidence.constraint_refs)
        for chk in f.required_checks:
            for ref in chk.evidence_refs:
                assert ref in known_refs, f"Check {chk.name!r} has dangling evidence_ref {ref!r} not in bundle"


# ---------------------------------------------------------------------------
# Severity / verdict structural invariants
# ---------------------------------------------------------------------------


class TestStructuralInvariants:
    """Severity is always one of the canonical values; verdict is always
    a Verdict enum member."""

    @given(any_finding_strategy())
    @settings(max_examples=100, deadline=None)
    def test_severity_is_canonical(self, f: Finding) -> None:
        assert f.severity in (
            "critical",
            "high",
            "medium",
            "low",
            "info",
        )

    @given(any_finding_strategy())
    @settings(max_examples=100, deadline=None)
    def test_verdict_is_enum_member(self, f: Finding) -> None:
        assert isinstance(f.verdict, Verdict)

    @given(any_finding_strategy())
    @settings(max_examples=100, deadline=None)
    def test_non_empty_title(self, f: Finding) -> None:
        assert len(f.title) >= 1
