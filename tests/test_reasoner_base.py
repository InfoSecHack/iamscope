"""S09 tests: Reasoner Protocol conformance and ReasonerError exception.

The Protocol is `runtime_checkable`, which means `isinstance(obj,
Reasoner)` checks structural conformance: the candidate must have all
four identity attributes AND both methods. Missing any of them fails
the check. Note that runtime_checkable does NOT validate signatures,
return types, or class-level vs instance-level attribute placement —
those are static-analysis-only.
"""

from __future__ import annotations

import pytest

from iamscope.constants import (
    NODE_TYPE_IAM_ROLE,
    NODE_TYPE_IAM_USER,
    PROVIDER_AWS,
    SEVERITY_MEDIUM,
)
from iamscope.models import NodeRef
from iamscope.reasoner.base import Reasoner, ReasonerError
from iamscope.reasoner.evidence import EvidenceBundle, TraceEntry
from iamscope.reasoner.fact_graph import FactGraph
from iamscope.reasoner.registry import Registry
from iamscope.reasoner.verdict import (
    Check,
    CheckState,
    Finding,
    Verdict,
)

# ---------------------------------------------------------------------------
# Conforming reference implementation
# ---------------------------------------------------------------------------


class _ConformingReasoner:
    """A minimal class that satisfies the Reasoner Protocol structurally.

    Used as a positive control across the conformance tests below.
    Methods are no-ops because we're testing protocol conformance,
    not reasoning logic.
    """

    pattern_id = "test.conforming"
    pattern_version = "1.0.0"
    pattern_title = "Test Conforming Reasoner"
    severity_default = "medium"

    def preconditions_met(self, facts: FactGraph) -> tuple[bool, str]:
        return (True, "")

    def run(self, facts: FactGraph) -> list[Finding]:
        return []


# ---------------------------------------------------------------------------
# ReasonerError exception
# ---------------------------------------------------------------------------


class TestReasonerError:
    """ReasonerError is a usable exception type."""

    def test_is_runtime_error_subclass(self) -> None:
        """ReasonerError must inherit from RuntimeError so the registry
        can catch generic RuntimeErrors as a safety net while still
        distinguishing explicit reasoner rejections."""
        assert issubclass(ReasonerError, RuntimeError)

    def test_can_be_raised_and_caught(self) -> None:
        with pytest.raises(ReasonerError, match="malformed fact graph"):
            raise ReasonerError("malformed fact graph: missing IAMRole nodes")

    def test_can_be_caught_as_runtime_error(self) -> None:
        """Catching RuntimeError should also catch ReasonerError."""
        with pytest.raises(RuntimeError):
            raise ReasonerError("test")


# ---------------------------------------------------------------------------
# Protocol conformance via runtime_checkable isinstance
# ---------------------------------------------------------------------------


class TestReasonerProtocolConformance:
    """isinstance(obj, Reasoner) is the structural conformance test."""

    def test_conforming_class_passes_isinstance(self) -> None:
        """A class with all required attrs + methods is a Reasoner."""
        instance = _ConformingReasoner()
        assert isinstance(instance, Reasoner)

    def test_missing_pattern_id_fails_isinstance(self) -> None:
        """Removing pattern_id breaks Protocol conformance."""

        class NoPatternId:
            pattern_version = "1.0.0"
            pattern_title = "Missing pattern_id"
            severity_default = "medium"

            def preconditions_met(self, facts: FactGraph) -> tuple[bool, str]:
                return (True, "")

            def run(self, facts: FactGraph) -> list[Finding]:
                return []

        assert not isinstance(NoPatternId(), Reasoner)

    def test_missing_run_method_fails_isinstance(self) -> None:
        """Removing the run method breaks Protocol conformance."""

        class NoRun:
            pattern_id = "test.no_run"
            pattern_version = "1.0.0"
            pattern_title = "Missing run"
            severity_default = "medium"

            def preconditions_met(self, facts: FactGraph) -> tuple[bool, str]:
                return (True, "")

        assert not isinstance(NoRun(), Reasoner)

    def test_missing_preconditions_met_fails_isinstance(self) -> None:
        """Removing preconditions_met breaks Protocol conformance."""

        class NoPreconditions:
            pattern_id = "test.no_preconditions"
            pattern_version = "1.0.0"
            pattern_title = "Missing preconditions_met"
            severity_default = "medium"

            def run(self, facts: FactGraph) -> list[Finding]:
                return []

        assert not isinstance(NoPreconditions(), Reasoner)

    def test_inheritance_not_required(self) -> None:
        """Protocol membership is structural, not nominal.

        A class that happens to define all four attributes and both
        methods satisfies Reasoner whether or not it explicitly
        inherits from it. This is the canonical Protocol contract.
        """
        # _ConformingReasoner above does not inherit from Reasoner.
        # It satisfies the Protocol purely by structure.
        assert _ConformingReasoner.__bases__ == (object,)
        assert isinstance(_ConformingReasoner(), Reasoner)

    def test_explicit_subclass_also_works(self) -> None:
        """A class can also explicitly inherit from Reasoner.

        This is rare in practice (Protocols are usually used
        structurally) but the syntax is valid.
        """

        class ExplicitSubclass(Reasoner):
            pattern_id = "test.explicit"
            pattern_version = "1.0.0"
            pattern_title = "Explicit Reasoner subclass"
            severity_default = "low"

            def preconditions_met(self, facts: FactGraph) -> tuple[bool, str]:
                return (True, "")

            def run(self, facts: FactGraph) -> list[Finding]:
                return []

        assert isinstance(ExplicitSubclass(), Reasoner)


# ---------------------------------------------------------------------------
# Registry: registration, lookup, and run_all
# ---------------------------------------------------------------------------


def _empty_facts() -> FactGraph:
    """A minimal empty FactGraph for registry tests."""
    return FactGraph(
        nodes=(),
        edges=(),
        constraints=(),
        edge_constraints=(),
        scenario_hash="deadbeef" * 8,
        edge_budget_exhausted=False,
    )


def _make_finding(pattern_id: str, source_arn: str, target_arn: str) -> Finding:
    """Build a real Finding for tests that need to verify findings get combined."""
    return Finding(
        pattern_id=pattern_id,
        pattern_version="1.0.0",
        source=NodeRef(
            provider=PROVIDER_AWS,
            node_type=NODE_TYPE_IAM_USER,
            provider_id=source_arn,
        ),
        target=NodeRef(
            provider=PROVIDER_AWS,
            node_type=NODE_TYPE_IAM_ROLE,
            provider_id=target_arn,
        ),
        verdict=Verdict.INCONCLUSIVE,
        severity=SEVERITY_MEDIUM,
        title=f"{pattern_id} test finding",
        required_checks=(
            Check(
                name="test_check",
                description="test",
                state=CheckState.UNKNOWN,
                evidence_refs=(),
                reason="test",
            ),
        ),
        blockers_observed=(),
        assumptions=(),
        evidence=EvidenceBundle(
            statement_digests=(),
            statement_sources={},
            edge_refs=(),
            constraint_refs=(),
            edge_constraint_refs=(),
            node_refs=(),
            condition_context_assumed=(),
            reasoning_trace=(TraceEntry(step=1, action="test", inputs=(), result="UNKNOWN", reason="test"),),
        ),
        scenario_hash="deadbeef" * 8,
    )


class _AlwaysSkipReasoner:
    """preconditions_met returns False — should be skipped by run_all."""

    pattern_id = "test.always_skip"
    pattern_version = "1.0.0"
    pattern_title = "Always Skip"
    severity_default = "low"

    def preconditions_met(self, facts: FactGraph) -> tuple[bool, str]:
        return (False, "intentionally skipped for testing")

    def run(self, facts: FactGraph) -> list[Finding]:
        # If this is called, the test fails — preconditions said skip.
        raise AssertionError("_AlwaysSkipReasoner.run should never be called when preconditions_met returns False")


class _AlwaysRunReasoner:
    """preconditions_met returns True — emits one finding."""

    pattern_id = "test.always_run"
    pattern_version = "1.0.0"
    pattern_title = "Always Run"
    severity_default = "medium"

    def preconditions_met(self, facts: FactGraph) -> tuple[bool, str]:
        return (True, "")

    def run(self, facts: FactGraph) -> list[Finding]:
        return [
            _make_finding(
                self.pattern_id,
                "arn:aws:iam::111:user/Alice",
                "arn:aws:iam::222:role/Target",
            ),
        ]


class _SecondAlwaysRunReasoner:
    """A second always-running reasoner with a different pattern_id.

    Used to verify run_all combines findings from multiple reasoners
    in registration order.
    """

    pattern_id = "test.always_run_two"
    pattern_version = "1.0.0"
    pattern_title = "Always Run Two"
    severity_default = "medium"

    def preconditions_met(self, facts: FactGraph) -> tuple[bool, str]:
        return (True, "")

    def run(self, facts: FactGraph) -> list[Finding]:
        return [
            _make_finding(
                self.pattern_id,
                "arn:aws:iam::111:user/Bob",
                "arn:aws:iam::222:role/Target",
            ),
        ]


class _RaisingReasoner:
    """run() raises ReasonerError — should propagate, not be swallowed."""

    pattern_id = "test.raises"
    pattern_version = "1.0.0"
    pattern_title = "Raises ReasonerError"
    severity_default = "high"

    def preconditions_met(self, facts: FactGraph) -> tuple[bool, str]:
        return (True, "")

    def run(self, facts: FactGraph) -> list[Finding]:
        raise ReasonerError("test reasoner intentional failure")


class TestRegistryConstruction:
    """Empty registry behavior."""

    def test_empty_registry_has_zero_length(self) -> None:
        registry = Registry()
        assert len(registry) == 0

    def test_empty_registry_lists_nothing(self) -> None:
        registry = Registry()
        assert registry.list_reasoners() == ()

    def test_empty_registry_run_all_returns_empty(self) -> None:
        registry = Registry()
        assert registry.run_all(_empty_facts()) == []


class TestRegistryRegistration:
    """register adds reasoners with conformance and uniqueness checks."""

    def test_register_conforming_reasoner(self) -> None:
        registry = Registry()
        registry.register(_ConformingReasoner())
        assert len(registry) == 1
        assert "test.conforming" in registry

    def test_register_multiple_preserves_order(self) -> None:
        """list_reasoners returns reasoners in registration order."""
        registry = Registry()
        first = _AlwaysRunReasoner()
        second = _SecondAlwaysRunReasoner()
        registry.register(first)
        registry.register(second)
        result = registry.list_reasoners()
        assert len(result) == 2
        assert result[0] is first
        assert result[1] is second

    def test_register_duplicate_pattern_id_rejected(self) -> None:
        """Two reasoners with the same pattern_id cannot coexist."""
        registry = Registry()
        registry.register(_AlwaysRunReasoner())
        with pytest.raises(ValueError, match="already registered"):
            registry.register(_AlwaysRunReasoner())

    def test_register_non_reasoner_rejected(self) -> None:
        """A class missing required attributes is rejected at register time."""

        class NotAReasoner:
            """Missing every required attribute."""

        registry = Registry()
        with pytest.raises(TypeError, match="Reasoner Protocol implementer"):
            registry.register(NotAReasoner())  # type: ignore[arg-type]

    def test_get_returns_registered_reasoner(self) -> None:
        registry = Registry()
        reasoner = _AlwaysRunReasoner()
        registry.register(reasoner)
        assert registry.get("test.always_run") is reasoner

    def test_get_returns_none_for_missing(self) -> None:
        registry = Registry()
        assert registry.get("test.nonexistent") is None


class TestRegistryRunAll:
    """run_all calls preconditions_met and run on each reasoner."""

    def test_skips_reasoner_with_failed_preconditions(self) -> None:
        """A reasoner with preconditions_met == (False, ...) is skipped.

        Per plan: 'absence of reasoning is not a finding.' The skipped
        reasoner contributes zero findings, and crucially run() is
        never called. The _AlwaysSkipReasoner stub raises an
        AssertionError if its run is invoked, so this test will fail
        loudly if the registry incorrectly invokes run on a skipped
        reasoner.
        """
        registry = Registry()
        registry.register(_AlwaysSkipReasoner())
        result = registry.run_all(_empty_facts())
        assert result == []

    def test_runs_reasoner_with_passing_preconditions(self) -> None:
        """A reasoner with preconditions_met == (True, ...) is run."""
        registry = Registry()
        registry.register(_AlwaysRunReasoner())
        result = registry.run_all(_empty_facts())
        assert len(result) == 1
        assert result[0].pattern_id == "test.always_run"

    def test_combines_findings_from_multiple_reasoners(self) -> None:
        """Findings from all reasoners are returned in registration order."""
        registry = Registry()
        registry.register(_AlwaysRunReasoner())
        registry.register(_SecondAlwaysRunReasoner())
        result = registry.run_all(_empty_facts())
        assert len(result) == 2
        assert result[0].pattern_id == "test.always_run"
        assert result[1].pattern_id == "test.always_run_two"

    def test_skipped_reasoner_does_not_affect_others(self) -> None:
        """A skipped reasoner does not block other reasoners from running."""
        registry = Registry()
        registry.register(_AlwaysSkipReasoner())
        registry.register(_AlwaysRunReasoner())
        result = registry.run_all(_empty_facts())
        assert len(result) == 1
        assert result[0].pattern_id == "test.always_run"

    def test_reasoner_error_propagates(self) -> None:
        """A reasoner raising ReasonerError stops run_all immediately."""
        registry = Registry()
        registry.register(_RaisingReasoner())
        with pytest.raises(ReasonerError, match="intentional failure"):
            registry.run_all(_empty_facts())

    def test_reasoner_error_propagates_through_other_registered(self) -> None:
        """ReasonerError from one reasoner halts the loop — later reasoners
        do not run. The CLI layer (S14) decides whether to retry without
        the failing reasoner.
        """
        registry = Registry()
        registry.register(_RaisingReasoner())
        registry.register(_AlwaysRunReasoner())  # would emit a finding if reached
        with pytest.raises(ReasonerError):
            registry.run_all(_empty_facts())
