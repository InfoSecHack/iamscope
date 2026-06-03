"""S09 tests: EvidenceBundle construction, bundle_digest stability, and
the local-scope §3.5 invariants (non-empty contiguous trace, statement
sources covers statement digests).

Cross-validation against `required_checks` is enforced at the Finding
level (test_verdict_enum.py — extended in S09 step 3 below).
"""

from __future__ import annotations

import pytest

from iamscope.reasoner.evidence import (
    EvidenceBundle,
    InvalidEvidenceError,
    TraceEntry,
)

# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


def _trace_entry(step: int = 1) -> TraceEntry:
    return TraceEntry(
        step=step,
        action="check_has_action",
        inputs=("arn:aws:iam::111111\u003111111:user/Alice", "iam:PassRole"),
        result="PASS",
        reason="inline policy grants exact resource ARN",
    )


def _make_bundle(
    *,
    statement_digests: tuple[str, ...] = ("digest_a",),
    statement_sources: dict | None = None,
    edge_refs: tuple[str, ...] = ("edge_x",),
    constraint_refs: tuple[str, ...] = (),
    edge_constraint_refs: tuple[str, ...] = (),
    node_refs: tuple[str, ...] = ("node_y",),
    condition_context_assumed: tuple = (),
    reasoning_trace: tuple[TraceEntry, ...] | None = None,
) -> EvidenceBundle:
    """Construct a minimal valid EvidenceBundle with sensible defaults."""
    if statement_sources is None:
        statement_sources = {d: ("arn:aws:iam::111111\u003111111:policy/test", 0, "stmt_0") for d in statement_digests}
    if reasoning_trace is None:
        reasoning_trace = (_trace_entry(1),)
    return EvidenceBundle(
        statement_digests=statement_digests,
        statement_sources=statement_sources,
        edge_refs=edge_refs,
        constraint_refs=constraint_refs,
        edge_constraint_refs=edge_constraint_refs,
        node_refs=node_refs,
        condition_context_assumed=condition_context_assumed,
        reasoning_trace=reasoning_trace,
    )


def _is_sha256_hex(s: str) -> bool:
    return isinstance(s, str) and len(s) == 64 and all(c in "0123456789abcdef" for c in s)


# ---------------------------------------------------------------------------
# Construction
# ---------------------------------------------------------------------------


class TestEvidenceBundleConstruction:
    """Minimal valid bundles construct without error."""

    def test_minimal_bundle_constructs(self) -> None:
        bundle = _make_bundle()
        assert bundle.statement_digests == ("digest_a",)
        assert len(bundle.reasoning_trace) == 1

    def test_bundle_with_multi_step_trace(self) -> None:
        bundle = _make_bundle(
            reasoning_trace=(
                _trace_entry(1),
                _trace_entry(2),
                _trace_entry(3),
            ),
        )
        assert len(bundle.reasoning_trace) == 3

    def test_bundle_with_no_statements_no_sources(self) -> None:
        """A bundle with zero statement digests has nothing for sources to cover."""
        bundle = _make_bundle(
            statement_digests=(),
            statement_sources={},
        )
        assert bundle.statement_digests == ()


# ---------------------------------------------------------------------------
# Invariant 2: non-empty contiguous trace
# ---------------------------------------------------------------------------


class TestTraceInvariants:
    """reasoning_trace must be non-empty with contiguous 1-based step values."""

    def test_empty_trace_rejected(self) -> None:
        """An empty trace is not a finding — invariant 2."""
        with pytest.raises(InvalidEvidenceError, match="reasoning_trace must be non-empty"):
            _make_bundle(reasoning_trace=())

    def test_non_contiguous_steps_rejected(self) -> None:
        """Skipping a step number is rejected."""
        with pytest.raises(InvalidEvidenceError, match="step values must be contiguous"):
            _make_bundle(
                reasoning_trace=(
                    _trace_entry(1),
                    _trace_entry(3),  # missing step 2
                ),
            )

    def test_zero_indexed_steps_rejected(self) -> None:
        """Step values must be 1-based, not 0-based."""
        with pytest.raises(InvalidEvidenceError, match="contiguous from 1"):
            _make_bundle(reasoning_trace=(_trace_entry(0),))

    def test_duplicated_step_rejected(self) -> None:
        """Step duplicates fail the contiguity check."""
        with pytest.raises(InvalidEvidenceError, match="contiguous"):
            _make_bundle(
                reasoning_trace=(_trace_entry(1), _trace_entry(1)),
            )


# ---------------------------------------------------------------------------
# Invariant 3: statement_sources covers statement_digests
# ---------------------------------------------------------------------------


class TestSourceCoverage:
    """Every statement_digest must have an entry in statement_sources."""

    def test_missing_source_rejected(self) -> None:
        """Citing a digest without a source locator → InvalidEvidenceError."""
        with pytest.raises(InvalidEvidenceError, match="must contain an entry for"):
            _make_bundle(
                statement_digests=("digest_a", "digest_b"),
                statement_sources={
                    "digest_a": ("policy_arn", 0, "stmt_0"),
                    # digest_b missing
                },
            )

    def test_extra_sources_allowed(self) -> None:
        """statement_sources may contain entries beyond statement_digests.

        Strict superset is allowed because a reasoner might know about
        sources it ultimately decided not to cite. Only the reverse
        direction is enforced.
        """
        bundle = _make_bundle(
            statement_digests=("digest_a",),
            statement_sources={
                "digest_a": ("policy_arn_a", 0, "stmt_0"),
                "digest_b": ("policy_arn_b", 1, "stmt_1"),  # extra
            },
        )
        # Should construct without error.
        assert "digest_a" in bundle.statement_sources


# ---------------------------------------------------------------------------
# bundle_digest determinism and shape
# ---------------------------------------------------------------------------


class TestBundleDigest:
    """bundle_digest is a deterministic SHA-256 hex."""

    def test_returns_sha256_hex(self) -> None:
        bundle = _make_bundle()
        assert _is_sha256_hex(bundle.bundle_digest)

    def test_two_constructions_same_digest(self) -> None:
        """Determinism: same inputs → same digest."""
        bundle_a = _make_bundle()
        bundle_b = _make_bundle()
        assert bundle_a.bundle_digest == bundle_b.bundle_digest

    def test_digest_stable_under_field_reordering(self) -> None:
        """Reordering order-insensitive fields doesn't change the digest.

        statement_digests, edge_refs, constraint_refs, etc. are all
        order-insensitive — the digest sorts them. A reasoner that builds
        the same evidence in two different orders must produce the same ID.
        """
        bundle_a = _make_bundle(
            edge_refs=("edge_a", "edge_b", "edge_c"),
        )
        bundle_b = _make_bundle(
            edge_refs=("edge_c", "edge_a", "edge_b"),
        )
        assert bundle_a.bundle_digest == bundle_b.bundle_digest

    def test_digest_changes_when_statement_digests_change(self) -> None:
        bundle_a = _make_bundle(
            statement_digests=("digest_a",),
            statement_sources={"digest_a": ("p", 0, "s")},
        )
        bundle_b = _make_bundle(
            statement_digests=("digest_b",),
            statement_sources={"digest_b": ("p", 0, "s")},
        )
        assert bundle_a.bundle_digest != bundle_b.bundle_digest

    def test_digest_changes_when_edge_refs_change(self) -> None:
        bundle_a = _make_bundle(edge_refs=("edge_x",))
        bundle_b = _make_bundle(edge_refs=("edge_y",))
        assert bundle_a.bundle_digest != bundle_b.bundle_digest

    def test_digest_changes_when_trace_action_changes(self) -> None:
        """Trace order is meaningful — changing the trace changes the digest."""
        trace_a = (TraceEntry(step=1, action="action_a", inputs=(), result="PASS", reason=""),)
        trace_b = (TraceEntry(step=1, action="action_b", inputs=(), result="PASS", reason=""),)
        bundle_a = _make_bundle(reasoning_trace=trace_a)
        bundle_b = _make_bundle(reasoning_trace=trace_b)
        assert bundle_a.bundle_digest != bundle_b.bundle_digest

    def test_digest_excludes_statement_sources(self) -> None:
        """statement_sources is EXCLUDED from the digest — presentation only.

        Including it would mean a finding's ID changes whenever AWS renames
        a managed policy or shifts a statement's index, which is not the
        semantic we want. The same digest content should produce the same
        finding ID even if the source locator metadata differs.
        """
        bundle_a = _make_bundle(
            statement_digests=("digest_a",),
            statement_sources={"digest_a": ("policy_arn_v1", 0, "stmt_0")},
        )
        bundle_b = _make_bundle(
            statement_digests=("digest_a",),
            statement_sources={"digest_a": ("policy_arn_v2", 99, "renamed_stmt")},
        )
        assert bundle_a.bundle_digest == bundle_b.bundle_digest

    def test_digest_excludes_trace_reason(self) -> None:
        """Trace `reason` field is presentation-only and excluded from digest.

        Two traces with identical structure but different `reason` strings
        produce the same digest. The `reason` field exists for human
        review; it must not affect finding identity.
        """
        trace_a = (TraceEntry(step=1, action="a", inputs=(), result="PASS", reason="short"),)
        trace_b = (TraceEntry(step=1, action="a", inputs=(), result="PASS", reason="much longer"),)
        bundle_a = _make_bundle(reasoning_trace=trace_a)
        bundle_b = _make_bundle(reasoning_trace=trace_b)
        assert bundle_a.bundle_digest == bundle_b.bundle_digest

    def test_digest_changes_when_assumption_changes(self) -> None:
        bundle_a = _make_bundle(
            condition_context_assumed=(("aws:RequestedRegion", "assumed us-east-1"),),
        )
        bundle_b = _make_bundle(
            condition_context_assumed=(("aws:RequestedRegion", "assumed eu-west-1"),),
        )
        assert bundle_a.bundle_digest != bundle_b.bundle_digest
