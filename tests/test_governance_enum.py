"""GC-1 closed governance enum tests.

Verifies that EdgeConstraint enforces governance_confidence ∈
GOVERNANCE_CONFIDENCE_VALUES at construction time, and that the
GOVERNANCE_CONFIDENCE_VALUES / ENRICHMENT_CONFIDENCE_VALUES frozensets
are closed sets matching the documented S07 contract.

Pre-S07 the field was an open string and ghostgates leaked its
enrichment-specific values ("compromised", "externally_validated") into
the same key the SCP/boundary binders wrote ("complete", "partial",
"needs_review"). After GC-1 those two value spaces are physically
separated: governance_confidence is closed at the EdgeConstraint level,
enrichment_confidence lives on EnrichmentResult under its own sidecar key.
"""

from __future__ import annotations

import pytest

from iamscope.constants import (
    ENRICHMENT_CONFIDENCE_COMPROMISED,
    ENRICHMENT_CONFIDENCE_EXTERNALLY_VALIDATED,
    ENRICHMENT_CONFIDENCE_VALUES,
    GOVERNANCE_CONFIDENCE_COMPLETE,
    GOVERNANCE_CONFIDENCE_NEEDS_REVIEW,
    GOVERNANCE_CONFIDENCE_PARTIAL,
    GOVERNANCE_CONFIDENCE_VALUES,
)
from iamscope.models import EdgeConstraint


def _make_ec(governance_confidence: str) -> EdgeConstraint:
    """Construct a minimal EdgeConstraint with the given confidence value."""
    return EdgeConstraint(
        edge_id="edge_x",
        constraint_id="constraint_x",
        governance_confidence=governance_confidence,
        likely_blocking=False,
        binding_reason="test",
    )


class TestEdgeConstraintGovernanceValidator:
    """EdgeConstraint.__post_init__ rejects open-string governance_confidence values."""

    def test_accepts_complete(self) -> None:
        """The 'complete' value is in the closed set."""
        ec = _make_ec(GOVERNANCE_CONFIDENCE_COMPLETE)
        assert ec.governance_confidence == "complete"

    def test_accepts_partial(self) -> None:
        """The 'partial' value is in the closed set."""
        ec = _make_ec(GOVERNANCE_CONFIDENCE_PARTIAL)
        assert ec.governance_confidence == "partial"

    def test_accepts_needs_review(self) -> None:
        """The 'needs_review' value is in the closed set."""
        ec = _make_ec(GOVERNANCE_CONFIDENCE_NEEDS_REVIEW)
        assert ec.governance_confidence == "needs_review"

    def test_rejects_invalid_value(self) -> None:
        """An arbitrary unknown string raises ValueError."""
        with pytest.raises(ValueError, match="governance_confidence must be one of"):
            _make_ec("not_a_real_value")

    def test_rejects_empty_string(self) -> None:
        """Empty string is not in the closed set."""
        with pytest.raises(ValueError, match="governance_confidence must be one of"):
            _make_ec("")

    def test_rejects_legacy_compromised(self) -> None:
        """'compromised' is the GC-1 root cause — must be rejected on EdgeConstraint.

        Pre-S07 ghostgates wrote this value into the same field, creating
        an open enum. The validator's whole purpose is to prevent this.
        """
        with pytest.raises(ValueError, match="EnrichmentResult.enrichment_confidence"):
            _make_ec(ENRICHMENT_CONFIDENCE_COMPROMISED)

    def test_rejects_legacy_externally_validated(self) -> None:
        """The other ghostgates value must also be rejected."""
        with pytest.raises(ValueError, match="EnrichmentResult.enrichment_confidence"):
            _make_ec(ENRICHMENT_CONFIDENCE_EXTERNALLY_VALIDATED)


class TestClosedEnumFrozensets:
    """The two closed-enum frozensets contain exactly the documented values."""

    def test_governance_confidence_values_is_closed(self) -> None:
        """GOVERNANCE_CONFIDENCE_VALUES contains exactly the 3 documented values."""
        assert (
            frozenset(
                {
                    "complete",
                    "partial",
                    "needs_review",
                }
            )
            == GOVERNANCE_CONFIDENCE_VALUES
        )
        # Tighten: no overlap with ghostgates values.
        assert "compromised" not in GOVERNANCE_CONFIDENCE_VALUES
        assert "externally_validated" not in GOVERNANCE_CONFIDENCE_VALUES

    def test_enrichment_confidence_values_is_closed(self) -> None:
        """ENRICHMENT_CONFIDENCE_VALUES contains exactly the 2 ghostgates values."""
        assert (
            frozenset(
                {
                    "compromised",
                    "externally_validated",
                }
            )
            == ENRICHMENT_CONFIDENCE_VALUES
        )
        # Tighten: no overlap with governance values.
        assert "complete" not in ENRICHMENT_CONFIDENCE_VALUES
        assert "partial" not in ENRICHMENT_CONFIDENCE_VALUES
        assert "needs_review" not in ENRICHMENT_CONFIDENCE_VALUES
