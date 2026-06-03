"""S09 tests: finding_id() formula determinism and version-bump semantics.

Per plan §3.3:
- finding_id is deterministic: same inputs → same output across runs.
- pattern_version is part of the formula. Bumping it forces a new ID even
  when scenario data is unchanged. This is how reasoner logic changes
  appear in findings_diff (S11+) as old_id deleted + new_id added rather
  than silently changing the verdict on the same ID.
- evidence_bundle_digest is part of the formula. Two findings with the
  same (pattern, source, target) but different evidence get different IDs.
"""

from __future__ import annotations

import pytest

from iamscope.identity.deterministic_ids import finding_id

# Canonical fixture used across multiple tests.
_PATTERN_ID = "passrole_lambda"
_PATTERN_VERSION = "1.0.0"
_SOURCE_ARN = "arn:aws:iam::111111\u003111111:user/Alice"
_TARGET_ARN = "arn:aws:iam::222222\u003222222:role/ProdAdmin"
_BUNDLE_DIGEST = "a" * 64  # placeholder SHA-256 hex string


def _is_sha256_hex(s: str) -> bool:
    """True if s is a lowercase 64-char hex string (matches canonical_id output)."""
    return isinstance(s, str) and len(s) == 64 and all(c in "0123456789abcdef" for c in s)


class TestFindingIdShape:
    """The output is a SHA-256 hex digest matching the canonical_id format."""

    def test_returns_64_char_hex(self) -> None:
        """finding_id returns a 64-character lowercase hex string."""
        fid = finding_id(
            _PATTERN_ID,
            _PATTERN_VERSION,
            _SOURCE_ARN,
            _TARGET_ARN,
            _BUNDLE_DIGEST,
        )
        assert _is_sha256_hex(fid)


class TestFindingIdDeterminism:
    """Same inputs → same output across calls. The headline guarantee."""

    def test_two_calls_same_inputs_same_output(self) -> None:
        """Calling finding_id twice with identical inputs yields identical output."""
        fid_a = finding_id(
            _PATTERN_ID,
            _PATTERN_VERSION,
            _SOURCE_ARN,
            _TARGET_ARN,
            _BUNDLE_DIGEST,
        )
        fid_b = finding_id(
            _PATTERN_ID,
            _PATTERN_VERSION,
            _SOURCE_ARN,
            _TARGET_ARN,
            _BUNDLE_DIGEST,
        )
        assert fid_a == fid_b

    def test_pinned_known_value(self) -> None:
        """Pin a specific known finding_id to catch any future formula change.

        If this hash changes, the deterministic ID algorithm has been
        modified — that is a BREAKING change because every existing
        findings.json file from a prior run is now invalidated. The
        canonical_id formula and the field ordering passed to it are
        load-bearing for cross-run comparisons.
        """
        fid = finding_id(
            _PATTERN_ID,
            _PATTERN_VERSION,
            _SOURCE_ARN,
            _TARGET_ARN,
            _BUNDLE_DIGEST,
        )
        # Computed via canonical_id("passrole_lambda", "1.0.0",
        #   "arn:aws:iam::111111 111111:user/alice",
        #   "arn:aws:iam::222222 222222:role/prodadmin", 64*"a")
        # using the sha256_null_separated_v2 algorithm. The v1→v2 bump
        # in v0.2.37 changed the `edge_id` formula only; `finding_id`'s
        # formula (pattern_id, pattern_version, source_provider_id,
        # target_provider_id, evidence_bundle_digest) is unchanged, so
        # this pinned expected hash is the same value it was under v1.
        # Re-pin if (and only if) the finding_id formula changes.
        expected = "c90dc2e7c4d121a092ffe76f16d408bda07ddaf87ced40af8a39510f1b207f17"
        assert fid == expected, (
            f"finding_id formula changed!\n"
            f"  Expected: {expected}\n"
            f"  Got:      {fid}\n"
            f"This is a BREAKING change to the deterministic ID algorithm. "
            f"Every existing findings.json file from a prior run is now "
            f"invalidated. Review carefully before re-pinning."
        )


class TestFindingIdSensitivity:
    """Each input field is load-bearing — changing any field changes the ID."""

    def test_pattern_id_change_changes_id(self) -> None:
        fid_a = finding_id(
            _PATTERN_ID,
            _PATTERN_VERSION,
            _SOURCE_ARN,
            _TARGET_ARN,
            _BUNDLE_DIGEST,
        )
        fid_b = finding_id(
            "cross_account_trust",
            _PATTERN_VERSION,
            _SOURCE_ARN,
            _TARGET_ARN,
            _BUNDLE_DIGEST,
        )
        assert fid_a != fid_b

    def test_pattern_version_change_changes_id(self) -> None:
        """Bumping pattern_version forces a new finding_id.

        This is the headline reasoner-versioning guarantee: when a
        reasoner bumps its version (because its logic changed), every
        finding it would emit gets a new ID. This is how findings_diff
        surfaces a reasoner change as old_id deleted + new_id added.
        """
        fid_a = finding_id(
            _PATTERN_ID,
            "1.0.0",
            _SOURCE_ARN,
            _TARGET_ARN,
            _BUNDLE_DIGEST,
        )
        fid_b = finding_id(
            _PATTERN_ID,
            "1.0.1",
            _SOURCE_ARN,
            _TARGET_ARN,
            _BUNDLE_DIGEST,
        )
        assert fid_a != fid_b

    def test_source_change_changes_id(self) -> None:
        fid_a = finding_id(
            _PATTERN_ID,
            _PATTERN_VERSION,
            _SOURCE_ARN,
            _TARGET_ARN,
            _BUNDLE_DIGEST,
        )
        fid_b = finding_id(
            _PATTERN_ID,
            _PATTERN_VERSION,
            "arn:aws:iam::111111\u003111111:user/Bob",
            _TARGET_ARN,
            _BUNDLE_DIGEST,
        )
        assert fid_a != fid_b

    def test_target_change_changes_id(self) -> None:
        fid_a = finding_id(
            _PATTERN_ID,
            _PATTERN_VERSION,
            _SOURCE_ARN,
            _TARGET_ARN,
            _BUNDLE_DIGEST,
        )
        fid_b = finding_id(
            _PATTERN_ID,
            _PATTERN_VERSION,
            _SOURCE_ARN,
            "arn:aws:iam::222222\u003222222:role/Other",
            _BUNDLE_DIGEST,
        )
        assert fid_a != fid_b

    def test_bundle_digest_change_changes_id(self) -> None:
        """Different evidence → different finding_id.

        Two reasoners that produce findings with the same (pattern, source,
        target) but different evidence (different statements cited,
        different edges examined) must produce different IDs. This
        prevents collision when a reasoner re-analyzes the same pair
        under expanded evidence (e.g., a new constraint that wasn't
        examined in the prior run).
        """
        fid_a = finding_id(
            _PATTERN_ID,
            _PATTERN_VERSION,
            _SOURCE_ARN,
            _TARGET_ARN,
            "a" * 64,
        )
        fid_b = finding_id(
            _PATTERN_ID,
            _PATTERN_VERSION,
            _SOURCE_ARN,
            _TARGET_ARN,
            "b" * 64,
        )
        assert fid_a != fid_b


class TestFindingIdValidation:
    """Empty fields are rejected (inherited from canonical_id)."""

    def test_rejects_empty_pattern_id(self) -> None:
        with pytest.raises(ValueError, match="empty after stripping"):
            finding_id("", _PATTERN_VERSION, _SOURCE_ARN, _TARGET_ARN, _BUNDLE_DIGEST)

    def test_rejects_empty_pattern_version(self) -> None:
        with pytest.raises(ValueError, match="empty after stripping"):
            finding_id(_PATTERN_ID, "", _SOURCE_ARN, _TARGET_ARN, _BUNDLE_DIGEST)

    def test_rejects_empty_source(self) -> None:
        with pytest.raises(ValueError, match="empty after stripping"):
            finding_id(_PATTERN_ID, _PATTERN_VERSION, "", _TARGET_ARN, _BUNDLE_DIGEST)

    def test_rejects_empty_target(self) -> None:
        with pytest.raises(ValueError, match="empty after stripping"):
            finding_id(_PATTERN_ID, _PATTERN_VERSION, _SOURCE_ARN, "", _BUNDLE_DIGEST)

    def test_rejects_empty_bundle_digest(self) -> None:
        with pytest.raises(ValueError, match="empty after stripping"):
            finding_id(_PATTERN_ID, _PATTERN_VERSION, _SOURCE_ARN, _TARGET_ARN, "")
