"""Tests for deterministic ID generation.

Tests verify the pinned sha256_null_separated_v3_case_sensitive_provider_ids algorithm:
- Same input → same output (stability)
- Different input → different output (uniqueness)
- `canonical_id` remains legacy case insensitive
- `node_id` and `edge_id` preserve provider-owned identity field case
- Whitespace insensitive (stripped before hashing)
- Stable formula (known input → known hash, pinned across versions)
- Edge ID uses correct component fields (v2+ includes
  features_digest as the fifth field)
- Constraint ID includes statement_id per R14

v2 bumped from v1 in v0.2.37 to address reviewer Top 10 #2 —
edge_ids in v1 did not include the features dict, so
MFA-conditioned and unconditioned trust edges between the same
principals collided on a single edge_id. Deeper rationale in
`iamscope.identity.deterministic_ids` module docstring.
"""

import hashlib

import pytest

from iamscope.constants import ID_ALGORITHM
from iamscope.identity.deterministic_ids import (
    canonical_id,
    constraint_id,
    edge_constraint_sort_key,
    edge_id,
    node_id,
)


class TestCanonicalId:
    """Tests for the core canonical_id function."""

    def test_same_input_same_output(self) -> None:
        """Identical inputs must produce identical IDs across calls."""
        id1 = canonical_id("aws", "IAMRole", "arn:aws:iam::111111\u003111111:role/Test")
        id2 = canonical_id("aws", "IAMRole", "arn:aws:iam::111111\u003111111:role/Test")
        assert id1 == id2
        assert len(id1) == 64  # SHA-256 hex digest

    def test_different_input_different_output(self) -> None:
        """Different inputs must produce different IDs."""
        id1 = canonical_id("aws", "IAMRole", "arn:aws:iam::111111\u003111111:role/RoleA")
        id2 = canonical_id("aws", "IAMRole", "arn:aws:iam::111111\u003111111:role/RoleB")
        assert id1 != id2

    def test_case_insensitive(self) -> None:
        """IDs must be case-insensitive (all fields lowercased)."""
        id_lower = canonical_id("aws", "iamrole", "arn:aws:iam::111111\u003111111:role/test")
        id_upper = canonical_id("AWS", "IAMRole", "arn:aws:iam::111111\u003111111:role/Test")
        id_mixed = canonical_id("Aws", "IamRole", "ARN:AWS:IAM::111111\u003111111:ROLE/TEST")
        assert id_lower == id_upper == id_mixed

    def test_whitespace_insensitive(self) -> None:
        """Leading/trailing whitespace must be stripped before hashing."""
        id_clean = canonical_id("aws", "IAMRole", "arn:aws:iam::111111\u003111111:role/Test")
        id_padded = canonical_id("  aws  ", "  IAMRole  ", "  arn:aws:iam::111111\u003111111:role/Test  ")
        assert id_clean == id_padded

    def test_stable_known_hash(self) -> None:
        """Known input must produce a known hash — pinned across versions.

        This test catches accidental changes to the hashing algorithm.
        If this test fails, the ID algorithm has been modified, which
        breaks ARF-RT references and cross-run comparisons.
        """
        # Manually compute expected hash
        canonical = "\x00".join(["aws", "iamrole", "arn:aws:iam::333333\u003333333:role/proddeployrole"])
        expected = hashlib.sha256(canonical.encode("utf-8")).hexdigest()

        actual = canonical_id("aws", "IAMRole", "arn:aws:iam::333333\u003333333:role/ProdDeployRole")
        assert actual == expected

    def test_null_separator_not_in_arns(self) -> None:
        """NULL byte separator must not collide with field content.

        The NULL byte (\\x00) cannot appear in ARNs, policy IDs, or
        any other field value, so it's a safe separator.
        """
        # These would collide without a separator:
        # ("a", "bc") vs ("ab", "c")
        id1 = canonical_id("a", "bc")
        id2 = canonical_id("ab", "c")
        assert id1 != id2

    def test_rejects_empty_fields(self) -> None:
        """Empty fields after stripping must raise ValueError."""
        with pytest.raises(ValueError, match="empty after stripping"):
            canonical_id("aws", "", "arn:aws:iam::111:role/Test")

        with pytest.raises(ValueError, match="empty after stripping"):
            canonical_id("aws", "   ", "arn:aws:iam::111:role/Test")

    def test_rejects_non_string_fields(self) -> None:
        """Non-string fields must raise ValueError."""
        with pytest.raises(ValueError, match="must be a string"):
            canonical_id("aws", "IAMRole", 12345)  # type: ignore[arg-type]

    def test_rejects_no_fields(self) -> None:
        """No fields must raise ValueError."""
        with pytest.raises(ValueError, match="at least one field"):
            canonical_id()


class TestNodeId:
    """Tests for node_id formula with case-preserved provider_id."""

    def test_node_id_components(self) -> None:
        """node_id must use (provider, node_type, provider_id)."""
        nid = node_id("aws", "IAMRole", "arn:aws:iam::111111\u003111111:role/TestRole")
        canonical = "\x00".join(["aws", "iamrole", "arn:aws:iam::111111\u003111111:role/TestRole"])
        expected = hashlib.sha256(canonical.encode("utf-8")).hexdigest()
        assert nid == expected

    def test_different_node_types_different_ids(self) -> None:
        """Same provider_id with different node_type must produce different IDs."""
        role_id = node_id("aws", "IAMRole", "arn:aws:iam::111:role/Test")
        user_id = node_id("aws", "IAMUser", "arn:aws:iam::111:role/Test")
        assert role_id != user_id

    def test_provider_id_case_is_preserved(self) -> None:
        """v3 keeps provider-owned identity field case in node IDs."""
        role_upper = node_id("aws", "IAMRole", "arn:aws:iam::000000000000:role/CaseRole")
        role_lower = node_id("aws", "IAMRole", "arn:aws:iam::000000000000:role/caserole")
        assert role_upper != role_lower

    def test_structural_fields_remain_case_normalized(self) -> None:
        """Provider and node_type remain structural, case-normalized fields."""
        lower_structural = node_id("aws", "iamrole", "arn:aws:iam::000000000000:role/CaseRole")
        mixed_structural = node_id("AWS", "IAMRole", "arn:aws:iam::000000000000:role/CaseRole")
        assert lower_structural == mixed_structural


class TestEdgeId:
    """Tests for edge_id formula with case-preserved src/dst provider IDs."""

    # Empty-features digest: canonical_json_bytes({}).decode("utf-8") == "{}"
    # Used as a stable "no features" placeholder in these unit tests so
    # the other fields remain the dimension under test.
    _EMPTY_FEATURES_DIGEST = "{}"

    def test_edge_id_components(self) -> None:
        """edge_id must use (edge_type, src_provider_id, dst_provider_id,
        region, features_digest)."""
        eid = edge_id(
            "sts:AssumeRole_trust",
            "arn:aws:iam::222222\u003222222:role/DevJump",
            "arn:aws:iam::333333\u003333333:role/ProdDeploy",
            "-",
            self._EMPTY_FEATURES_DIGEST,
        )
        canonical = "\x00".join(
            [
                "sts:assumerole_trust",
                "arn:aws:iam::222222\u003222222:role/DevJump",
                "arn:aws:iam::333333\u003333333:role/ProdDeploy",
                "-",
                self._EMPTY_FEATURES_DIGEST,
            ]
        )
        expected = hashlib.sha256(canonical.encode("utf-8")).hexdigest()
        assert eid == expected

    def test_different_edge_types_different_ids(self) -> None:
        """Same src/dst/features with different edge_type must produce
        different IDs."""
        trust_id = edge_id(
            "sts:AssumeRole_trust",
            "arn:aws:iam::111:role/A",
            "arn:aws:iam::222:role/B",
            "-",
            self._EMPTY_FEATURES_DIGEST,
        )
        perm_id = edge_id(
            "sts:AssumeRole_permission",
            "arn:aws:iam::111:role/A",
            "arn:aws:iam::222:role/B",
            "-",
            self._EMPTY_FEATURES_DIGEST,
        )
        assert trust_id != perm_id

    def test_regional_edge_id(self) -> None:
        """Regional edges must include region in the ID."""
        global_id = edge_id(
            "lambda:InvokeFunction_trust",
            "arn:aws:iam::111:role/A",
            "arn:aws:lambda:us-east-1:111:function/MyFunc",
            "-",
            self._EMPTY_FEATURES_DIGEST,
        )
        regional_id = edge_id(
            "lambda:InvokeFunction_trust",
            "arn:aws:iam::111:role/A",
            "arn:aws:lambda:us-east-1:111:function/MyFunc",
            "us-east-1",
            self._EMPTY_FEATURES_DIGEST,
        )
        assert global_id != regional_id

    def test_source_provider_id_case_is_preserved(self) -> None:
        """v3 keeps source provider-owned identity field case in edge IDs."""
        upper_source = edge_id(
            "sts:AssumeRole_permission",
            "arn:aws:iam::000000000000:user/CaseUser",
            "arn:aws:iam::000000000000:role/TargetRole",
            "-",
            self._EMPTY_FEATURES_DIGEST,
        )
        lower_source = edge_id(
            "sts:AssumeRole_permission",
            "arn:aws:iam::000000000000:user/caseuser",
            "arn:aws:iam::000000000000:role/TargetRole",
            "-",
            self._EMPTY_FEATURES_DIGEST,
        )
        assert upper_source != lower_source

    def test_destination_provider_id_case_is_preserved(self) -> None:
        """v3 keeps destination provider-owned identity field case in edge IDs."""
        upper_destination = edge_id(
            "sts:AssumeRole_permission",
            "arn:aws:iam::000000000000:user/SourceUser",
            "arn:aws:iam::000000000000:role/CaseRole",
            "-",
            self._EMPTY_FEATURES_DIGEST,
        )
        lower_destination = edge_id(
            "sts:AssumeRole_permission",
            "arn:aws:iam::000000000000:user/SourceUser",
            "arn:aws:iam::000000000000:role/caserole",
            "-",
            self._EMPTY_FEATURES_DIGEST,
        )
        assert upper_destination != lower_destination

    def test_structural_fields_remain_case_normalized(self) -> None:
        """Edge type and region remain structural, case-normalized fields."""
        lower_structural = edge_id(
            "sts:assumerole_permission",
            "arn:aws:iam::000000000000:user/CaseUser",
            "arn:aws:iam::000000000000:role/CaseRole",
            "us-east-1",
            self._EMPTY_FEATURES_DIGEST,
        )
        mixed_structural = edge_id(
            "sts:AssumeRole_permission",
            "arn:aws:iam::000000000000:user/CaseUser",
            "arn:aws:iam::000000000000:role/CaseRole",
            "US-EAST-1",
            self._EMPTY_FEATURES_DIGEST,
        )
        assert lower_structural == mixed_structural


class TestConstraintId:
    """Tests for constraint_id formula including statement_id (R14)."""

    def test_constraint_id_includes_statement_id(self) -> None:
        """constraint_id must include statement_id to avoid collisions."""
        cid1 = constraint_id("aws", "SCP", "OU", "ou-abc", "p-123", "DenyAssumeRole")
        cid2 = constraint_id("aws", "SCP", "OU", "ou-abc", "p-123", "DenyS3")
        assert cid1 != cid2

    def test_constraint_id_same_statement_same_id(self) -> None:
        """Same inputs including statement_id must produce same ID."""
        cid1 = constraint_id("aws", "SCP", "OU", "ou-abc", "p-123", "stmt_0")
        cid2 = constraint_id("aws", "SCP", "OU", "ou-abc", "p-123", "stmt_0")
        assert cid1 == cid2

    def test_constraint_id_remains_legacy_case_normalized_pending_review(self) -> None:
        """Constraint IDs stay on the legacy lowercase canonicalization path."""
        cid_lower = constraint_id("aws", "scp", "ou", "ou-abc", "p-123", "case-sensitive-sid")
        cid_mixed = constraint_id("AWS", "SCP", "OU", "ou-abc", "p-123", "Case-Sensitive-Sid")
        assert cid_lower == cid_mixed


def test_id_algorithm_constant_is_v3_case_sensitive_provider_ids() -> None:
    assert ID_ALGORITHM == "sha256_null_separated_v3_case_sensitive_provider_ids"


class TestEdgeConstraintSortKey:
    """Tests for edge_constraint sort key."""

    def test_sort_key_tuple(self) -> None:
        """Sort key must be (edge_id, constraint_id) tuple."""
        key = edge_constraint_sort_key("aaa", "bbb")
        assert key == ("aaa", "bbb")

    def test_sort_key_ordering(self) -> None:
        """Sort keys must produce correct lexicographic ordering."""
        keys = [
            edge_constraint_sort_key("bbb", "aaa"),
            edge_constraint_sort_key("aaa", "bbb"),
            edge_constraint_sort_key("aaa", "aaa"),
        ]
        sorted_keys = sorted(keys)
        assert sorted_keys == [
            ("aaa", "aaa"),
            ("aaa", "bbb"),
            ("bbb", "aaa"),
        ]
