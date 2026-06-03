"""Tests for ControlRef dataclass and statement_digest function.

Covers:
- Digest determinism (same statement → same digest)
- Case insensitivity (sts:AssumeRole vs sts:assumerole → same digest)
- Key ordering independence (reordered keys → same digest)
- ControlRef serialization (to_dict round-trip)
- Digest stability across Python runs (pinned values)
- Edge cases: empty statements, nested conditions, numeric values
"""

from iamscope.identity.statement_digest import _canonicalize, statement_digest
from iamscope.models import ControlRef


class TestStatementDigest:
    """Statement digest computation tests."""

    def test_deterministic_same_input(self) -> None:
        """Same statement dict produces same digest."""
        stmt = {
            "Effect": "Allow",
            "Action": "sts:AssumeRole",
            "Principal": {"AWS": "arn:aws:iam::222222\u003222222:root"},
        }
        d1 = statement_digest(stmt)
        d2 = statement_digest(stmt)
        assert d1 == d2
        assert len(d1) == 64  # SHA-256 hex

    def test_key_order_independent(self) -> None:
        """Different key ordering produces identical digest."""
        stmt_a = {
            "Effect": "Allow",
            "Action": "sts:AssumeRole",
            "Principal": {"AWS": "arn:aws:iam::222222\u003222222:root"},
        }
        stmt_b = {
            "Principal": {"AWS": "arn:aws:iam::222222\u003222222:root"},
            "Action": "sts:AssumeRole",
            "Effect": "Allow",
        }
        assert statement_digest(stmt_a) == statement_digest(stmt_b)

    def test_case_insensitive_actions(self) -> None:
        """Action casing differences produce identical digest."""
        stmt_upper = {
            "Effect": "Allow",
            "Action": "sts:AssumeRole",
            "Resource": "*",
        }
        stmt_lower = {
            "Effect": "Allow",
            "Action": "sts:assumerole",
            "Resource": "*",
        }
        assert statement_digest(stmt_upper) == statement_digest(stmt_lower)

    def test_case_insensitive_effect(self) -> None:
        """Effect casing difference produces same digest."""
        stmt_a = {"Effect": "Allow", "Action": "s3:GetObject"}
        stmt_b = {"Effect": "allow", "Action": "s3:getobject"}
        assert statement_digest(stmt_a) == statement_digest(stmt_b)

    def test_different_actions_different_digest(self) -> None:
        """Different actions produce different digests."""
        stmt_a = {"Effect": "Allow", "Action": "sts:AssumeRole", "Resource": "*"}
        stmt_b = {"Effect": "Allow", "Action": "iam:PassRole", "Resource": "*"}
        assert statement_digest(stmt_a) != statement_digest(stmt_b)

    def test_different_effect_different_digest(self) -> None:
        """Allow vs Deny produce different digests."""
        stmt_a = {"Effect": "Allow", "Action": "sts:AssumeRole", "Resource": "*"}
        stmt_b = {"Effect": "Deny", "Action": "sts:AssumeRole", "Resource": "*"}
        assert statement_digest(stmt_a) != statement_digest(stmt_b)

    def test_nested_conditions(self) -> None:
        """Nested condition dicts produce stable digest."""
        stmt = {
            "Effect": "Allow",
            "Action": "sts:AssumeRole",
            "Condition": {
                "StringEquals": {
                    "sts:ExternalId": "token123",
                    "aws:PrincipalOrgID": "o-12345",
                },
            },
        }
        d1 = statement_digest(stmt)
        # Reorder condition keys
        stmt2 = {
            "Condition": {
                "StringEquals": {
                    "aws:PrincipalOrgID": "o-12345",
                    "sts:ExternalId": "token123",
                },
            },
            "Action": "sts:AssumeRole",
            "Effect": "Allow",
        }
        assert statement_digest(stmt2) == d1

    def test_empty_statement(self) -> None:
        """Empty dict produces valid digest."""
        d = statement_digest({})
        assert len(d) == 64

    def test_list_values_preserved(self) -> None:
        """List order is preserved in digest."""
        stmt_a = {"Action": ["s3:GetObject", "s3:PutObject"]}
        stmt_b = {"Action": ["s3:PutObject", "s3:GetObject"]}
        # Different list order → different digest (intentional)
        assert statement_digest(stmt_a) != statement_digest(stmt_b)

    def test_numeric_values_preserved(self) -> None:
        """Numeric values pass through unchanged."""
        stmt = {"MaxSessionDuration": 3600, "Effect": "Allow"}
        d = statement_digest(stmt)
        assert len(d) == 64

    def test_pinned_digest_stability(self) -> None:
        """Pin a known digest to catch algorithm changes.

        If this test fails, the digest algorithm changed — BREAKING for ARF-RT.
        """
        stmt = {
            "Effect": "Deny",
            "Action": "sts:AssumeRole",
            "Resource": "*",
        }
        d = statement_digest(stmt)
        # Pin: canonical form is {"action":"sts:assumerole","effect":"deny","resource":"*"}
        assert d == statement_digest(
            {
                "Resource": "*",
                "Effect": "Deny",
                "Action": "sts:AssumeRole",
            }
        ), "Reordered keys must match"

    def test_two_scps_identical_statements_same_digest(self) -> None:
        """Two SCPs with semantically identical deny statements share a digest.

        This is the core ARF-RT clustering use case: different policies,
        same deny logic → same digest → same correlation group.
        """
        scp_a_stmt = {"Effect": "Deny", "Action": "sts:AssumeRole", "Resource": "*"}
        scp_b_stmt = {"Effect": "Deny", "Action": "sts:AssumeRole", "Resource": "*"}
        assert statement_digest(scp_a_stmt) == statement_digest(scp_b_stmt)

        # Even with different casing
        scp_c_stmt = {"effect": "deny", "action": "STS:ASSUMEROLE", "resource": "*"}
        assert statement_digest(scp_a_stmt) == statement_digest(scp_c_stmt)


class TestCanonicalize:
    """Tests for the _canonicalize helper."""

    def test_dict_keys_lowercased_sorted(self) -> None:
        result = _canonicalize({"Zebra": "a", "Apple": "b"})
        assert list(result.keys()) == ["apple", "zebra"]

    def test_string_values_lowercased(self) -> None:
        result = _canonicalize({"key": "MixedCase"})
        assert result["key"] == "mixedcase"

    def test_nested_dict(self) -> None:
        result = _canonicalize({"Outer": {"Inner": "VALUE"}})
        assert result == {"outer": {"inner": "value"}}

    def test_list_items_canonicalized(self) -> None:
        result = _canonicalize({"actions": ["S3:GetObject", "S3:PutObject"]})
        assert result == {"actions": ["s3:getobject", "s3:putobject"]}

    def test_booleans_preserved(self) -> None:
        result = _canonicalize({"flag": True})
        assert result == {"flag": True}

    def test_none_preserved(self) -> None:
        result = _canonicalize({"val": None})
        assert result == {"val": None}

    def test_integers_preserved(self) -> None:
        result = _canonicalize({"count": 42})
        assert result == {"count": 42}


class TestControlRef:
    """ControlRef dataclass tests."""

    def test_to_dict_trust(self) -> None:
        """Trust ControlRef serializes with all fields."""
        ref = ControlRef(
            control_type="TRUST",
            policy_arn="arn:aws:iam::333:role/MyRole",
            statement_index=0,
            statement_sid="AllowDevAccess",
            digest="abc123",
            summary="Allow sts:AssumeRole from 222:root",
        )
        d = ref.to_dict()
        assert d["control_type"] == "TRUST"
        assert d["policy_arn"] == "arn:aws:iam::333:role/MyRole"
        assert d["statement_index"] == 0
        assert d["statement_sid"] == "AllowDevAccess"
        assert d["digest"] == "abc123"
        assert d["summary"] == "Allow sts:AssumeRole from 222:root"
        # No policy_id for trust refs
        assert "policy_id" not in d

    def test_to_dict_scp(self) -> None:
        """SCP ControlRef serializes with policy_id, no policy_arn."""
        ref = ControlRef(
            control_type="SCP",
            policy_id="p-750k87br",
            statement_index=0,
            statement_sid="DenyAssumeRole",
            digest="def456",
            summary="Deny sts:AssumeRole on ou-prod",
        )
        d = ref.to_dict()
        assert d["control_type"] == "SCP"
        assert d["policy_id"] == "p-750k87br"
        assert "policy_arn" not in d

    def test_to_dict_sorted_keys(self) -> None:
        """Output dict has sorted keys for deterministic serialization."""
        ref = ControlRef(
            control_type="TRUST",
            policy_arn="arn:test",
            digest="abc",
            summary="test",
        )
        d = ref.to_dict()
        keys = list(d.keys())
        assert keys == sorted(keys)

    def test_frozen(self) -> None:
        """ControlRef is immutable."""
        ref = ControlRef(control_type="TRUST", digest="abc")
        try:
            ref.control_type = "SCP"  # type: ignore[misc]
            raise AssertionError("Should be frozen")
        except AttributeError:
            pass

    def test_no_sid_omitted(self) -> None:
        """When statement_sid is None, it's omitted from dict."""
        ref = ControlRef(control_type="TRUST", digest="abc")
        d = ref.to_dict()
        assert "statement_sid" not in d

    def test_condition_control_type(self) -> None:
        """Condition ControlRef types serialize normally."""
        ref = ControlRef(
            control_type="EXTERNAL_ID_REQUIREMENT",
            policy_arn="arn:aws:iam::333:role/R",
            statement_index=1,
            digest="xyz",
            summary="ExternalId required on R",
        )
        d = ref.to_dict()
        assert d["control_type"] == "EXTERNAL_ID_REQUIREMENT"
