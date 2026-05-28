"""Tests for expansion controller — graph explosion controls.

Tests cover architecture doc Decision 5, §10.5:
- Default mode is warn
- Global mode applies to all edge types
- Type-specific overrides (passrole, lambda, ec2)
- check_expansion with warn mode emits no warnings for normal counts
- check_expansion with expand mode allows expansion
- >500 per expansion forces warn regardless of config
- skip mode returns skip
- MAX_TOTAL_EDGES hard limit enforced
- Edge count tracking across multiple registrations
- reset_count works
- Invalid mode values rejected
- Config dict serialization
"""

import pytest

from iamscope.constants import (
    EXPANSION_MODE_EXPAND,
    EXPANSION_MODE_SKIP,
    EXPANSION_MODE_WARN,
    MAX_EDGES_PER_EXPANSION,
    MAX_TOTAL_EDGES,
)
from iamscope.controls.expansion import ExpansionController, TotalEdgeLimitError


class TestDefaultBehavior:
    """Tests for default expansion controller configuration."""

    def test_default_mode_is_warn(self) -> None:
        """Default global mode is warn."""
        ec = ExpansionController()
        assert ec.global_mode == EXPANSION_MODE_WARN

    def test_default_get_mode_returns_warn(self) -> None:
        """get_mode returns warn for any edge type with defaults."""
        ec = ExpansionController()
        assert ec.get_mode("iam:PassRole_permission") == EXPANSION_MODE_WARN
        assert ec.get_mode("lambda:InvokeFunction_trust") == EXPANSION_MODE_WARN
        assert ec.get_mode("ec2:InstanceProfile_resolved") == EXPANSION_MODE_WARN
        assert ec.get_mode("sts:AssumeRole_trust") == EXPANSION_MODE_WARN


class TestGlobalMode:
    """Tests for global expansion mode."""

    def test_global_skip_applies_to_all(self) -> None:
        """Global skip mode applies to all edge types."""
        ec = ExpansionController(global_mode=EXPANSION_MODE_SKIP)
        assert ec.get_mode("iam:PassRole_permission") == EXPANSION_MODE_SKIP
        assert ec.get_mode("lambda:InvokeFunction_trust") == EXPANSION_MODE_SKIP

    def test_global_expand_applies_to_all(self) -> None:
        """Global expand mode applies to all edge types."""
        ec = ExpansionController(global_mode=EXPANSION_MODE_EXPAND)
        assert ec.get_mode("sts:AssumeRole_trust") == EXPANSION_MODE_EXPAND


class TestTypeSpecificOverrides:
    """Tests for type-specific mode overrides."""

    def test_passrole_override(self) -> None:
        """passrole_mode overrides global for PassRole edges."""
        ec = ExpansionController(global_mode=EXPANSION_MODE_WARN, passrole_mode=EXPANSION_MODE_SKIP)
        assert ec.get_mode("iam:PassRole_permission") == EXPANSION_MODE_SKIP
        # Non-PassRole still uses global
        assert ec.get_mode("sts:AssumeRole_trust") == EXPANSION_MODE_WARN

    def test_lambda_override(self) -> None:
        """lambda_mode overrides global for Lambda edges."""
        ec = ExpansionController(global_mode=EXPANSION_MODE_WARN, lambda_mode=EXPANSION_MODE_EXPAND)
        assert ec.get_mode("lambda:InvokeFunction_trust") == EXPANSION_MODE_EXPAND
        assert ec.get_mode("sts:AssumeRole_trust") == EXPANSION_MODE_WARN

    def test_ec2_override(self) -> None:
        """ec2_mode overrides global for EC2/InstanceProfile edges."""
        ec = ExpansionController(global_mode=EXPANSION_MODE_WARN, ec2_mode=EXPANSION_MODE_SKIP)
        assert ec.get_mode("ec2:InstanceProfile_resolved") == EXPANSION_MODE_SKIP
        assert ec.get_mode("sts:AssumeRole_trust") == EXPANSION_MODE_WARN

    def test_multiple_overrides(self) -> None:
        """Multiple type-specific overrides coexist."""
        ec = ExpansionController(
            global_mode=EXPANSION_MODE_WARN,
            passrole_mode=EXPANSION_MODE_SKIP,
            lambda_mode=EXPANSION_MODE_EXPAND,
            ec2_mode=EXPANSION_MODE_SKIP,
        )
        assert ec.get_mode("iam:PassRole_permission") == EXPANSION_MODE_SKIP
        assert ec.get_mode("lambda:InvokeFunction_trust") == EXPANSION_MODE_EXPAND
        assert ec.get_mode("ec2:InstanceProfile_resolved") == EXPANSION_MODE_SKIP
        assert ec.get_mode("sts:AssumeRole_trust") == EXPANSION_MODE_WARN


class TestCheckExpansion:
    """Tests for check_expansion with hard limit enforcement."""

    def test_warn_mode_normal_count(self) -> None:
        """Warn mode with normal count returns warn, no warnings."""
        ec = ExpansionController(global_mode=EXPANSION_MODE_WARN)
        mode, warnings = ec.check_expansion(50, "iam:PassRole_permission")
        assert mode == EXPANSION_MODE_WARN
        assert warnings == []

    def test_expand_mode_normal_count(self) -> None:
        """Expand mode with count under limit returns expand."""
        ec = ExpansionController(global_mode=EXPANSION_MODE_EXPAND)
        mode, warnings = ec.check_expansion(100, "iam:PassRole_permission")
        assert mode == EXPANSION_MODE_EXPAND
        assert warnings == []

    def test_expand_mode_at_limit(self) -> None:
        """Expand mode at exactly MAX_EDGES_PER_EXPANSION returns expand."""
        ec = ExpansionController(global_mode=EXPANSION_MODE_EXPAND)
        mode, warnings = ec.check_expansion(MAX_EDGES_PER_EXPANSION, "iam:PassRole_permission")
        assert mode == EXPANSION_MODE_EXPAND
        assert warnings == []

    def test_expand_mode_over_limit_forces_warn(self) -> None:
        """Expand mode with count > MAX_EDGES_PER_EXPANSION forced to warn."""
        ec = ExpansionController(global_mode=EXPANSION_MODE_EXPAND)
        mode, warnings = ec.check_expansion(501, "iam:PassRole_permission")
        assert mode == EXPANSION_MODE_WARN
        assert len(warnings) == 1
        assert "hard limit" in warnings[0].lower() or "501" in warnings[0]

    def test_skip_mode_ignores_count(self) -> None:
        """Skip mode always returns skip regardless of count."""
        ec = ExpansionController(global_mode=EXPANSION_MODE_SKIP)
        mode, warnings = ec.check_expansion(10000, "iam:PassRole_permission")
        assert mode == EXPANSION_MODE_SKIP
        assert warnings == []

    def test_warn_mode_over_limit_stays_warn(self) -> None:
        """Warn mode with count > limit stays warn (already the safest mode)."""
        ec = ExpansionController(global_mode=EXPANSION_MODE_WARN)
        mode, warnings = ec.check_expansion(501, "iam:PassRole_permission")
        assert mode == EXPANSION_MODE_WARN
        assert warnings == []  # Warn mode doesn't need to be forced


class TestTotalEdgeLimit:
    """Tests for MAX_TOTAL_EDGES hard limit enforcement."""

    def test_register_edges_tracks_count(self) -> None:
        """register_edges accumulates total count."""
        ec = ExpansionController()
        ec.register_edges(100)
        assert ec.total_edges == 100
        ec.register_edges(200)
        assert ec.total_edges == 300

    def test_total_limit_exceeded_raises(self) -> None:
        """Exceeding MAX_TOTAL_EDGES raises TotalEdgeLimitError."""
        ec = ExpansionController()
        ec.register_edges(MAX_TOTAL_EDGES)
        # At limit — no error yet
        assert ec.total_edges == MAX_TOTAL_EDGES

        # One more pushes over
        with pytest.raises(TotalEdgeLimitError) as exc_info:
            ec.register_edges(1)
        assert exc_info.value.current_count == MAX_TOTAL_EDGES + 1
        assert exc_info.value.limit == MAX_TOTAL_EDGES

    def test_reset_count(self) -> None:
        """reset_count clears the accumulator."""
        ec = ExpansionController()
        ec.register_edges(5000)
        ec.reset_count()
        assert ec.total_edges == 0


class TestValidation:
    """Tests for mode validation."""

    def test_invalid_global_mode_rejected(self) -> None:
        """Invalid global_mode raises ValueError."""
        with pytest.raises(ValueError, match="Invalid global_mode"):
            ExpansionController(global_mode="invalid")

    def test_invalid_override_mode_rejected(self) -> None:
        """Invalid type-specific mode raises ValueError."""
        with pytest.raises(ValueError, match="Invalid passrole_mode"):
            ExpansionController(passrole_mode="bad")


class TestConfigSerialization:
    """Tests for config dict serialization."""

    def test_config_dict_defaults(self) -> None:
        """Default config dict uses global mode for all types."""
        ec = ExpansionController()
        d = ec.to_config_dict()
        assert d["expansion_mode"] == EXPANSION_MODE_WARN
        assert d["passrole_mode"] == EXPANSION_MODE_WARN
        assert d["lambda_mode"] == EXPANSION_MODE_WARN
        assert d["ec2_mode"] == EXPANSION_MODE_WARN

    def test_config_dict_with_overrides(self) -> None:
        """Config dict reflects overrides."""
        ec = ExpansionController(
            global_mode=EXPANSION_MODE_WARN,
            passrole_mode=EXPANSION_MODE_SKIP,
        )
        d = ec.to_config_dict()
        assert d["expansion_mode"] == EXPANSION_MODE_WARN
        assert d["passrole_mode"] == EXPANSION_MODE_SKIP
        assert d["lambda_mode"] == EXPANSION_MODE_WARN
