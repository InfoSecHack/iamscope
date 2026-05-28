"""Session 3: expansion mode enforcement for lambda/ec2 wildcard
permissions.

Reviewer Top 10 #3. The fix is in `iamscope/collector/passrole.py`:
`_get_expansion_edge_type()` now returns `"lambda"` and `"ec2"` for
those action families (previously fell through to `"permission"`),
and `_handle_wildcard_resource()` now consults the expansion
controller's mode BEFORE the BUG-022 non-role bypass, so
`lambda_mode="skip"` and `ec2_mode="skip"` suppress hyperedge
emission as operators expect.

Tests cover:
- skip mode → zero edges for lambda and ec2 actions
- warn mode → hyperedge emitted with correct markers
- None override → falls through to global_mode
"""

from __future__ import annotations

from iamscope.collector.passrole import build_permission_edges
from iamscope.constants import NODE_TYPE_HYPEREDGE, NODE_TYPE_IAM_USER
from iamscope.controls.expansion import ExpansionController
from iamscope.models import PermissionParseResult


def _make_pr(
    action: str = "lambda:InvokeFunction",
    resource: str = "*",
    is_wildcard: bool = True,
    source_arn: str = "arn:aws:iam::111111111111:user/Admin",
) -> PermissionParseResult:
    """Minimal PermissionParseResult for a wildcard lambda grant.
    Follows the test_passrole.py::_make_pr() convention."""
    return PermissionParseResult(
        statement_index=0,
        effect="Allow",
        action=action,
        resource_pattern=resource,
        is_wildcard_resource=is_wildcard,
        source_arn=source_arn,
        source_node_type=NODE_TYPE_IAM_USER,
        source_account_id="111111111111",
        policy_source="inline",
        policy_name="test-policy",
        action_matched_via="exact",
    )


class TestLambdaModeEnforcement:
    """Lambda-specific expansion mode enforcement."""

    def test_lambda_mode_skip_suppresses_wildcard_invoke_hyperedge(
        self,
    ) -> None:
        """Step 0 reproducer. Pre-fix this test FAILED because the
        BUG-022 bypass emitted a hyperedge without consulting
        lambda_mode. Post-fix it passes: skip → zero output."""
        pr = _make_pr(
            action="lambda:InvokeFunction",
            resource="*",
            is_wildcard=True,
        )
        ec = ExpansionController(
            global_mode="warn",
            lambda_mode="skip",
        )
        edges, nodes = build_permission_edges([pr], ec, [])

        assert edges == [] and nodes == [], (
            f"lambda_mode='skip' should suppress wildcard "
            f"lambda:InvokeFunction entirely, but got "
            f"{len(edges)} edge(s) and {len(nodes)} node(s)."
        )

    def test_lambda_mode_warn_emits_hyperedge_with_suppressed_flag(
        self,
    ) -> None:
        """Warn mode for lambda must still emit a hyperedge — the fix
        only gates skip, not warn. The hyperedge carries
        features.suppressed=True and features.expansion_mode='warn'
        so downstream reasoners can identify it as a suppressed
        wildcard expansion."""
        pr = _make_pr(
            action="lambda:InvokeFunction",
            resource="*",
            is_wildcard=True,
        )
        ec = ExpansionController(
            global_mode="skip",
            lambda_mode="warn",
        )
        edges, nodes = build_permission_edges([pr], ec, [])

        assert len(edges) == 1, f"expected 1 hyperedge, got {len(edges)}"
        assert len(nodes) == 1, f"expected 1 hyperedge node, got {len(nodes)}"
        assert edges[0].dst.node_type == NODE_TYPE_HYPEREDGE
        assert edges[0].features["suppressed"] is True
        assert edges[0].features["expansion_mode"] == "warn"


class TestEc2ModeEnforcement:
    """EC2-specific expansion mode enforcement — symmetric partner
    to TestLambdaModeEnforcement."""

    def test_ec2_mode_skip_suppresses_wildcard_runinstances_hyperedge(
        self,
    ) -> None:
        pr = _make_pr(
            action="ec2:RunInstances",
            resource="*",
            is_wildcard=True,
        )
        ec = ExpansionController(
            global_mode="warn",
            ec2_mode="skip",
        )
        edges, nodes = build_permission_edges([pr], ec, [])

        assert edges == [] and nodes == [], (
            f"ec2_mode='skip' should suppress wildcard "
            f"ec2:RunInstances entirely, but got "
            f"{len(edges)} edge(s) and {len(nodes)} node(s)."
        )

    def test_ec2_mode_warn_emits_hyperedge_with_suppressed_flag(
        self,
    ) -> None:
        pr = _make_pr(
            action="ec2:RunInstances",
            resource="*",
            is_wildcard=True,
        )
        ec = ExpansionController(
            global_mode="skip",
            ec2_mode="warn",
        )
        edges, nodes = build_permission_edges([pr], ec, [])

        assert len(edges) == 1, f"expected 1 hyperedge, got {len(edges)}"
        assert len(nodes) == 1, f"expected 1 hyperedge node, got {len(nodes)}"
        assert edges[0].dst.node_type == NODE_TYPE_HYPEREDGE
        assert edges[0].features["suppressed"] is True
        assert edges[0].features["expansion_mode"] == "warn"


class TestModeFallThrough:
    """When no per-family override is set (lambda_mode=None), the
    global_mode must apply. This verifies the ExpansionController
    fall-through contract works end-to-end through the permission
    builder, not just in the controller's unit tests."""

    def test_lambda_mode_none_falls_through_to_global_skip(
        self,
    ) -> None:
        pr = _make_pr(
            action="lambda:InvokeFunction",
            resource="*",
            is_wildcard=True,
        )
        ec = ExpansionController(
            global_mode="skip",
            lambda_mode=None,
        )
        edges, nodes = build_permission_edges([pr], ec, [])

        assert edges == [] and nodes == [], (
            f"lambda_mode=None with global_mode='skip' should suppress "
            f"wildcard lambda:InvokeFunction, but got "
            f"{len(edges)} edge(s) and {len(nodes)} node(s)."
        )
