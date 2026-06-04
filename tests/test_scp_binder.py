"""Tests for SCP binder — binding SCP constraints to edges with governance metadata.

Tests cover architecture doc §5.5, §10.1-10.4:
- Action match via deny_actions
- Action match via deny_not_actions (NotAction inversion — CRITICAL)
- No match returns None
- Exception pattern match prevents blocking
- likely_blocking requires parse_status="complete" (Invariant #17)
- governance_confidence mapping
- confidence_q mapping
- Wildcard action matching (sts:* matches sts:AssumeRole)
- OU inheritance propagation via ou_account_map
- Multiple SCPs binding to same edge
- Partial parse_status → likely_blocking=False
- bind_all_scps sorts output by composite key
"""

from iamscope.constants import (
    CONFIDENCE_Q_COMPLETE_BLOCKING,
    CONFIDENCE_Q_COMPLETE_NOT_BLOCKING,
    CONFIDENCE_Q_PARTIAL,
    CONFIDENCE_Q_UNSUPPORTED,
    CONSTRAINT_TYPE_SCP,
    GOVERNANCE_CONFIDENCE_COMPLETE,
    GOVERNANCE_CONFIDENCE_NEEDS_REVIEW,
    GOVERNANCE_CONFIDENCE_PARTIAL,
    NODE_TYPE_ACCOUNT_ROOT,
    NODE_TYPE_IAM_ROLE,
    PARSE_STATUS_COMPLETE,
    PARSE_STATUS_PARTIAL,
    PARSE_STATUS_UNSUPPORTED,
    PROVIDER_AWS,
    REGION_GLOBAL,
)
from iamscope.models import Constraint, Edge, NodeRef
from iamscope.resolver.scp_binder import (
    bind_all_scps,
    bind_scp_to_edge,
    compute_confidence_q,
)


def _make_edge(
    edge_type: str = "sts:AssumeRole_trust",
    src_id: str = "arn:aws:iam::222222\u003222222:root",
    src_type: str = NODE_TYPE_ACCOUNT_ROOT,
    dst_id: str = "arn:aws:iam::111111\u003111111:role/TargetRole",
) -> Edge:
    return Edge(
        edge_type=edge_type,
        src=NodeRef(provider=PROVIDER_AWS, node_type=src_type, provider_id=src_id),
        dst=NodeRef(provider=PROVIDER_AWS, node_type=NODE_TYPE_IAM_ROLE, provider_id=dst_id),
        region=REGION_GLOBAL,
        features={"layer": "trust"},
    )


def _make_scp_constraint(
    deny_actions: list[str] | None = None,
    deny_not_actions: list[str] | None = None,
    exception_principal_patterns: list[str] | None = None,
    applicable_principal_patterns: list[str] | None = None,
    exception_org_ids: list[str] | None = None,
    exception_account_ids: list[str] | None = None,
    resource_patterns: list[str] | None = None,
    parse_status: str = PARSE_STATUS_COMPLETE,
    scope_id: str = "ou-prod",
    policy_id: str = "p-001",
    statement_id: str = "DenyStmt",
) -> Constraint:
    props = {
        "deny_actions": deny_actions or [],
        "deny_not_actions": deny_not_actions or [],
        "applicable_principal_patterns": applicable_principal_patterns or [],
        "exception_principal_patterns": exception_principal_patterns or [],
        "exception_org_ids": exception_org_ids or [],
        "exception_account_ids": exception_account_ids or [],
        "parse_status": parse_status,
        "resource_patterns": resource_patterns or ["*"],
    }
    return Constraint(
        provider=PROVIDER_AWS,
        constraint_type=CONSTRAINT_TYPE_SCP,
        scope_type="OU",
        scope_id=scope_id,
        policy_id=policy_id,
        statement_id=statement_id,
        properties=props,
        confidence_q=800,
    )


class TestActionMatching:
    """Tests for SCP action matching against edges."""

    def test_deny_actions_exact_match(self) -> None:
        """SCP deny_actions exactly matching edge action produces binding."""
        edge = _make_edge()
        scp = _make_scp_constraint(deny_actions=["sts:AssumeRole"])
        binding = bind_scp_to_edge(edge, scp)

        assert binding is not None
        assert binding.edge_id == edge.edge_id
        assert binding.constraint_id == scp.constraint_id
        assert binding.likely_blocking is True

    def test_deny_actions_no_match(self) -> None:
        """SCP deny_actions not matching edge action returns None."""
        edge = _make_edge()
        scp = _make_scp_constraint(deny_actions=["s3:PutObject"])
        binding = bind_scp_to_edge(edge, scp)

        assert binding is None

    def test_deny_not_actions_inversion(self) -> None:
        """NotAction: edge action NOT in deny_not_actions → IS denied (§10.1 CRITICAL).

        SCP says: deny everything EXCEPT s3 actions.
        sts:AssumeRole is NOT in the exception list → it IS denied.
        Note: SCP parser sets parse_status=partial for NotAction,
        so likely_blocking=False per Invariant #17.
        """
        edge = _make_edge()
        scp = _make_scp_constraint(
            deny_not_actions=["s3:GetObject", "s3:PutObject"],
            parse_status=PARSE_STATUS_PARTIAL,  # SCP parser sets partial for NotAction
        )
        binding = bind_scp_to_edge(edge, scp)

        assert binding is not None
        assert binding.likely_blocking is False  # Invariant #17: partial → never blocking
        # But the binding still exists — action IS matched

    def test_deny_not_actions_action_excepted(self) -> None:
        """NotAction: edge action IN deny_not_actions → NOT denied."""
        edge = _make_edge()
        scp = _make_scp_constraint(deny_not_actions=["sts:AssumeRole", "sts:TagSession"])
        binding = bind_scp_to_edge(edge, scp)

        # sts:AssumeRole IS in the exception list → NOT denied → no binding
        assert binding is None

    def test_wildcard_action_match(self) -> None:
        """Wildcard action pattern (sts:*) matches sts:AssumeRole."""
        edge = _make_edge()
        scp = _make_scp_constraint(deny_actions=["sts:*"])
        binding = bind_scp_to_edge(edge, scp)

        assert binding is not None

    def test_star_action_matches_all(self) -> None:
        """Action '*' matches any edge action."""
        edge = _make_edge()
        scp = _make_scp_constraint(deny_actions=["*"])
        binding = bind_scp_to_edge(edge, scp)

        assert binding is not None

    def test_case_insensitive_action_match(self) -> None:
        """Action matching is case-insensitive."""
        edge = _make_edge()
        scp = _make_scp_constraint(deny_actions=["STS:ASSUMEROLE"])
        binding = bind_scp_to_edge(edge, scp)

        assert binding is not None

    def test_resource_scoped_scp_binds_only_matching_target_role(self) -> None:
        """Target-scoped SCP Deny must not bind unrelated AssumeRole targets."""
        matching_edge = _make_edge(dst_id="arn:aws:iam::111111\u003111111:role/iamscope-test/env12-admin")
        unrelated_edge = _make_edge(dst_id="arn:aws:iam::111111\u003111111:role/iamscope-test/env12-reader")
        scp = _make_scp_constraint(
            deny_actions=["sts:AssumeRole"],
            resource_patterns=["arn:aws:iam::111111\u003111111:role/iamscope-test/env12-admin"],
            parse_status=PARSE_STATUS_PARTIAL,
        )

        matching_binding = bind_scp_to_edge(matching_edge, scp)
        unrelated_binding = bind_scp_to_edge(unrelated_edge, scp)

        assert matching_binding is not None
        assert matching_binding.governance_confidence == GOVERNANCE_CONFIDENCE_PARTIAL
        assert matching_binding.likely_blocking is False
        assert unrelated_binding is None

    def test_resource_scoped_scp_supports_wildcard_target_pattern(self) -> None:
        edge = _make_edge(dst_id="arn:aws:iam::111111\u003111111:role/iamscope-test/env12-admin")
        scp = _make_scp_constraint(
            deny_actions=["sts:AssumeRole"],
            resource_patterns=["arn:aws:iam::111111\u003111111:role/iamscope-test/env12-*"],
            parse_status=PARSE_STATUS_PARTIAL,
        )

        binding = bind_scp_to_edge(edge, scp)

        assert binding is not None


class TestExceptionMatching:
    """Tests for SCP exception pattern matching."""

    def test_exception_pattern_matches_src(self) -> None:
        """If src principal matches exception pattern, binding has likely_blocking=False."""
        edge = _make_edge(src_id="arn:aws:iam::222222\u003222222:role/BreakGlassAdmin")
        scp = _make_scp_constraint(
            deny_actions=["sts:AssumeRole"],
            exception_principal_patterns=["arn:aws:iam::*:role/BreakGlass*"],
        )
        binding = bind_scp_to_edge(edge, scp)

        assert binding is not None
        assert binding.likely_blocking is False
        assert "exception" in binding.binding_reason

    def test_exception_pattern_no_match(self) -> None:
        """Non-matching exception pattern doesn't prevent blocking."""
        edge = _make_edge(src_id="arn:aws:iam::222222\u003222222:role/NormalRole")
        scp = _make_scp_constraint(
            deny_actions=["sts:AssumeRole"],
            exception_principal_patterns=["arn:aws:iam::*:role/BreakGlass*"],
        )
        binding = bind_scp_to_edge(edge, scp)

        assert binding is not None
        assert binding.likely_blocking is True

    def test_multiple_exception_patterns(self) -> None:
        """Any matching exception pattern prevents blocking."""
        edge = _make_edge(src_id="arn:aws:iam::222222\u003222222:role/Admin-Prod")
        scp = _make_scp_constraint(
            deny_actions=["sts:AssumeRole"],
            exception_principal_patterns=[
                "arn:aws:iam::*:role/BreakGlass*",
                "arn:aws:iam::*:role/Admin*",
            ],
        )
        binding = bind_scp_to_edge(edge, scp)

        assert binding is not None
        assert binding.likely_blocking is False


class TestPrincipalApplicabilityMatching:
    """Tests for positive aws:PrincipalArn Deny applicability filters."""

    def test_nonmatching_applicability_pattern_does_not_bind_unrelated_edge(self) -> None:
        edge = _make_edge(src_id="arn:aws:iam::222222\u003222222:user/env22-alice", src_type="IAMUser")
        scp = _make_scp_constraint(
            deny_actions=["sts:AssumeRole"],
            applicable_principal_patterns=["arn:aws:iam::222222\u003222222:role/Blocked*"],
        )

        binding = bind_scp_to_edge(edge, scp)

        assert binding is None

    def test_matching_applicability_pattern_binds_and_preserves_blocking(self) -> None:
        edge = _make_edge(src_id="arn:aws:iam::222222\u003222222:user/env22-alice", src_type="IAMUser")
        scp = _make_scp_constraint(
            deny_actions=["sts:AssumeRole"],
            applicable_principal_patterns=["arn:aws:iam::222222\u003222222:user/env22-*"],
        )

        binding = bind_scp_to_edge(edge, scp)

        assert binding is not None
        assert binding.likely_blocking is True
        assert binding.governance_confidence == GOVERNANCE_CONFIDENCE_COMPLETE
        assert "applicable_principal_patterns" in binding.binding_reason

    def test_unsupported_condition_shape_stays_conservative(self) -> None:
        edge = _make_edge(src_id="arn:aws:iam::222222\u003222222:user/env22-alice", src_type="IAMUser")
        scp = _make_scp_constraint(
            deny_actions=["sts:AssumeRole"],
            parse_status=PARSE_STATUS_PARTIAL,
        )

        binding = bind_scp_to_edge(edge, scp)

        assert binding is not None
        assert binding.likely_blocking is False
        assert binding.governance_confidence == GOVERNANCE_CONFIDENCE_PARTIAL


class TestLikelyBlocking:
    """Tests for likely_blocking computation."""

    def test_complete_no_exception_is_blocking(self) -> None:
        """complete parse_status + no exception → likely_blocking=True."""
        edge = _make_edge()
        scp = _make_scp_constraint(
            deny_actions=["sts:AssumeRole"],
            parse_status=PARSE_STATUS_COMPLETE,
        )
        binding = bind_scp_to_edge(edge, scp)

        assert binding is not None
        assert binding.likely_blocking is True

    def test_partial_never_blocking(self) -> None:
        """Invariant #17: likely_blocking=True requires parse_status='complete'."""
        edge = _make_edge()
        scp = _make_scp_constraint(
            deny_actions=["sts:AssumeRole"],
            parse_status=PARSE_STATUS_PARTIAL,
        )
        binding = bind_scp_to_edge(edge, scp)

        assert binding is not None
        assert binding.likely_blocking is False

    def test_unsupported_never_blocking(self) -> None:
        """Unsupported parse_status → likely_blocking=False."""
        edge = _make_edge()
        scp = _make_scp_constraint(
            deny_actions=["sts:AssumeRole"],
            parse_status=PARSE_STATUS_UNSUPPORTED,
        )
        binding = bind_scp_to_edge(edge, scp)

        assert binding is not None
        assert binding.likely_blocking is False


class TestGovernanceConfidence:
    """Tests for governance_confidence mapping."""

    def test_complete_parse_gives_complete_confidence(self) -> None:
        edge = _make_edge()
        scp = _make_scp_constraint(
            deny_actions=["sts:AssumeRole"],
            parse_status=PARSE_STATUS_COMPLETE,
        )
        binding = bind_scp_to_edge(edge, scp)
        assert binding is not None
        assert binding.governance_confidence == GOVERNANCE_CONFIDENCE_COMPLETE

    def test_partial_parse_gives_partial_confidence(self) -> None:
        edge = _make_edge()
        scp = _make_scp_constraint(
            deny_actions=["sts:AssumeRole"],
            parse_status=PARSE_STATUS_PARTIAL,
        )
        binding = bind_scp_to_edge(edge, scp)
        assert binding is not None
        assert binding.governance_confidence == GOVERNANCE_CONFIDENCE_PARTIAL

    def test_unsupported_parse_gives_needs_review(self) -> None:
        edge = _make_edge()
        scp = _make_scp_constraint(
            deny_actions=["sts:AssumeRole"],
            parse_status=PARSE_STATUS_UNSUPPORTED,
        )
        binding = bind_scp_to_edge(edge, scp)
        assert binding is not None
        assert binding.governance_confidence == GOVERNANCE_CONFIDENCE_NEEDS_REVIEW


class TestConfidenceQ:
    """Tests for confidence_q mapping (Phase A R05)."""

    def test_complete_blocking(self) -> None:
        assert compute_confidence_q(PARSE_STATUS_COMPLETE, True) == CONFIDENCE_Q_COMPLETE_BLOCKING

    def test_complete_not_blocking(self) -> None:
        assert compute_confidence_q(PARSE_STATUS_COMPLETE, False) == CONFIDENCE_Q_COMPLETE_NOT_BLOCKING

    def test_partial(self) -> None:
        assert compute_confidence_q(PARSE_STATUS_PARTIAL, True) == CONFIDENCE_Q_PARTIAL

    def test_unsupported(self) -> None:
        assert compute_confidence_q(PARSE_STATUS_UNSUPPORTED, False) == CONFIDENCE_Q_UNSUPPORTED


class TestBindAllScps:
    """Tests for bind_all_scps with OU inheritance."""

    def test_global_binding_no_scope_map(self) -> None:
        """Without ou_account_map, all constraints bind to all matching edges."""
        edge = _make_edge()
        scp = _make_scp_constraint(deny_actions=["sts:AssumeRole"])
        bindings = bind_all_scps([edge], [scp])

        assert len(bindings) == 1

    def test_ou_scope_limits_binding(self) -> None:
        """With ou_account_map, SCP only binds to source principals in scope."""
        edge_in_scope = _make_edge(src_id="arn:aws:iam::111111\u003111111:root")
        edge_out_scope = _make_edge(src_id="arn:aws:iam::999999\u003999999:root")

        scp = _make_scp_constraint(deny_actions=["sts:AssumeRole"], scope_id="ou-prod")

        ou_map = {"ou-prod": {"111111\u003111111"}}
        bindings = bind_all_scps([edge_in_scope, edge_out_scope], [scp], ou_account_map=ou_map)

        assert len(bindings) == 1
        assert bindings[0].edge_id == edge_in_scope.edge_id

    def test_multiple_scps_same_edge(self) -> None:
        """Multiple SCPs can bind to the same edge."""
        edge = _make_edge()
        scp1 = _make_scp_constraint(deny_actions=["sts:AssumeRole"], policy_id="p-001", statement_id="s1")
        scp2 = _make_scp_constraint(deny_actions=["sts:*"], policy_id="p-002", statement_id="s2")

        bindings = bind_all_scps([edge], [scp1, scp2])

        assert len(bindings) == 2
        constraint_ids = {b.constraint_id for b in bindings}
        assert scp1.constraint_id in constraint_ids
        assert scp2.constraint_id in constraint_ids

    def test_output_sorted_by_composite_key(self) -> None:
        """Output is sorted by (edge_id, constraint_id) tuple."""
        edge = _make_edge()
        scp1 = _make_scp_constraint(deny_actions=["sts:AssumeRole"], policy_id="p-aaa", statement_id="s1")
        scp2 = _make_scp_constraint(deny_actions=["sts:*"], policy_id="p-zzz", statement_id="s2")

        bindings = bind_all_scps([edge], [scp2, scp1])  # Reverse input order

        keys = [(b.edge_id, b.constraint_id) for b in bindings]
        assert keys == sorted(keys)


class TestBindAllScpsSourceAccountScope:
    """Regression coverage: SCP scope applies to the principal account, not target account."""

    def _cross_account_edge(self) -> Edge:
        return _make_edge(
            src_id="arn:aws:iam::111111\u003111111:role/Caller",
            src_type=NODE_TYPE_IAM_ROLE,
            dst_id="arn:aws:iam::222222\u003222222:role/TargetRole",
        )

    def test_cross_account_source_scoped_deny_binds(self) -> None:
        edge = self._cross_account_edge()
        scp = _make_scp_constraint(deny_actions=["sts:AssumeRole"], scope_id="ou-source")
        ou_map = {"ou-source": {"111111\u003111111"}}

        bindings = bind_all_scps([edge], [scp], ou_account_map=ou_map)

        assert len(bindings) == 1
        assert bindings[0].edge_id == edge.edge_id
        assert bindings[0].constraint_id == scp.constraint_id

    def test_cross_account_target_scoped_deny_does_not_bind(self) -> None:
        edge = self._cross_account_edge()
        scp = _make_scp_constraint(deny_actions=["sts:AssumeRole"], scope_id="ou-target")
        ou_map = {"ou-target": {"222222\u003222222"}}

        bindings = bind_all_scps([edge], [scp], ou_account_map=ou_map)

        assert bindings == []

    def test_resource_matching_remains_target_based(self) -> None:
        edge = self._cross_account_edge()
        scp = _make_scp_constraint(
            deny_actions=["sts:AssumeRole"],
            resource_patterns=["arn:aws:iam::222222\u003222222:role/OtherRole"],
            scope_id="ou-source",
        )
        ou_map = {"ou-source": {"111111\u003111111"}}

        bindings = bind_all_scps([edge], [scp], ou_account_map=ou_map)

        assert bindings == []

    def test_principal_applicability_still_uses_source_principal(self) -> None:
        edge = self._cross_account_edge()
        scp = _make_scp_constraint(
            deny_actions=["sts:AssumeRole"],
            applicable_principal_patterns=["arn:aws:iam::111111\u003111111:role/OtherCaller"],
            scope_id="ou-source",
        )
        ou_map = {"ou-source": {"111111\u003111111"}}

        bindings = bind_all_scps([edge], [scp], ou_account_map=ou_map)

        assert bindings == []

    def test_same_account_behavior_still_binds(self) -> None:
        edge = _make_edge(
            src_id="arn:aws:iam::111111\u003111111:role/Caller",
            src_type=NODE_TYPE_IAM_ROLE,
            dst_id="arn:aws:iam::111111\u003111111:role/TargetRole",
        )
        scp = _make_scp_constraint(deny_actions=["sts:AssumeRole"], scope_id="ou-same")
        ou_map = {"ou-same": {"111111\u003111111"}}

        bindings = bind_all_scps([edge], [scp], ou_account_map=ou_map)

        assert len(bindings) == 1

    def test_ou_map_uses_source_account_not_target_account(self) -> None:
        edge = self._cross_account_edge()
        source_scoped_scp = _make_scp_constraint(
            deny_actions=["sts:AssumeRole"],
            scope_id="ou-source",
            policy_id="p-source",
            statement_id="source",
        )
        target_scoped_scp = _make_scp_constraint(
            deny_actions=["sts:AssumeRole"],
            scope_id="ou-target",
            policy_id="p-target",
            statement_id="target",
        )
        ou_map = {
            "ou-source": {"111111\u003111111"},
            "ou-target": {"222222\u003222222"},
        }

        bindings = bind_all_scps([edge], [target_scoped_scp, source_scoped_scp], ou_account_map=ou_map)

        assert len(bindings) == 1
        assert bindings[0].constraint_id == source_scoped_scp.constraint_id

    def test_unavailable_source_account_does_not_fall_back_to_target_account(self) -> None:
        edge = _make_edge(
            src_id="__synthetic__:external-principal-set",
            dst_id="arn:aws:iam::222222\u003222222:role/TargetRole",
        )
        scp = _make_scp_constraint(deny_actions=["sts:AssumeRole"], scope_id="ou-target")
        ou_map = {"ou-target": {"222222\u003222222"}}

        bindings = bind_all_scps([edge], [scp], ou_account_map=ou_map)

        assert bindings == []


class TestBindingReason:
    """Tests for human-readable binding reason."""

    def test_deny_actions_reason(self) -> None:
        edge = _make_edge()
        scp = _make_scp_constraint(deny_actions=["sts:AssumeRole"])
        binding = bind_scp_to_edge(edge, scp)
        assert binding is not None
        assert "deny_actions" in binding.binding_reason

    def test_not_action_reason(self) -> None:
        edge = _make_edge()
        scp = _make_scp_constraint(deny_not_actions=["s3:GetObject"])
        binding = bind_scp_to_edge(edge, scp)
        assert binding is not None
        assert "NotAction" in binding.binding_reason

    def test_exception_reason(self) -> None:
        edge = _make_edge(src_id="arn:aws:iam::222222\u003222222:role/BreakGlassAdmin")
        scp = _make_scp_constraint(
            deny_actions=["sts:AssumeRole"],
            exception_principal_patterns=["arn:aws:iam::*:role/BreakGlass*"],
        )
        binding = bind_scp_to_edge(edge, scp)
        assert binding is not None
        assert "exception" in binding.binding_reason


class TestScp1UnresolvableExceptionDowngrade:
    """SCP-1 regression tests: downgrade confidence when org/account exceptions present.

    Pre-S04 the SCP binder emitted likely_blocking=True + governance_confidence=complete
    for any matched deny_action regardless of whether the SCP had org_id or account_id
    exceptions populated. IAMScope has no org-membership resolver, so we cannot
    confirm that a source principal falls outside an excepted org/account — the
    correct move is to downgrade to needs_review rather than emit a high-confidence
    claim that might be wrong.

    Post-S04 rules:
    - likely_blocking=True + exception_org_ids non-empty → governance_confidence=needs_review
    - likely_blocking=True + exception_account_ids non-empty → same
    - likely_blocking=True + both empty → governance_confidence stays complete
    - likely_blocking=False (action miss, principal exception, or partial parse) →
      downgrade is a no-op (we're not claiming a block anyway)
    """

    def test_exception_org_ids_downgrades_confidence(self) -> None:
        """Non-empty exception_org_ids + likely_blocking → needs_review."""
        edge = _make_edge()
        scp = _make_scp_constraint(
            deny_actions=["sts:AssumeRole"],
            exception_org_ids=["o-aaaabbbbcc"],
        )
        binding = bind_scp_to_edge(edge, scp)

        assert binding is not None
        assert binding.likely_blocking is True
        assert binding.governance_confidence == GOVERNANCE_CONFIDENCE_NEEDS_REVIEW
        assert "exception_org_ids=1" in binding.binding_reason
        assert "unresolved" in binding.binding_reason

    def test_exception_account_ids_downgrades_confidence(self) -> None:
        """Non-empty exception_account_ids + likely_blocking → needs_review."""
        edge = _make_edge()
        scp = _make_scp_constraint(
            deny_actions=["sts:AssumeRole"],
            exception_account_ids=["222222\u003222222"],
        )
        binding = bind_scp_to_edge(edge, scp)

        assert binding is not None
        assert binding.likely_blocking is True
        assert binding.governance_confidence == GOVERNANCE_CONFIDENCE_NEEDS_REVIEW
        assert "exception_account_ids=1" in binding.binding_reason

    def test_no_org_or_account_exception_stays_complete(self) -> None:
        """Regression guard: absent org/account exceptions → still complete + blocking.

        This is the shape the golden fixtures and most existing tests depend on.
        """
        edge = _make_edge()
        scp = _make_scp_constraint(
            deny_actions=["sts:AssumeRole"],
            # both exception lists default to []
        )
        binding = bind_scp_to_edge(edge, scp)

        assert binding is not None
        assert binding.likely_blocking is True
        assert binding.governance_confidence == GOVERNANCE_CONFIDENCE_COMPLETE
        # Must not contain the downgrade clause.
        assert "unresolved" not in binding.binding_reason

    def test_downgrade_skipped_when_already_not_blocking(self) -> None:
        """If likely_blocking=False, the downgrade is a no-op.

        Exercises the case where action matching fails — we're already not
        claiming a block, so emitting needs_review would be spurious. This is
        actually a trivially-passing case because bind_scp_to_edge returns
        None when the action doesn't match, so the binding never exists to
        downgrade. We assert the None return explicitly to document the
        contract.
        """
        edge = _make_edge(edge_type="iam:PassRole_permission")
        scp = _make_scp_constraint(
            deny_actions=["sts:AssumeRole"],  # doesn't match iam:PassRole
            exception_org_ids=["o-aaaabbbbcc"],
        )
        binding = bind_scp_to_edge(edge, scp)
        # Action miss → no binding at all; downgrade path never reached.
        assert binding is None
