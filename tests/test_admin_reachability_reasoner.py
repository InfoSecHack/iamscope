"""Tests for the admin_reachability reasoner.

Covers:
- Basic 2-hop reachability → validated/high (1 admin reachable)
- Multi-admin reachability → validated/critical (2+ admins)
- No admin reachable → no finding
- Single principal in graph → checked correctly
- Hyperedge in walk → inconclusive
- Cycle detection (no infinite loop)
- Determinism: double run produces identical findings
- Source enumeration: all eligible principals get findings
- Walk hits depth limit → check 4 UNKNOWN → inconclusive

Reuses helpers from test_assume_role_chain_reasoner.py since the
fact-graph builders are identical.
"""

from __future__ import annotations

from iamscope.collector.passrole import build_permission_edges
from iamscope.constants import (
    CONSTRAINT_TYPE_PERMISSION_BOUNDARY,
    CONSTRAINT_TYPE_SCP,
    NODE_TYPE_ACCOUNT_ROOT,
    NODE_TYPE_IAM_ROLE,
    NODE_TYPE_WILDCARD_PRINCIPAL,
    PROVIDER_AWS,
    REGION_GLOBAL,
    TRUST_SCOPE_ACCOUNT_ROOT,
    TRUST_SCOPE_ANY_AWS_PRINCIPAL,
)
from iamscope.controls.expansion import ExpansionController
from iamscope.models import Constraint, Edge, EdgeConstraint, Node
from iamscope.parser.permission_policy import parse_permission_policy
from iamscope.reasoner import AdminReachabilityReasoner, FactGraph
from tests.test_assume_role_chain_reasoner import (  # noqa: I001
    _ADMIN_ARN,
    _ALICE_ARN,
    _DEPLOY_ARN,
    _DEVOPS_ARN,
    _NON_ADMIN_ARN,
    _PROD_ARN,
    _admin_grant_edge,
    _assume_perm_edge,
    _build_three_hop_chain,
    _build_two_hop_chain,
    _make_facts,
    _role,
    _trust_edge,
    _user,
    _wildcard_trust_edge,
)

_AWS_MANAGED_ADMINISTRATOR_ACCESS_ARN = "arn:aws:iam::aws:policy/AdministratorAccess"

# ---------------------------------------------------------------------------
# Preconditions
# ---------------------------------------------------------------------------


class TestPreconditions:
    def test_empty_graph_skipped(self) -> None:
        empty = FactGraph(
            nodes=(),
            edges=(),
            constraints=(),
            edge_constraints=(),
            scenario_hash="x" * 64,
            edge_budget_exhausted=False,
        )
        ok, reason = AdminReachabilityReasoner().preconditions_met(empty)
        assert not ok
        assert "no IAM roles" in reason

    def test_role_present_runs(self) -> None:
        facts = _make_facts(nodes=(_role(_ADMIN_ARN),), edges=())
        ok, reason = AdminReachabilityReasoner().preconditions_met(facts)
        assert ok


# ---------------------------------------------------------------------------
# Basic reachability — 2-hop chain
# ---------------------------------------------------------------------------


class TestTwoHopReachability:
    def test_emits_one_finding(self) -> None:
        findings = AdminReachabilityReasoner().run(_build_two_hop_chain())
        # Source candidates: Alice (has assumerole perm) + DevOps (has assumerole perm).
        # Alice reaches Admin via DevOps → 1 finding
        # DevOps reaches Admin directly (1 hop) → 1 finding
        # Total: 2 findings
        assert len(findings) == 2

    def test_alice_finding_validated_high(self) -> None:
        findings = AdminReachabilityReasoner().run(_build_two_hop_chain())
        alice_f = next(f for f in findings if f.source.provider_id == _ALICE_ARN)
        assert alice_f.verdict.value == "validated"
        # Alice reaches 1 admin → severity high
        assert alice_f.severity == "high"

    def test_alice_target_is_admin(self) -> None:
        findings = AdminReachabilityReasoner().run(_build_two_hop_chain())
        alice_f = next(f for f in findings if f.source.provider_id == _ALICE_ARN)
        assert alice_f.target.provider_id == _ADMIN_ARN

    def test_check_2_reports_one_admin(self) -> None:
        findings = AdminReachabilityReasoner().run(_build_two_hop_chain())
        alice_f = next(f for f in findings if f.source.provider_id == _ALICE_ARN)
        c = next(c for c in alice_f.required_checks if c.name == "reaches_at_least_one_admin")
        assert "1" in c.reason
        assert _ADMIN_ARN in c.reason


# ---------------------------------------------------------------------------
# Multi-admin reachability → critical severity
# ---------------------------------------------------------------------------


class TestMultiAdminReachability:
    def _build_two_admins_facts(self) -> FactGraph:
        """Alice → DevOps → AdminRole AND Alice → DevOps → ProdAdmin.

        DevOps trusts Alice. AdminRole and ProdAdmin both trust DevOps.
        Both AdminRole and ProdAdmin are admin-equivalent.
        """
        alice = _user(_ALICE_ARN)
        devops = _role(_DEVOPS_ARN)
        admin = _role(_ADMIN_ARN)
        prod_admin = _role(_PROD_ARN)

        # Alice → DevOps
        perm_a_d = _assume_perm_edge(src_arn=_ALICE_ARN, dst_arn=_DEVOPS_ARN, digest="1" * 64)
        trust_a_d = _trust_edge(principal_arn=_ALICE_ARN, target_arn=_DEVOPS_ARN, digest="2" * 64)
        # DevOps → Admin
        perm_d_a = _assume_perm_edge(src_arn=_DEVOPS_ARN, dst_arn=_ADMIN_ARN, digest="3" * 64)
        trust_d_a = _trust_edge(principal_arn=_DEVOPS_ARN, target_arn=_ADMIN_ARN, digest="4" * 64)
        # DevOps → ProdAdmin
        perm_d_p = _assume_perm_edge(src_arn=_DEVOPS_ARN, dst_arn=_PROD_ARN, digest="5" * 64)
        trust_d_p = _trust_edge(principal_arn=_DEVOPS_ARN, target_arn=_PROD_ARN, digest="6" * 64)
        # Both targets are admin-equivalent
        admin_grant_1 = _admin_grant_edge(_ADMIN_ARN)
        admin_grant_2 = _admin_grant_edge(_PROD_ARN)
        return _make_facts(
            nodes=(alice, devops, admin, prod_admin),
            edges=(
                perm_a_d,
                trust_a_d,
                perm_d_a,
                trust_d_a,
                perm_d_p,
                trust_d_p,
                admin_grant_1,
                admin_grant_2,
            ),
        )

    def test_alice_severity_critical_with_two_admins(self) -> None:
        findings = AdminReachabilityReasoner().run(self._build_two_admins_facts())
        alice_f = next(f for f in findings if f.source.provider_id == _ALICE_ARN)
        assert alice_f.verdict.value == "validated"
        assert alice_f.severity == "critical"

    def test_alice_check_2_lists_both_admins(self) -> None:
        findings = AdminReachabilityReasoner().run(self._build_two_admins_facts())
        alice_f = next(f for f in findings if f.source.provider_id == _ALICE_ARN)
        c = next(c for c in alice_f.required_checks if c.name == "reaches_at_least_one_admin")
        assert "2" in c.reason
        assert _ADMIN_ARN in c.reason
        assert _PROD_ARN in c.reason

    def test_target_is_first_admin_lexicographically(self) -> None:
        """Deterministic target selection: smallest ARN wins."""
        findings = AdminReachabilityReasoner().run(self._build_two_admins_facts())
        alice_f = next(f for f in findings if f.source.provider_id == _ALICE_ARN)
        # _ADMIN_ARN ("...:role/Admin") and _PROD_ARN ("...:role/Prod")
        # Lexicographic sort: Admin < Prod
        assert alice_f.target.provider_id == _ADMIN_ARN

    def test_evidence_contains_both_admin_witnesses(self) -> None:
        """Both admin grant edges should appear in evidence.edge_refs."""
        findings = AdminReachabilityReasoner().run(self._build_two_admins_facts())
        alice_f = next(f for f in findings if f.source.provider_id == _ALICE_ARN)
        # The walk has 4 chain edges (2 hops × 2 edges each + 2 more for
        # the second branch) + 2 admin witnesses = 6+ edge refs
        assert len(alice_f.evidence.edge_refs) >= 6


# ---------------------------------------------------------------------------
# No reachable admin → no finding
# ---------------------------------------------------------------------------


class TestNoReachableAdmin:
    def test_chain_to_non_admin_no_finding(self) -> None:
        """Alice → DevOps → NonAdmin (NonAdmin has no admin permissions)."""
        alice = _user(_ALICE_ARN)
        devops = _role(_DEVOPS_ARN)
        non_admin = _role(_NON_ADMIN_ARN)
        perm_1 = _assume_perm_edge(src_arn=_ALICE_ARN, dst_arn=_DEVOPS_ARN)
        trust_1 = _trust_edge(principal_arn=_ALICE_ARN, target_arn=_DEVOPS_ARN)
        perm_2 = _assume_perm_edge(src_arn=_DEVOPS_ARN, dst_arn=_NON_ADMIN_ARN)
        trust_2 = _trust_edge(principal_arn=_DEVOPS_ARN, target_arn=_NON_ADMIN_ARN)
        # No admin_grant — NonAdmin has no admin permissions
        facts = _make_facts(
            nodes=(alice, devops, non_admin),
            edges=(perm_1, trust_1, perm_2, trust_2),
        )
        findings = AdminReachabilityReasoner().run(facts)
        assert len(findings) == 0

    def test_principal_with_no_assumerole_no_finding(self) -> None:
        """A principal with no sts:AssumeRole permission should not be a candidate."""
        alice = _user(_ALICE_ARN)
        admin = _role(_ADMIN_ARN)
        admin_grant = _admin_grant_edge(_ADMIN_ARN)
        # Alice has no permission edges at all
        facts = _make_facts(nodes=(alice, admin), edges=(admin_grant,))
        findings = AdminReachabilityReasoner().run(facts)
        assert len(findings) == 0


# ---------------------------------------------------------------------------
# Permission boundary blockers
# ---------------------------------------------------------------------------


class TestConditionedTrustReachability:
    def test_conditioned_trust_downgrades_reachable_admin_to_inconclusive(self) -> None:
        alice = _user(_ALICE_ARN)
        devops = _role(_DEVOPS_ARN)
        admin = _role(_ADMIN_ARN)
        perm_1 = _assume_perm_edge(src_arn=_ALICE_ARN, dst_arn=_DEVOPS_ARN)
        trust_1 = _trust_edge(
            principal_arn=_ALICE_ARN,
            target_arn=_DEVOPS_ARN,
            raw_conditions={"Bool": {"aws:MultiFactorAuthPresent": "true"}},
        )
        perm_2 = _assume_perm_edge(src_arn=_DEVOPS_ARN, dst_arn=_ADMIN_ARN)
        trust_2 = _trust_edge(principal_arn=_DEVOPS_ARN, target_arn=_ADMIN_ARN)
        admin_grant = _admin_grant_edge(_ADMIN_ARN)
        facts = _make_facts(
            nodes=(alice, devops, admin),
            edges=(perm_1, trust_1, perm_2, trust_2, admin_grant),
        )
        findings = AdminReachabilityReasoner().run(facts)
        alice_f = next(f for f in findings if f.source.provider_id == _ALICE_ARN)
        assert alice_f.verdict.value == "inconclusive"
        check = next(
            c for c in alice_f.required_checks if c.name == "at_least_one_reachable_chain_uses_clean_witnesses"
        )
        assert check.state.value == "unknown"


class TestWildcardTrustPrincipalReachability:
    def test_wildcard_trust_path_to_admin_is_inconclusive(self) -> None:
        alice = _user(_ALICE_ARN)
        admin = _role(_ADMIN_ARN)
        perm = _assume_perm_edge(src_arn=_ALICE_ARN, dst_arn=_ADMIN_ARN)
        trust = _wildcard_trust_edge(target_arn=_ADMIN_ARN)
        admin_grant = _admin_grant_edge(_ADMIN_ARN)
        facts = _make_facts(
            nodes=(alice, admin),
            edges=(perm, trust, admin_grant),
        )

        findings = AdminReachabilityReasoner().run(facts)
        alice_f = next(f for f in findings if f.source.provider_id == _ALICE_ARN)

        assert alice_f.verdict.value == "inconclusive"
        check = next(
            c for c in alice_f.required_checks if c.name == "at_least_one_reachable_chain_uses_clean_witnesses"
        )
        assert check.state.value == "unknown"
        assert trust.edge_id in alice_f.evidence.edge_refs

    def test_account_root_trust_without_principalarn_is_inconclusive(self) -> None:
        alice = _user(_ALICE_ARN)
        admin = _role(_ADMIN_ARN)
        root_arn = "arn:aws:iam::111111\u003111111:root"
        perm = _assume_perm_edge(src_arn=_ALICE_ARN, dst_arn=_ADMIN_ARN)
        trust = _trust_edge(principal_arn=root_arn, target_arn=_ADMIN_ARN)
        admin_grant = _admin_grant_edge(_ADMIN_ARN)
        facts = _make_facts(
            nodes=(alice, admin),
            edges=(perm, trust, admin_grant),
        )

        findings = AdminReachabilityReasoner().run(facts)
        alice_f = next(f for f in findings if f.source.provider_id == _ALICE_ARN)

        assert alice_f.verdict.value == "inconclusive"
        check = next(
            c for c in alice_f.required_checks if c.name == "at_least_one_reachable_chain_uses_clean_witnesses"
        )
        assert check.state.value == "unknown"

    def test_unrelated_trust_still_produces_no_reachability(self) -> None:
        alice = _user(_ALICE_ARN)
        admin = _role(_ADMIN_ARN)
        bob_arn = "arn:aws:iam::111111\u003111111:user/Bob"
        perm = _assume_perm_edge(src_arn=_ALICE_ARN, dst_arn=_ADMIN_ARN)
        unrelated_trust = _trust_edge(principal_arn=bob_arn, target_arn=_ADMIN_ARN)
        admin_grant = _admin_grant_edge(_ADMIN_ARN)
        facts = _make_facts(
            nodes=(alice, admin),
            edges=(perm, unrelated_trust, admin_grant),
        )

        findings = AdminReachabilityReasoner().run(facts)

        assert not any(f.source.provider_id == _ALICE_ARN for f in findings)


class TestAdministratorAccessCalibration:
    def _admin_edges_from_policy(
        self,
        *,
        role_arn: str,
        policy_arn: str,
        conditions: dict | None = None,
    ) -> tuple[tuple[Edge, ...], tuple[Node, ...]]:
        policy: dict = {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Effect": "Allow",
                    "Action": "*",
                    "Resource": "*",
                }
            ],
        }
        if conditions is not None:
            policy["Statement"][0]["Condition"] = conditions
        parse_results = parse_permission_policy(
            policy,
            source_arn=role_arn,
            source_node_type=NODE_TYPE_IAM_ROLE,
            source_account_id="111111\u003111111",
            policy_source="managed",
            policy_name="AdministratorAccess",
            policy_arn=policy_arn,
        )
        edges, hyperedge_nodes = build_permission_edges(
            parse_results,
            ExpansionController(global_mode="warn"),
            known_role_arns=[role_arn],
        )
        return (tuple(edges), tuple(hyperedge_nodes))

    def _single_hop_to_admin_with_policy(
        self,
        *,
        source_arn: str = _ALICE_ARN,
        target_arn: str = _ADMIN_ARN,
        policy_arn: str = _AWS_MANAGED_ADMINISTRATOR_ACCESS_ARN,
        conditions: dict | None = None,
        wildcard_assume_role_permission: bool = False,
    ) -> FactGraph:
        source = _user(source_arn) if ":user/" in source_arn else _role(source_arn)
        target = _role(target_arn)
        assume_perm = _assume_perm_edge(
            src_arn=source_arn,
            dst_arn=target_arn,
            is_wildcard_resource=wildcard_assume_role_permission,
        )
        trust = _trust_edge(principal_arn=source_arn, target_arn=target_arn)
        admin_edges, hyperedge_nodes = self._admin_edges_from_policy(
            role_arn=target_arn,
            policy_arn=policy_arn,
            conditions=conditions,
        )
        return _make_facts(
            nodes=(source, target, *hyperedge_nodes),
            edges=(assume_perm, trust, *admin_edges),
        )

    def _finding_for_source(self, facts: FactGraph, source_arn: str) -> object:
        return next(f for f in AdminReachabilityReasoner().run(facts) if f.source.provider_id == source_arn)

    def _clean_witness_check_state(self, finding: object) -> str:
        check = next(
            c for c in finding.required_checks if c.name == "at_least_one_reachable_chain_uses_clean_witnesses"
        )
        return check.state.value

    def _conditioned_root_trust_facts(
        self,
        *,
        source_arn: str,
        target_arn: str,
        principal_arn_value: str | list[str] | None,
        extra_conditions: dict | None = None,
        wildcard_principal: bool = False,
        include_external_id: bool = True,
    ) -> FactGraph:
        source = _role(source_arn)
        target = _role(target_arn)
        account_id = source_arn.split(":")[4]
        root_arn = f"arn:aws:iam::{account_id}:root"
        raw_conditions: dict = {}
        if principal_arn_value is not None:
            raw_conditions["ArnLike"] = {"aws:PrincipalArn": principal_arn_value}
        if include_external_id:
            raw_conditions.setdefault("StringEquals", {})["sts:ExternalId"] = "reviewed-external-id"
        if extra_conditions:
            for operator, body in extra_conditions.items():
                raw_conditions.setdefault(operator, {}).update(body)
        assume_perm = _assume_perm_edge(src_arn=source_arn, dst_arn=target_arn)
        trust_src = Node(
            provider=PROVIDER_AWS,
            node_type=NODE_TYPE_WILDCARD_PRINCIPAL if wildcard_principal else NODE_TYPE_ACCOUNT_ROOT,
            provider_id="*" if wildcard_principal else root_arn,
            properties={"account_id": account_id, "is_synthetic": True},
        )
        trust = Edge(
            edge_type="sts:AssumeRole_trust",
            src=trust_src.to_ref(),
            dst=target.to_ref(),
            region=REGION_GLOBAL,
            features={
                "allow_controls": [
                    {
                        "control_type": "TRUST",
                        "policy_arn": target_arn,
                        "statement_index": 0,
                        "digest": "2" * 64,
                        "summary": f"trust {trust_src.provider_id}",
                    }
                ],
                "cross_account": False,
                "effect": "Allow",
                "has_conditions": bool(raw_conditions),
                "has_external_id": include_external_id,
                "is_wildcard_principal": wildcard_principal,
                "layer": "trust",
                "principal_type": "AWS",
                "raw_conditions": raw_conditions,
                "statement_index": 0,
                "trust_scope": TRUST_SCOPE_ANY_AWS_PRINCIPAL if wildcard_principal else TRUST_SCOPE_ACCOUNT_ROOT,
            },
        )
        admin_edges, hyperedge_nodes = self._admin_edges_from_policy(
            role_arn=target_arn,
            policy_arn=_AWS_MANAGED_ADMINISTRATOR_ACCESS_ARN,
        )
        return _make_facts(
            nodes=(source, target, trust_src, *hyperedge_nodes),
            edges=(assume_perm, trust, *admin_edges),
        )

    def _exact_assumed_role_pattern(self, role_arn: str) -> str:
        account_id = role_arn.split(":")[4]
        role_name = role_arn.rsplit("/", 1)[-1]
        return f"arn:aws:sts::{account_id}:assumed-role/{role_name}/*"

    def test_aws_managed_administratoraccess_is_clean_admin_witness(self) -> None:
        facts = self._single_hop_to_admin_with_policy(policy_arn=_AWS_MANAGED_ADMINISTRATOR_ACCESS_ARN)

        finding = self._finding_for_source(facts, _ALICE_ARN)

        assert finding.verdict.value == "validated"
        assert self._clean_witness_check_state(finding) == "pass"

    def test_custom_wildcard_admin_policy_remains_conservative(self) -> None:
        facts = self._single_hop_to_admin_with_policy(
            policy_arn="arn:aws:iam::111111\u003111111:policy/CustomAdminPolicy"
        )

        finding = self._finding_for_source(facts, _ALICE_ARN)

        assert finding.verdict.value == "inconclusive"
        assert self._clean_witness_check_state(finding) == "unknown"

    def test_spoofed_administratoraccess_policy_arn_remains_conservative(self) -> None:
        facts = self._single_hop_to_admin_with_policy(
            policy_arn="arn:aws:iam::111111\u003111111:policy/MyAdministratorAccess"
        )

        finding = self._finding_for_source(facts, _ALICE_ARN)

        assert finding.verdict.value == "inconclusive"
        assert self._clean_witness_check_state(finding) == "unknown"

    def test_conditioned_administratoraccess_witness_remains_conservative(self) -> None:
        facts = self._single_hop_to_admin_with_policy(
            policy_arn=_AWS_MANAGED_ADMINISTRATOR_ACCESS_ARN,
            conditions={"StringEquals": {"aws:PrincipalTag/admin-review": "approved"}},
        )

        finding = self._finding_for_source(facts, _ALICE_ARN)

        assert finding.verdict.value == "inconclusive"
        assert self._clean_witness_check_state(finding) == "unknown"

    def test_ambiguous_assumerole_path_to_aws_managed_administratoraccess_stays_inconclusive(self) -> None:
        facts = self._single_hop_to_admin_with_policy(
            policy_arn=_AWS_MANAGED_ADMINISTRATOR_ACCESS_ARN,
            wildcard_assume_role_permission=True,
        )

        finding = self._finding_for_source(facts, _ALICE_ARN)

        assert finding.verdict.value == "inconclusive"
        assert self._clean_witness_check_state(finding) == "unknown"

    def test_real_pilot_shape_prodapprole_to_proddbadminrole_validates(self) -> None:
        source_arn = "arn:aws:iam::111111\u003111111:role/ProdAppRole"
        target_arn = "arn:aws:iam::111111\u003111111:role/ProdDBAdminRole"
        facts = self._single_hop_to_admin_with_policy(
            source_arn=source_arn,
            target_arn=target_arn,
            policy_arn=_AWS_MANAGED_ADMINISTRATOR_ACCESS_ARN,
        )

        finding = self._finding_for_source(facts, source_arn)

        assert finding.target.provider_id == target_arn
        assert finding.verdict.value == "validated"
        assert self._clean_witness_check_state(finding) == "pass"

    def test_conditioned_account_root_exact_source_role_principalarn_validates(self) -> None:
        source_arn = "arn:aws:iam::111111\u003111111:role/ProdAppRole"
        target_arn = "arn:aws:iam::111111\u003111111:role/ProdDBAdminRole"
        facts = self._conditioned_root_trust_facts(
            source_arn=source_arn,
            target_arn=target_arn,
            principal_arn_value=source_arn,
        )

        finding = self._finding_for_source(facts, source_arn)

        assert finding.verdict.value == "validated"
        assert self._clean_witness_check_state(finding) == "pass"

    def test_conditioned_account_root_exact_assumed_role_pattern_validates(self) -> None:
        source_arn = "arn:aws:iam::111111\u003111111:role/ProdDeployRole"
        target_arn = "arn:aws:iam::111111\u003111111:role/ProdDBAdminRole"
        facts = self._conditioned_root_trust_facts(
            source_arn=source_arn,
            target_arn=target_arn,
            principal_arn_value=self._exact_assumed_role_pattern(source_arn),
        )

        finding = self._finding_for_source(facts, source_arn)

        assert finding.verdict.value == "validated"
        assert self._clean_witness_check_state(finding) == "pass"

    def test_conditioned_account_root_externalid_only_stays_inconclusive(self) -> None:
        source_arn = "arn:aws:iam::111111\u003111111:role/ProdAppRole"
        target_arn = "arn:aws:iam::111111\u003111111:role/ProdDBAdminRole"
        facts = self._conditioned_root_trust_facts(
            source_arn=source_arn,
            target_arn=target_arn,
            principal_arn_value=None,
        )

        finding = self._finding_for_source(facts, source_arn)

        assert finding.verdict.value == "inconclusive"
        assert self._clean_witness_check_state(finding) == "unknown"

    def test_conditioned_account_root_broad_role_wildcard_stays_inconclusive(self) -> None:
        source_arn = "arn:aws:iam::111111\u003111111:role/ProdAppRole"
        target_arn = "arn:aws:iam::111111\u003111111:role/ProdDBAdminRole"
        facts = self._conditioned_root_trust_facts(
            source_arn=source_arn,
            target_arn=target_arn,
            principal_arn_value="arn:aws:iam::111111\u003111111:role/*",
        )

        finding = self._finding_for_source(facts, source_arn)

        assert finding.verdict.value == "inconclusive"
        assert self._clean_witness_check_state(finding) == "unknown"

    def test_conditioned_account_root_broad_assumed_role_wildcard_stays_inconclusive(self) -> None:
        source_arn = "arn:aws:iam::111111\u003111111:role/ProdAppRole"
        target_arn = "arn:aws:iam::111111\u003111111:role/ProdDBAdminRole"
        facts = self._conditioned_root_trust_facts(
            source_arn=source_arn,
            target_arn=target_arn,
            principal_arn_value="arn:aws:sts::111111\u003111111:assumed-role/*",
        )

        finding = self._finding_for_source(facts, source_arn)

        assert finding.verdict.value == "inconclusive"
        assert self._clean_witness_check_state(finding) == "unknown"

    def test_conditioned_account_root_different_role_stays_inconclusive(self) -> None:
        source_arn = "arn:aws:iam::111111\u003111111:role/ProdAppRole"
        target_arn = "arn:aws:iam::111111\u003111111:role/ProdDBAdminRole"
        facts = self._conditioned_root_trust_facts(
            source_arn=source_arn,
            target_arn=target_arn,
            principal_arn_value="arn:aws:iam::111111\u003111111:role/OtherRole",
        )

        finding = self._finding_for_source(facts, source_arn)

        assert finding.verdict.value == "inconclusive"
        assert self._clean_witness_check_state(finding) == "unknown"

    def test_conditioned_account_root_unsupported_condition_stays_inconclusive(self) -> None:
        source_arn = "arn:aws:iam::111111\u003111111:role/ProdAppRole"
        target_arn = "arn:aws:iam::111111\u003111111:role/ProdDBAdminRole"
        facts = self._conditioned_root_trust_facts(
            source_arn=source_arn,
            target_arn=target_arn,
            principal_arn_value=source_arn,
            extra_conditions={"Bool": {"aws:MultiFactorAuthPresent": "true"}},
        )

        finding = self._finding_for_source(facts, source_arn)

        assert finding.verdict.value == "inconclusive"
        assert self._clean_witness_check_state(finding) == "unknown"

    def test_conditioned_wildcard_principal_stays_inconclusive(self) -> None:
        source_arn = "arn:aws:iam::111111\u003111111:role/ProdAppRole"
        target_arn = "arn:aws:iam::111111\u003111111:role/ProdDBAdminRole"
        facts = self._conditioned_root_trust_facts(
            source_arn=source_arn,
            target_arn=target_arn,
            principal_arn_value=source_arn,
            wildcard_principal=True,
        )

        finding = self._finding_for_source(facts, source_arn)

        assert finding.verdict.value == "inconclusive"
        assert self._clean_witness_check_state(finding) == "unknown"

    def test_conditioned_account_root_scp_blocker_still_wins(self) -> None:
        source_arn = "arn:aws:iam::111111\u003111111:role/ProdAppRole"
        target_arn = "arn:aws:iam::111111\u003111111:role/ProdDBAdminRole"
        facts = self._conditioned_root_trust_facts(
            source_arn=source_arn,
            target_arn=target_arn,
            principal_arn_value=source_arn,
        )
        trust_edge = next(edge for edge in facts.edges if edge.edge_type == "sts:AssumeRole_trust")
        scp = Constraint(
            provider=PROVIDER_AWS,
            constraint_type=CONSTRAINT_TYPE_SCP,
            scope_type="Account",
            scope_id="111111\u003111111",
            policy_id="p-deny-assumerole",
            statement_id="DenyAssumeRole",
            region=REGION_GLOBAL,
            properties={"deny_actions": ["sts:AssumeRole"], "resource_patterns": ["*"], "parse_status": "complete"},
        )
        blocked = FactGraph(
            nodes=facts.nodes,
            edges=facts.edges,
            constraints=(scp,),
            edge_constraints=(
                EdgeConstraint(
                    edge_id=trust_edge.edge_id,
                    constraint_id=scp.constraint_id,
                    governance_confidence="complete",
                    likely_blocking=True,
                    binding_reason="SCP denies sts:AssumeRole",
                ),
            ),
            scenario_hash=facts.scenario_hash,
            edge_budget_exhausted=False,
        )

        finding = self._finding_for_source(blocked, source_arn)

        assert finding.verdict.value == "blocked"
        assert finding.severity == "info"
        assert finding.blockers_observed[0].kind == "scp"

    def test_real_pilot_conditioned_account_root_sources_validate_under_safe_rule(self) -> None:
        target_arn = "arn:aws:iam::111111\u003111111:role/ProdDBAdminRole"
        source_arns = (
            "arn:aws:iam::111111\u003111111:role/ProdAppRole",
            "arn:aws:iam::111111\u003111111:role/ProdDeployRole",
            "arn:aws:iam::111111\u003111111:role/ProdReadOnlyRole",
        )
        principal_patterns = [
            *source_arns,
            *(self._exact_assumed_role_pattern(source_arn) for source_arn in source_arns),
        ]

        for source_arn in source_arns:
            facts = self._conditioned_root_trust_facts(
                source_arn=source_arn,
                target_arn=target_arn,
                principal_arn_value=principal_patterns,
            )

            finding = self._finding_for_source(facts, source_arn)

            assert finding.target.provider_id == target_arn
            assert finding.verdict.value == "validated"
            assert self._clean_witness_check_state(finding) == "pass"


class TestPermissionBoundaryReachability:
    def _boundary(self) -> Constraint:
        return Constraint(
            provider=PROVIDER_AWS,
            constraint_type=CONSTRAINT_TYPE_PERMISSION_BOUNDARY,
            scope_type="Principal",
            scope_id=_ALICE_ARN,
            policy_id="arn:aws:iam::111111\u003111111:policy/AliceBoundary",
            statement_id="Boundary",
            region=REGION_GLOBAL,
            properties={"boundary_arn": "arn:aws:iam::111111\u003111111:policy/AliceBoundary"},
        )

    def test_boundary_block_downgrades_reachable_admin_to_blocked(self) -> None:
        facts = _build_two_hop_chain()
        first_hop = next(
            e for e in facts.edges if e.edge_type == "sts:AssumeRole_permission" and e.src.provider_id == _ALICE_ARN
        )
        boundary = self._boundary()
        binding = EdgeConstraint(
            edge_id=first_hop.edge_id,
            constraint_id=boundary.constraint_id,
            governance_confidence="complete",
            likely_blocking=True,
            binding_reason="permission boundary excludes sts:AssumeRole on DevOps",
        )
        bounded = FactGraph(
            nodes=facts.nodes,
            edges=facts.edges,
            constraints=(boundary,),
            edge_constraints=(binding,),
            scenario_hash=facts.scenario_hash,
            edge_budget_exhausted=False,
        )

        findings = AdminReachabilityReasoner().run(bounded)
        alice_f = next(f for f in findings if f.source.provider_id == _ALICE_ARN)

        assert alice_f.verdict.value == "blocked"
        assert alice_f.severity == "info"
        check = next(c for c in alice_f.required_checks if c.name == "no_permission_boundary_blocks_reachable_walk")
        assert check.state.value == "fail"
        assert alice_f.blockers_observed[0].kind == "permission_boundary"
        assert boundary.constraint_id in alice_f.evidence.constraint_refs

    def test_boundary_block_on_admin_witness_downgrades_reachability(self) -> None:
        facts = _build_two_hop_chain()
        admin_witness = next(
            e for e in facts.edges if e.edge_type == "iam:*_permission" and e.src.provider_id == _ADMIN_ARN
        )
        boundary = self._boundary()
        binding = EdgeConstraint(
            edge_id=admin_witness.edge_id,
            constraint_id=boundary.constraint_id,
            governance_confidence="complete",
            likely_blocking=True,
            binding_reason="permission boundary excludes admin witness permission",
        )
        bounded = FactGraph(
            nodes=facts.nodes,
            edges=facts.edges,
            constraints=(boundary,),
            edge_constraints=(binding,),
            scenario_hash=facts.scenario_hash,
            edge_budget_exhausted=False,
        )

        findings = AdminReachabilityReasoner().run(bounded)
        alice_f = next(f for f in findings if f.source.provider_id == _ALICE_ARN)

        assert alice_f.verdict.value == "blocked"
        check = next(c for c in alice_f.required_checks if c.name == "no_permission_boundary_blocks_reachable_walk")
        assert check.state.value == "fail"
        assert boundary.constraint_id in alice_f.evidence.constraint_refs

    def test_boundary_needs_review_makes_reachable_admin_inconclusive(self) -> None:
        facts = _build_two_hop_chain()
        first_hop = next(
            e for e in facts.edges if e.edge_type == "sts:AssumeRole_permission" and e.src.provider_id == _ALICE_ARN
        )
        boundary = self._boundary()
        binding = EdgeConstraint(
            edge_id=first_hop.edge_id,
            constraint_id=boundary.constraint_id,
            governance_confidence="needs_review",
            likely_blocking=False,
            binding_reason="permission boundary condition requires runtime context",
        )
        bounded = FactGraph(
            nodes=facts.nodes,
            edges=facts.edges,
            constraints=(boundary,),
            edge_constraints=(binding,),
            scenario_hash=facts.scenario_hash,
            edge_budget_exhausted=False,
        )

        findings = AdminReachabilityReasoner().run(bounded)
        alice_f = next(f for f in findings if f.source.provider_id == _ALICE_ARN)

        assert alice_f.verdict.value == "inconclusive"
        check = next(c for c in alice_f.required_checks if c.name == "no_permission_boundary_blocks_reachable_walk")
        assert check.state.value == "unknown"


# ---------------------------------------------------------------------------
# SCP blockers
# ---------------------------------------------------------------------------


class TestScpReachability:
    def _scp(
        self,
        *,
        parse_status: str = "partial",
        resource_patterns: list[str] | None = None,
    ) -> Constraint:
        return Constraint(
            provider=PROVIDER_AWS,
            constraint_type=CONSTRAINT_TYPE_SCP,
            scope_type="ACCOUNT",
            scope_id="111111\u003111111",
            policy_id="p-env12",
            statement_id="Env12DenyAssumeEnv12Admin",
            region=REGION_GLOBAL,
            properties={
                "deny_actions": ["sts:AssumeRole"],
                "deny_not_actions": [],
                "exception_principal_patterns": [],
                "parse_status": parse_status,
                "resource_patterns": resource_patterns or [_ADMIN_ARN],
            },
        )

    def test_resource_scoped_scp_downgrades_reachable_admin_to_inconclusive(self) -> None:
        facts = _build_two_hop_chain()
        admin_trust = next(
            e for e in facts.edges if e.edge_type == "sts:AssumeRole_trust" and e.dst.provider_id == _ADMIN_ARN
        )
        scp = self._scp()
        binding = EdgeConstraint(
            edge_id=admin_trust.edge_id,
            constraint_id=scp.constraint_id,
            governance_confidence="partial",
            likely_blocking=False,
            binding_reason="resource-scoped SCP denies sts:AssumeRole on admin target",
        )
        bounded = FactGraph(
            nodes=facts.nodes,
            edges=facts.edges,
            constraints=(scp,),
            edge_constraints=(binding,),
            scenario_hash=facts.scenario_hash,
            edge_budget_exhausted=False,
        )

        findings = AdminReachabilityReasoner().run(bounded)
        alice_f = next(f for f in findings if f.source.provider_id == _ALICE_ARN)

        assert alice_f.verdict.value == "inconclusive"
        check = next(c for c in alice_f.required_checks if c.name == "no_scp_blocks_reachable_walk")
        assert check.state.value == "unknown"
        assert scp.constraint_id in alice_f.evidence.constraint_refs

    def test_complete_scp_block_downgrades_reachable_admin_to_blocked(self) -> None:
        facts = _build_two_hop_chain()
        admin_trust = next(
            e for e in facts.edges if e.edge_type == "sts:AssumeRole_trust" and e.dst.provider_id == _ADMIN_ARN
        )
        scp = self._scp(parse_status="complete", resource_patterns=["*"])
        binding = EdgeConstraint(
            edge_id=admin_trust.edge_id,
            constraint_id=scp.constraint_id,
            governance_confidence="complete",
            likely_blocking=True,
            binding_reason="SCP denies sts:AssumeRole",
        )
        bounded = FactGraph(
            nodes=facts.nodes,
            edges=facts.edges,
            constraints=(scp,),
            edge_constraints=(binding,),
            scenario_hash=facts.scenario_hash,
            edge_budget_exhausted=False,
        )

        findings = AdminReachabilityReasoner().run(bounded)
        alice_f = next(f for f in findings if f.source.provider_id == _ALICE_ARN)

        assert alice_f.verdict.value == "blocked"
        check = next(c for c in alice_f.required_checks if c.name == "no_scp_blocks_reachable_walk")
        assert check.state.value == "fail"
        assert alice_f.blockers_observed[0].kind == "scp"


# ---------------------------------------------------------------------------
# Hyperedge → inconclusive
# ---------------------------------------------------------------------------


class TestHyperedgeInconclusive:
    def test_clean_admin_path_plus_unrelated_ambiguous_branch_stays_validated(self) -> None:
        """An ambiguous alternate branch must not poison a separate clean admin proof."""
        facts = _build_two_hop_chain()
        non_admin = _role(_NON_ADMIN_ARN)
        ambiguous_perm = _assume_perm_edge(
            src_arn=_ALICE_ARN,
            dst_arn=_NON_ADMIN_ARN,
            digest="8" * 64,
            is_wildcard_resource=True,
        )
        ambiguous_trust = _trust_edge(
            principal_arn=_ALICE_ARN,
            target_arn=_NON_ADMIN_ARN,
            digest="9" * 64,
        )
        branched = _make_facts(
            nodes=(*facts.nodes, non_admin),
            edges=(*facts.edges, ambiguous_perm, ambiguous_trust),
        )

        findings = AdminReachabilityReasoner().run(branched)
        alice_f = next(f for f in findings if f.source.provider_id == _ALICE_ARN)

        assert alice_f.verdict.value == "validated"
        check = next(
            c for c in alice_f.required_checks if c.name == "at_least_one_reachable_chain_uses_clean_witnesses"
        )
        assert check.state.value == "pass"
        assert "ambiguous alternate walk evidence" in check.reason
        assert ambiguous_perm.edge_id in alice_f.evidence.edge_refs
        assert ambiguous_trust.edge_id in alice_f.evidence.edge_refs

    def test_only_ambiguous_path_to_admin_remains_inconclusive(self) -> None:
        """Admin reachability through only a wildcard hop remains inconclusive."""
        alice = _user(_ALICE_ARN)
        admin = _role(_ADMIN_ARN)
        wildcard_perm = _assume_perm_edge(
            src_arn=_ALICE_ARN,
            dst_arn=_ADMIN_ARN,
            is_wildcard_resource=True,
        )
        trust = _trust_edge(principal_arn=_ALICE_ARN, target_arn=_ADMIN_ARN)
        admin_grant = _admin_grant_edge(_ADMIN_ARN)
        facts = _make_facts(
            nodes=(alice, admin),
            edges=(wildcard_perm, trust, admin_grant),
        )

        findings = AdminReachabilityReasoner().run(facts)
        alice_f = next(f for f in findings if f.source.provider_id == _ALICE_ARN)

        assert alice_f.verdict.value == "inconclusive"
        check = next(
            c for c in alice_f.required_checks if c.name == "at_least_one_reachable_chain_uses_clean_witnesses"
        )
        assert check.state.value == "unknown"

    def test_wildcard_hop_produces_inconclusive(self) -> None:
        """Wildcard sts:AssumeRole on first hop → check 3 UNKNOWN."""
        alice = _user(_ALICE_ARN)
        devops = _role(_DEVOPS_ARN)
        admin = _role(_ADMIN_ARN)
        perm_1 = _assume_perm_edge(
            src_arn=_ALICE_ARN,
            dst_arn=_DEVOPS_ARN,
            is_wildcard_resource=True,
        )
        trust_1 = _trust_edge(principal_arn=_ALICE_ARN, target_arn=_DEVOPS_ARN)
        perm_2 = _assume_perm_edge(src_arn=_DEVOPS_ARN, dst_arn=_ADMIN_ARN)
        trust_2 = _trust_edge(principal_arn=_DEVOPS_ARN, target_arn=_ADMIN_ARN)
        admin_grant = _admin_grant_edge(_ADMIN_ARN)
        facts = _make_facts(
            nodes=(alice, devops, admin),
            edges=(perm_1, trust_1, perm_2, trust_2, admin_grant),
        )
        findings = AdminReachabilityReasoner().run(facts)
        alice_f = next(f for f in findings if f.source.provider_id == _ALICE_ARN)
        assert alice_f.verdict.value == "inconclusive"
        # Check 3 should be UNKNOWN
        c = next(c for c in alice_f.required_checks if c.name == "at_least_one_reachable_chain_uses_clean_witnesses")
        assert c.state.value == "unknown"


class TestDepthLimitConservative:
    def test_clean_admin_path_still_inconclusive_when_alternate_walk_hits_depth_limit(self) -> None:
        alice = _user(_ALICE_ARN)
        admin = _role(_ADMIN_ARN)
        deploy = _role(_DEPLOY_ARN)
        devops = _role(_DEVOPS_ARN)
        prod = _role(_PROD_ARN)
        non_admin = _role(_NON_ADMIN_ARN)

        direct_perm = _assume_perm_edge(src_arn=_ALICE_ARN, dst_arn=_ADMIN_ARN, digest="1" * 64)
        direct_trust = _trust_edge(principal_arn=_ALICE_ARN, target_arn=_ADMIN_ARN, digest="2" * 64)
        branch_1_perm = _assume_perm_edge(src_arn=_ALICE_ARN, dst_arn=_DEPLOY_ARN, digest="3" * 64)
        branch_1_trust = _trust_edge(principal_arn=_ALICE_ARN, target_arn=_DEPLOY_ARN, digest="4" * 64)
        branch_2_perm = _assume_perm_edge(src_arn=_DEPLOY_ARN, dst_arn=_DEVOPS_ARN, digest="5" * 64)
        branch_2_trust = _trust_edge(principal_arn=_DEPLOY_ARN, target_arn=_DEVOPS_ARN, digest="6" * 64)
        branch_3_perm = _assume_perm_edge(src_arn=_DEVOPS_ARN, dst_arn=_PROD_ARN, digest="7" * 64)
        branch_3_trust = _trust_edge(principal_arn=_DEVOPS_ARN, target_arn=_PROD_ARN, digest="8" * 64)
        branch_4_perm = _assume_perm_edge(src_arn=_PROD_ARN, dst_arn=_NON_ADMIN_ARN, digest="9" * 64)
        branch_4_trust = _trust_edge(principal_arn=_PROD_ARN, target_arn=_NON_ADMIN_ARN, digest="0" * 64)
        admin_grant = _admin_grant_edge(_ADMIN_ARN)
        facts = _make_facts(
            nodes=(alice, admin, deploy, devops, prod, non_admin),
            edges=(
                direct_perm,
                direct_trust,
                branch_1_perm,
                branch_1_trust,
                branch_2_perm,
                branch_2_trust,
                branch_3_perm,
                branch_3_trust,
                branch_4_perm,
                branch_4_trust,
                admin_grant,
            ),
        )

        findings = AdminReachabilityReasoner().run(facts)
        alice_f = next(f for f in findings if f.source.provider_id == _ALICE_ARN)

        assert alice_f.verdict.value == "inconclusive"
        check = next(c for c in alice_f.required_checks if c.name == "walk_terminated_within_depth_limit")
        assert check.state.value == "unknown"


# ---------------------------------------------------------------------------
# 3-hop chain — Alice reaches Admin via DevOps → Prod (intermediate not admin)
# ---------------------------------------------------------------------------


class TestThreeHopReachability:
    def test_alice_reaches_admin_through_three_hops(self) -> None:
        """Alice → DevOps → Prod → Admin. Only Admin is admin-equivalent."""
        findings = AdminReachabilityReasoner().run(_build_three_hop_chain())
        alice_f = next(f for f in findings if f.source.provider_id == _ALICE_ARN)
        assert alice_f.verdict.value == "validated"
        assert alice_f.severity == "high"  # 1 admin reachable
        assert alice_f.target.provider_id == _ADMIN_ARN


# ---------------------------------------------------------------------------
# Determinism
# ---------------------------------------------------------------------------


class TestDeterminism:
    def test_double_run_same_findings(self) -> None:
        f1 = AdminReachabilityReasoner().run(_build_two_hop_chain())
        f2 = AdminReachabilityReasoner().run(_build_two_hop_chain())
        assert len(f1) == len(f2)
        for a, b in zip(f1, f2, strict=True):
            assert a.finding_id == b.finding_id
            assert a.evidence.bundle_digest == b.evidence.bundle_digest

    def test_findings_sorted_by_source_arn(self) -> None:
        """Output ordering is stable across runs."""
        findings = AdminReachabilityReasoner().run(_build_two_hop_chain())
        sources = [f.source.provider_id for f in findings]
        assert sources == sorted(sources)
