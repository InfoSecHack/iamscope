"""S09 tests: FactGraph wrapper and the critical tristate `has_action`.

Per plan §3.3, `has_action` is the load-bearing correctness method for
every reasoner. The test classes here cover:

1. Construction + index lookups (node_by_id, node_by_provider_id,
   edges_from, edges_to, edges_by_action, bindings_for_edge).
2. has_action tristate behavior across PASS/FAIL/UNKNOWN cases.
3. The plan §3.3 invariant: a reasoner that breaks `has_action` so
   it returns PASS for hyperedges produces silent false positives.
   The negative tests here exist to make that breakage visible.
4. passrole_edges_from and trust_policy_of convenience helpers.
"""

from __future__ import annotations

from iamscope.constants import (
    NODE_TYPE_HYPEREDGE,
    NODE_TYPE_IAM_ROLE,
    NODE_TYPE_IAM_USER,
    PROVIDER_AWS,
    REGION_GLOBAL,
)
from iamscope.models import Edge, Node, NodeRef
from iamscope.reasoner.fact_graph import FactGraph
from iamscope.reasoner.verdict import CheckState

# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


_ALICE_ARN = "arn:aws:iam::111111111111:user/Alice"
_BOB_ARN = "arn:aws:iam::111111111111:user/Bob"
_PROD_ROLE_ARN = "arn:aws:iam::222222222222:role/ProdAdmin"
_DEV_ROLE_ARN = "arn:aws:iam::222222222222:role/DevAdmin"


def _user(arn: str = _ALICE_ARN) -> Node:
    return Node(
        provider=PROVIDER_AWS,
        node_type=NODE_TYPE_IAM_USER,
        provider_id=arn,
        region=REGION_GLOBAL,
        properties={"account_id": arn.split(":")[4]},
    )


def _role(arn: str = _PROD_ROLE_ARN) -> Node:
    return Node(
        provider=PROVIDER_AWS,
        node_type=NODE_TYPE_IAM_ROLE,
        provider_id=arn,
        region=REGION_GLOBAL,
        properties={"account_id": arn.split(":")[4]},
    )


def _hyperedge_node(synthetic_id: str = "hyperedge_test_001") -> Node:
    """Build a Node with __hyperedge__ node_type, mirroring the collector."""
    return Node(
        provider=PROVIDER_AWS,
        node_type=NODE_TYPE_HYPEREDGE,
        provider_id=synthetic_id,
        region=REGION_GLOBAL,
        properties={"would_expand_to": 50, "expansion_type": "iam:PassRole"},
    )


def _explicit_passrole_edge(
    *,
    src_arn: str = _ALICE_ARN,
    dst_arn: str = _PROD_ROLE_ARN,
    has_conditions: bool = False,
) -> Edge:
    """A clean passrole permission edge — explicit resource, no wildcards.

    This is the canonical PASS-witness shape for `has_action`.
    """
    return Edge(
        edge_type="iam:PassRole_permission",
        src=_user(src_arn).to_ref(),
        dst=_role(dst_arn).to_ref(),
        region=REGION_GLOBAL,
        features={
            "action_matched_via": "exact",
            "effect": "Allow",
            "has_conditions": has_conditions,
            "is_wildcard_resource": False,
            "layer": "permission",
            "policy_arn": "",
            "policy_name": "AlicePassRole",
            "raw_conditions": {},
            "resource_pattern": dst_arn,
            "statement_index": 0,
        },
    )


def _wildcard_expanded_passrole_edge(
    *,
    src_arn: str = _ALICE_ARN,
    dst_arn: str = _PROD_ROLE_ARN,
) -> Edge:
    """A passrole edge created by wildcard-resource expansion.

    `is_wildcard_resource=True` marks this as the UNKNOWN witness case
    from plan §3.3 — the source policy used `Resource: "*"` and the
    expansion code resolved it to this dst, but conditions or
    namespace nuances might still apply.
    """
    return Edge(
        edge_type="iam:PassRole_permission",
        src=_user(src_arn).to_ref(),
        dst=_role(dst_arn).to_ref(),
        region=REGION_GLOBAL,
        features={
            "action_matched_via": "exact",
            "effect": "Allow",
            "expanded_from_wildcard": True,
            "has_conditions": False,
            "is_wildcard_resource": True,
            "layer": "permission",
            "policy_arn": "",
            "policy_name": "AliceAdmin",
            "raw_conditions": {},
            "resource_pattern": "*",
            "statement_index": 0,
        },
    )


def _hyperedge_passrole_edge(src_arn: str = _ALICE_ARN) -> Edge:
    """A warn-suppressed wildcard expansion → __hyperedge__ dst.

    This is the canonical UNKNOWN-witness shape for hyperedge cases.
    Per plan §4B.6 fixture F, this is the highest-priority false-positive
    guard: a reasoner that treats this edge as PASS produces silent FPs.
    """
    return Edge(
        edge_type="iam:PassRole_permission",
        src=_user(src_arn).to_ref(),
        dst=_hyperedge_node().to_ref(),
        region=REGION_GLOBAL,
        features={
            "action_matched_via": "exact",
            "effect": "Allow",
            "expansion_mode": "warn",
            "has_conditions": False,
            "is_wildcard_resource": True,
            "layer": "permission",
            "policy_arn": "",
            "policy_name": "AliceAdmin",
            "raw_conditions": {},
            "resource_pattern": "*",
            "statement_index": 0,
            "suppressed": True,
            "would_expand_to": 50,
        },
    )


def _trust_edge(*, src_arn: str = _ALICE_ARN, dst_arn: str = _PROD_ROLE_ARN) -> Edge:
    return Edge(
        edge_type="sts:AssumeRole_trust",
        src=NodeRef(
            provider=PROVIDER_AWS,
            node_type=NODE_TYPE_IAM_USER,
            provider_id=src_arn,
        ),
        dst=NodeRef(
            provider=PROVIDER_AWS,
            node_type=NODE_TYPE_IAM_ROLE,
            provider_id=dst_arn,
        ),
        region=REGION_GLOBAL,
        features={"layer": "trust"},
    )


def _make_graph(
    *,
    nodes: tuple[Node, ...] = (),
    edges: tuple[Edge, ...] = (),
    constraints: tuple = (),
    edge_constraints: tuple = (),
    edge_budget_exhausted: bool = False,
) -> FactGraph:
    return FactGraph(
        nodes=nodes,
        edges=edges,
        constraints=constraints,
        edge_constraints=edge_constraints,
        scenario_hash="deadbeef" * 8,
        edge_budget_exhausted=edge_budget_exhausted,
    )


# ---------------------------------------------------------------------------
# Construction & basic field passthrough
# ---------------------------------------------------------------------------


class TestFactGraphConstruction:
    """A FactGraph can be constructed from empty inputs and a populated set."""

    def test_empty_graph_constructs(self) -> None:
        graph = _make_graph()
        assert graph.nodes == ()
        assert graph.edges == ()
        assert graph.scenario_hash == "deadbeef" * 8
        assert graph.edge_budget_exhausted is False

    def test_edge_budget_exhausted_passthrough(self) -> None:
        graph = _make_graph(edge_budget_exhausted=True)
        assert graph.edge_budget_exhausted is True

    def test_populated_graph_constructs(self) -> None:
        alice = _user()
        prod_role = _role()
        edge = _explicit_passrole_edge()
        graph = _make_graph(
            nodes=(alice, prod_role),
            edges=(edge,),
        )
        assert len(graph.nodes) == 2
        assert len(graph.edges) == 1


# ---------------------------------------------------------------------------
# Index lookups
# ---------------------------------------------------------------------------


class TestNodeLookups:
    """node_by_id and node_by_provider_id index correctly."""

    def test_node_by_provider_id_finds_user(self) -> None:
        alice = _user()
        graph = _make_graph(nodes=(alice,))
        assert graph.node_by_provider_id(_ALICE_ARN) is alice

    def test_node_by_provider_id_returns_none_for_missing(self) -> None:
        graph = _make_graph()
        assert graph.node_by_provider_id("nonexistent") is None

    def test_node_by_id_finds_node(self) -> None:
        alice = _user()
        graph = _make_graph(nodes=(alice,))
        assert graph.node_by_id(alice.node_id) is alice

    def test_node_by_id_returns_none_for_missing(self) -> None:
        graph = _make_graph()
        assert graph.node_by_id("missing_id") is None


class TestEdgeLookups:
    """edges_from, edges_to, edges_by_action, bindings_for_edge."""

    def test_edges_from_finds_principal_edges(self) -> None:
        edge = _explicit_passrole_edge()
        graph = _make_graph(edges=(edge,))
        result = graph.edges_from(_ALICE_ARN)
        assert len(result) == 1
        assert result[0] is edge

    def test_edges_from_returns_empty_for_unknown_principal(self) -> None:
        graph = _make_graph()
        assert graph.edges_from("arn:aws:iam::999:user/Nobody") == ()

    def test_edges_to_finds_target_edges(self) -> None:
        edge = _explicit_passrole_edge()
        graph = _make_graph(edges=(edge,))
        result = graph.edges_to(_PROD_ROLE_ARN)
        assert len(result) == 1
        assert result[0] is edge

    def test_edges_by_action_indexes_permission_edges(self) -> None:
        edge = _explicit_passrole_edge()
        graph = _make_graph(edges=(edge,))
        result = graph.edges_by_action("iam:PassRole")
        assert len(result) == 1

    def test_edges_by_action_indexes_trust_edges(self) -> None:
        trust = _trust_edge()
        graph = _make_graph(edges=(trust,))
        result = graph.edges_by_action("sts:AssumeRole")
        assert len(result) == 1

    def test_edges_by_action_returns_empty_for_unknown_action(self) -> None:
        graph = _make_graph(edges=(_explicit_passrole_edge(),))
        assert graph.edges_by_action("ec2:TerminateInstances") == ()

    def test_bindings_for_edge_returns_empty_when_no_bindings(self) -> None:
        edge = _explicit_passrole_edge()
        graph = _make_graph(edges=(edge,))
        assert graph.bindings_for_edge(edge.edge_id) == ()


# ---------------------------------------------------------------------------
# THE CRITICAL CORRECTNESS SUITE: tristate has_action
# ---------------------------------------------------------------------------


class TestHasActionPass:
    """PASS witness scenarios — explicit edges with no ambiguity flags."""

    def test_explicit_edge_returns_pass(self) -> None:
        """A clean permission edge → PASS."""
        edge = _explicit_passrole_edge()
        graph = _make_graph(edges=(edge,))
        result = graph.has_action(_ALICE_ARN, "iam:PassRole", _PROD_ROLE_ARN)
        assert result is CheckState.PASS

    def test_explicit_edge_with_wildcard_resource_query_returns_pass(self) -> None:
        """has_action(..., resource_pattern='*') matches any explicit edge."""
        edge = _explicit_passrole_edge()
        graph = _make_graph(edges=(edge,))
        assert graph.has_action(_ALICE_ARN, "iam:PassRole", "*") is CheckState.PASS

    def test_one_pass_witness_overrides_unknown_witnesses(self) -> None:
        """One clean edge in a sea of ambiguous edges → still PASS.

        Plan §3.3: 'a reasoner that has any clean evidence is allowed
        to claim PASS even if other matching edges are ambiguous.'
        """
        clean = _explicit_passrole_edge(dst_arn=_PROD_ROLE_ARN)
        wildcard = _wildcard_expanded_passrole_edge(dst_arn=_PROD_ROLE_ARN)
        graph = _make_graph(edges=(wildcard, clean))
        assert graph.has_action(_ALICE_ARN, "iam:PassRole", _PROD_ROLE_ARN) is CheckState.PASS


class TestHasActionFail:
    """FAIL scenarios — no matching edge at all."""

    def test_no_edges_returns_fail(self) -> None:
        graph = _make_graph()
        assert graph.has_action(_ALICE_ARN, "iam:PassRole") is CheckState.FAIL

    def test_principal_has_no_matching_action_returns_fail(self) -> None:
        """Principal has SOME edges but none for the requested action."""
        unrelated = Edge(
            edge_type="ec2:TerminateInstances_permission",
            src=_user(_ALICE_ARN).to_ref(),
            dst=_role(_PROD_ROLE_ARN).to_ref(),
            features={
                "has_conditions": False,
                "is_wildcard_resource": False,
            },
        )
        graph = _make_graph(edges=(unrelated,))
        assert graph.has_action(_ALICE_ARN, "iam:PassRole") is CheckState.FAIL

    def test_other_principal_returns_fail(self) -> None:
        """Alice has the edge; Bob does not."""
        edge = _explicit_passrole_edge(src_arn=_ALICE_ARN)
        graph = _make_graph(edges=(edge,))
        assert graph.has_action(_BOB_ARN, "iam:PassRole") is CheckState.FAIL

    def test_specific_resource_no_match_returns_fail(self) -> None:
        """Edge dst doesn't match the requested specific resource → FAIL."""
        edge = _explicit_passrole_edge(dst_arn=_PROD_ROLE_ARN)
        graph = _make_graph(edges=(edge,))
        result = graph.has_action(_ALICE_ARN, "iam:PassRole", _DEV_ROLE_ARN)
        assert result is CheckState.FAIL


class TestHasActionUnknown:
    """The headline correctness suite. UNKNOWN must NEVER be collapsed to FAIL."""

    def test_hyperedge_dst_returns_unknown(self) -> None:
        """The plan §4B.6 fixture F false-positive guard.

        A reasoner that treats hyperedges as PASS produces silent false
        positives. A reasoner that treats hyperedges as FAIL produces
        silent false negatives. Both are wrong. The correct answer is
        UNKNOWN, and the reasoner must surface that to the human reviewer.
        """
        edge = _hyperedge_passrole_edge()
        graph = _make_graph(edges=(edge,))
        result = graph.has_action(_ALICE_ARN, "iam:PassRole", _PROD_ROLE_ARN)
        assert result is CheckState.UNKNOWN

    def test_hyperedge_with_wildcard_query_returns_unknown(self) -> None:
        """Even when querying for any resource, hyperedge alone is UNKNOWN."""
        edge = _hyperedge_passrole_edge()
        graph = _make_graph(edges=(edge,))
        assert graph.has_action(_ALICE_ARN, "iam:PassRole", "*") is CheckState.UNKNOWN

    def test_wildcard_resource_expansion_returns_unknown(self) -> None:
        """An is_wildcard_resource=True edge is an UNKNOWN witness.

        Per plan §3.3: even though the parser already resolved the
        wildcard to a specific dst, the original wildcard might cover
        nuances (region scoping, condition keys) that the resolver
        missed. Conservative answer: UNKNOWN.
        """
        edge = _wildcard_expanded_passrole_edge()
        graph = _make_graph(edges=(edge,))
        result = graph.has_action(_ALICE_ARN, "iam:PassRole", _PROD_ROLE_ARN)
        assert result is CheckState.UNKNOWN

    def test_has_conditions_returns_unknown(self) -> None:
        """An explicit edge with has_conditions=True → UNKNOWN.

        The reasoner cannot evaluate runtime condition context from a
        static fact graph, so any conditioned edge is automatically
        ambiguous. This is what makes the §3.4 'VALIDATED requires no
        condition_context assumption' invariant load-bearing.
        """
        edge = _explicit_passrole_edge(has_conditions=True)
        graph = _make_graph(edges=(edge,))
        result = graph.has_action(_ALICE_ARN, "iam:PassRole", _PROD_ROLE_ARN)
        assert result is CheckState.UNKNOWN

    def test_only_unknown_witnesses_returns_unknown(self) -> None:
        """Multiple ambiguous edges, no clean ones → UNKNOWN.

        A reasoner that scans the matching edge list and finds only
        wildcard expansions / hyperedges / conditioned edges must
        return UNKNOWN, not collapse to FAIL.
        """
        wildcard = _wildcard_expanded_passrole_edge()
        hyper = _hyperedge_passrole_edge()
        conditioned = _explicit_passrole_edge(has_conditions=True)
        graph = _make_graph(edges=(wildcard, hyper, conditioned))
        result = graph.has_action(_ALICE_ARN, "iam:PassRole", _PROD_ROLE_ARN)
        assert result is CheckState.UNKNOWN


class TestHasActionResourceMatching:
    """resource_pattern argument supports specific ARNs and fnmatch wildcards."""

    def test_specific_resource_match_returns_pass(self) -> None:
        graph = _make_graph(
            edges=(
                _explicit_passrole_edge(dst_arn=_PROD_ROLE_ARN),
                _explicit_passrole_edge(dst_arn=_DEV_ROLE_ARN),
            )
        )
        # Filter to only the prod role.
        result = graph.has_action(_ALICE_ARN, "iam:PassRole", _PROD_ROLE_ARN)
        assert result is CheckState.PASS

    def test_fnmatch_wildcard_pattern_matches(self) -> None:
        """fnmatch.fnmatchcase semantics: '*Admin' matches both prod/dev."""
        graph = _make_graph(edges=(_explicit_passrole_edge(dst_arn=_PROD_ROLE_ARN),))
        # Match by suffix wildcard.
        result = graph.has_action(
            _ALICE_ARN,
            "iam:PassRole",
            "arn:aws:iam::222222222222:role/*",
        )
        assert result is CheckState.PASS


# ---------------------------------------------------------------------------
# Convenience helpers for higher-level reasoners
# ---------------------------------------------------------------------------


class TestPassroleEdgesFrom:
    """passrole_edges_from filters to iam:PassRole_permission edges."""

    def test_returns_only_passrole_edges(self) -> None:
        passrole = _explicit_passrole_edge()
        unrelated = Edge(
            edge_type="iam:CreateRole_permission",
            src=_user(_ALICE_ARN).to_ref(),
            dst=_role(_PROD_ROLE_ARN).to_ref(),
            features={"has_conditions": False, "is_wildcard_resource": False},
        )
        graph = _make_graph(edges=(passrole, unrelated))
        result = graph.passrole_edges_from(_ALICE_ARN)
        assert len(result) == 1
        assert result[0] is passrole

    def test_returns_empty_for_principal_with_no_passrole(self) -> None:
        graph = _make_graph()
        assert graph.passrole_edges_from(_ALICE_ARN) == ()


class TestTrustPolicyOf:
    """trust_policy_of returns trust edges TO a role."""

    def test_returns_trust_edges_to_role(self) -> None:
        trust = _trust_edge(src_arn=_ALICE_ARN, dst_arn=_PROD_ROLE_ARN)
        permission = _explicit_passrole_edge(dst_arn=_PROD_ROLE_ARN)
        graph = _make_graph(edges=(trust, permission))
        result = graph.trust_policy_of(_PROD_ROLE_ARN)
        assert len(result) == 1
        assert result[0] is trust

    def test_returns_empty_for_role_with_no_trust(self) -> None:
        graph = _make_graph()
        assert graph.trust_policy_of(_PROD_ROLE_ARN) == ()
