"""Reasoner fact graph wrapper — S09.

`FactGraph` is a read-only view of a scenario plus its binding metadata,
with typed lookup helpers that reasoners use instead of walking raw
node/edge lists. The class is a frozen dataclass; all indexes are built
once in `__post_init__` and stored in private fields via
`object.__setattr__` (the standard frozen-dataclass-with-cache pattern).

The most important method is `has_action`, which is a TRISTATE
returning `CheckState.PASS`, `CheckState.UNKNOWN`, or `CheckState.FAIL`.
**A reasoner must never collapse UNKNOWN into FAIL.** Per plan §3.3, this
is the single most common way false positives get produced — a wildcard
expansion edge or a hyperedge match is NOT proof that the principal
cannot reach the target. The whole `_build_hyperedge` code path in the
S05 collector exists specifically so wildcard expansion above the budget
threshold becomes an UNKNOWN witness here, not a silent FAIL.

Construction is O(N) over the input lists, where N is the largest of
nodes, edges, constraints, edge_constraints. Lookups are O(1) average
case via dict indexes built in __post_init__.
"""

from __future__ import annotations

import fnmatch
from dataclasses import dataclass, field
from typing import Any

from iamscope.constants import NODE_TYPE_HYPEREDGE
from iamscope.models import Constraint, Edge, EdgeConstraint, Node
from iamscope.reasoner.verdict import CheckState
from iamscope.truth.probe_overlay import ProbeRecord


@dataclass(frozen=True)
class FactGraph:
    """Read-only view of a scenario + its binding metadata.

    Construction-time arguments are the raw fact lists from the
    pipeline. Indexes are built lazily in `__post_init__` and stored
    via `object.__setattr__` because the dataclass is frozen.
    """

    nodes: tuple[Node, ...]
    edges: tuple[Edge, ...]
    constraints: tuple[Constraint, ...]
    edge_constraints: tuple[EdgeConstraint, ...]
    scenario_hash: str
    edge_budget_exhausted: bool
    probe_records_by_edge: dict[str, tuple[ProbeRecord, ...]] = field(
        default_factory=dict,
        repr=False,
        compare=False,
    )

    # ---------------------------------------------------------------
    # Private indexes (built in __post_init__).
    # `compare=False` keeps equality comparisons working without
    # touching cache state. `repr=False` keeps the FactGraph repr
    # readable instead of dumping every index dict.
    # ---------------------------------------------------------------
    _node_by_id: dict[str, Node] = field(
        default_factory=dict,
        repr=False,
        compare=False,
    )
    _node_by_provider_id: dict[str, Node] = field(
        default_factory=dict,
        repr=False,
        compare=False,
    )
    _edges_from_index: dict[str, tuple[Edge, ...]] = field(
        default_factory=dict,
        repr=False,
        compare=False,
    )
    _edges_to_index: dict[str, tuple[Edge, ...]] = field(
        default_factory=dict,
        repr=False,
        compare=False,
    )
    _edges_by_action_index: dict[str, tuple[Edge, ...]] = field(
        default_factory=dict,
        repr=False,
        compare=False,
    )
    _bindings_for_edge_index: dict[str, tuple[EdgeConstraint, ...]] = field(
        default_factory=dict,
        repr=False,
        compare=False,
    )
    _constraint_by_id: dict[str, Constraint] = field(
        default_factory=dict,
        repr=False,
        compare=False,
    )

    def __post_init__(self) -> None:
        # Build all indexes once. The default_factory dicts are empty
        # at this point — we populate them via object.__setattr__ to
        # respect the frozen contract.
        node_by_id: dict[str, Node] = {}
        node_by_provider_id: dict[str, Node] = {}
        for node in self.nodes:
            node_by_id[node.node_id] = node
            node_by_provider_id[node.provider_id] = node
        object.__setattr__(self, "_node_by_id", node_by_id)
        object.__setattr__(self, "_node_by_provider_id", node_by_provider_id)

        edges_from: dict[str, list[Edge]] = {}
        edges_to: dict[str, list[Edge]] = {}
        edges_by_action: dict[str, list[Edge]] = {}
        for edge in self.edges:
            edges_from.setdefault(edge.src.provider_id, []).append(edge)
            edges_to.setdefault(edge.dst.provider_id, []).append(edge)
            # Permission edges have edge_type "<action>_permission"; trust
            # edges have edge_type "<action>_trust". Index by the bare
            # action half so callers can ask "edges with action X" without
            # caring whether they're trust or permission edges.
            action = _action_from_edge_type(edge.edge_type)
            if action:
                edges_by_action.setdefault(action, []).append(edge)
        # Freeze the lists to tuples so the public lookups are immutable.
        # **S10 determinism requirement (plan §4A.6 failure mode 5):** sort
        # each index value by `edge_id` so reasoners that iterate
        # `edges_from(principal)` / `edges_to(role)` / `edges_by_action(act)`
        # see edges in a stable order across runs. Without this sort, two
        # runs over the same fact graph could produce different finding IDs
        # because `bundle_digest` reflects trace entry order, which depends
        # on iteration order.
        object.__setattr__(
            self,
            "_edges_from_index",
            {k: tuple(sorted(v, key=lambda e: e.edge_id)) for k, v in edges_from.items()},
        )
        object.__setattr__(
            self,
            "_edges_to_index",
            {k: tuple(sorted(v, key=lambda e: e.edge_id)) for k, v in edges_to.items()},
        )
        object.__setattr__(
            self,
            "_edges_by_action_index",
            {k: tuple(sorted(v, key=lambda e: e.edge_id)) for k, v in edges_by_action.items()},
        )

        bindings_for_edge: dict[str, list[EdgeConstraint]] = {}
        for ec in self.edge_constraints:
            bindings_for_edge.setdefault(ec.edge_id, []).append(ec)
        object.__setattr__(
            self,
            "_bindings_for_edge_index",
            {k: tuple(v) for k, v in bindings_for_edge.items()},
        )

        # **S12 helper:** index constraints by ID so reasoners that walk
        # bindings can look up the parent Constraint to distinguish SCP
        # from PERMISSION_BOUNDARY. Without this, every reasoner that
        # cares about constraint type would have to build its own dict
        # locally.
        constraint_by_id: dict[str, Constraint] = {}
        for c in self.constraints:
            constraint_by_id[c.constraint_id] = c
        object.__setattr__(self, "_constraint_by_id", constraint_by_id)

    # ---------------------------------------------------------------
    # Public lookup API
    # ---------------------------------------------------------------

    def node_by_id(self, node_id: str) -> Node | None:
        """Return the node with the given deterministic ID, or None."""
        return self._node_by_id.get(node_id)

    def node_by_provider_id(self, pid: str) -> Node | None:
        """Return the node with the given provider_id (e.g., full ARN), or None."""
        return self._node_by_provider_id.get(pid)

    def edges_from(self, src_provider_id: str) -> tuple[Edge, ...]:
        """All edges with src.provider_id == src_provider_id, in input order."""
        return self._edges_from_index.get(src_provider_id, ())

    def edges_to(self, dst_provider_id: str) -> tuple[Edge, ...]:
        """All edges with dst.provider_id == dst_provider_id, in input order."""
        return self._edges_to_index.get(dst_provider_id, ())

    def edges_by_action(self, action: str) -> tuple[Edge, ...]:
        """All edges whose edge_type encodes the given action.

        For example, `edges_by_action("iam:PassRole")` returns every edge
        with `edge_type == "iam:PassRole_permission"` AND every edge with
        `edge_type == "iam:PassRole_trust"` (sts:AssumeRole_trust uses
        the action "sts:AssumeRole" by the same convention).
        """
        return self._edges_by_action_index.get(action, ())

    def bindings_for_edge(self, edge_id: str) -> tuple[EdgeConstraint, ...]:
        """All EdgeConstraint records for the given edge_id, in input order.

        A single edge can have multiple bindings if multiple SCPs and/or
        permission boundaries apply. Reasoners walk the full list to
        evaluate the strongest blocker.
        """
        return self._bindings_for_edge_index.get(edge_id, ())

    def probe_records_for_edge(self, edge_id: str) -> tuple[ProbeRecord, ...]:
        """All probe overlay records for the given edge_id, in overlay order.

        This is intentionally sidecar-only state. It is not part of
        scenario.json, does not affect edge IDs, and defaults to empty so
        existing reasoner behavior is unchanged unless an overlay is supplied.
        """
        return self.probe_records_by_edge.get(edge_id, ())

    def constraint_by_id(self, constraint_id: str) -> Constraint | None:
        """Look up a parent Constraint by its constraint_id.

        Reasoners that walk `bindings_for_edge` get back EdgeConstraint
        records, which carry only `edge_id` + `constraint_id` plus the
        governance metadata. Distinguishing SCP from PERMISSION_BOUNDARY
        (or trust condition) requires looking up the parent Constraint
        — which is what this method does. Returns None if the
        constraint_id is not in the graph.

        Added in S12 for the passrole_lambda reasoner's checks 4–7
        (SCP vs boundary blocker filtering). Generic enough to benefit
        every future reasoner that needs constraint-type distinction.
        """
        return self._constraint_by_id.get(constraint_id)

    def has_action(
        self,
        principal_arn: str,
        action: str,
        resource_pattern: str = "*",
    ) -> CheckState:
        """Tristate: does this principal have this action against this resource?

        Returns:
            CheckState.PASS  — at least one explicit, non-conditioned,
                non-wildcard-expanded permission edge exists from
                `principal_arn` for `action` against a resource matching
                `resource_pattern`. The principal definitely has the
                action against the requested resource.
            CheckState.UNKNOWN — at least one matching edge exists but
                EVERY matching edge has at least one ambiguity flag:
                a `__hyperedge__` dst (wildcard expansion was suppressed),
                `features.is_wildcard_resource == True` (the source
                policy used a wildcard resource pattern that the
                expansion code resolved to this dst, but the resolution
                might have missed conditions or namespace nuances), or
                `features.has_conditions == True` (the statement has
                a Condition block whose runtime context the reasoner
                cannot evaluate).
            CheckState.FAIL — no edge from `principal_arn` for `action`
                exists at all (or no edge survives the resource match).

        **A reasoner must never collapse UNKNOWN into FAIL.** Per plan
        §3.3 and §4B.6, that is the single most common false-positive
        production path. The hyperedge code in the collector exists
        specifically so this method can return UNKNOWN instead of
        silently treating wildcard expansions as missing edges.

        Args:
            principal_arn: src principal ARN to look up.
            action: bare action string (e.g., "iam:PassRole",
                "lambda:CreateFunction"). NOT the full edge_type — the
                method appends "_permission" internally.
            resource_pattern: target resource ARN to match against
                edge.dst.provider_id. Defaults to "*" which matches any
                target. fnmatch wildcards are supported.

        Returns:
            CheckState enum value (never None).
        """
        expected_edge_type = f"{action}_permission"
        matching_edges = [e for e in self.edges_from(principal_arn) if e.edge_type == expected_edge_type]
        if not matching_edges:
            return CheckState.FAIL

        has_pass_witness = False
        has_unknown_witness = False

        for edge in matching_edges:
            if not _resource_matches(edge, resource_pattern):
                continue
            if _is_unknown_witness(edge):
                has_unknown_witness = True
            else:
                has_pass_witness = True

        if has_pass_witness:
            return CheckState.PASS
        if has_unknown_witness:
            return CheckState.UNKNOWN
        return CheckState.FAIL

    def passrole_edges_from(self, principal_arn: str) -> tuple[Edge, ...]:
        """All `iam:PassRole_permission` edges from this principal.

        Convenience helper for the passrole_lambda reasoner (S12), which
        needs to walk the full PassRole edge set rather than asking
        binary questions via `has_action`. Returns edges in input order.
        """
        return tuple(e for e in self.edges_from(principal_arn) if e.edge_type == "iam:PassRole_permission")

    def trust_policy_of(self, role_arn: str) -> tuple[Edge, ...]:
        """All trust edges TO the given role (i.e., who trusts this role).

        Convenience helper for the cross_account_trust reasoner (S10).
        Returns edges in input order. The result is exactly the
        materialized trust policy of the role expressed as the set of
        principals it trusts.
        """
        return tuple(e for e in self.edges_to(role_arn) if e.edge_type.endswith("_trust"))


# ---------------------------------------------------------------
# Module-level helpers
# ---------------------------------------------------------------


def _action_from_edge_type(edge_type: str) -> str | None:
    """Extract the bare action from an edge_type string.

    `iam:PassRole_permission` → `iam:PassRole`
    `sts:AssumeRole_trust`    → `sts:AssumeRole`
    Anything else             → None

    Returns None for edge_types that don't match either suffix so the
    indexer can skip them silently rather than corrupting the action
    index with synthetic non-action edges.
    """
    if edge_type.endswith("_permission"):
        return edge_type[: -len("_permission")]
    if edge_type.endswith("_trust"):
        return edge_type[: -len("_trust")]
    return None


def _resource_matches(edge: Edge, resource_pattern: str) -> bool:
    """Does this edge's dst match the requested resource_pattern?

    Three cases:
    1. resource_pattern == "*" — matches any edge (caller asks "any resource")
    2. dst is a hyperedge — cannot resolve specific target, treat as match
       so the edge becomes an UNKNOWN witness in `has_action`
    3. otherwise — fnmatch the requested pattern against dst.provider_id

    Note that case 2 is intentionally permissive: a hyperedge represents
    "the principal has this action against many possibly-relevant
    targets, but expansion was suppressed." Whether the SPECIFIC target
    in `resource_pattern` is one of those is unknowable. The conservative
    answer is "this hyperedge is a candidate," which `has_action` then
    classifies as an UNKNOWN witness via `_is_unknown_witness`.
    """
    if resource_pattern == "*":
        return True
    if edge.dst.node_type == NODE_TYPE_HYPEREDGE:
        return True
    return fnmatch.fnmatchcase(edge.dst.provider_id, resource_pattern)


def _is_unknown_witness(edge: Edge) -> bool:
    """Does this edge produce an UNKNOWN witness rather than a PASS witness?

    The three ambiguity flags from plan §3.3:
    - dst is a __hyperedge__ node (wildcard expansion was suppressed)
    - features.is_wildcard_resource == True (source policy used wildcard
      resource, expansion code resolved it but may have missed nuances)
    - features.has_conditions == True (statement has a Condition block,
      runtime context not evaluable from the static graph)
    """
    if edge.dst.node_type == NODE_TYPE_HYPEREDGE:
        return True
    features: dict[str, Any] = edge.features or {}
    if features.get("is_wildcard_resource", False):
        return True
    return bool(features.get("has_conditions", False))
