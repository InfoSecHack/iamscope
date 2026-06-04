"""Shared admin equivalence detection for chain-walking reasoners.

Two-tier detection that handles both unit-test fixtures (which build
explicit `iam:*_permission` self-edges) and real collected data (where
the collector expands `Action: "*"` policies into per-action permission
edges pointing to wildcard expansion hyperedges).

History: this logic was originally inlined as `_is_admin_equivalent` in
`passrole_lambda`, then cloned into `passrole_ecs`, then again into
`assume_role_chain` (with the additional `_find_admin_witness_edge`
helper that returns the edge instead of just a bool), then again into
`admin_reachability`. Four copies of the same logic across five
reasoners. Promoted here in priority 3c-refactor as the canonical
source of truth.

Refuses-to-lie property: detection is binary (admin-equivalent or not),
no UNKNOWN tier — the wildcard expansion hyperedge is itself a strong
positive signal that the policy literally said `Action: "*"`, so
recognizing it is not a guess.
"""

from __future__ import annotations

from iamscope.models import Edge, Node
from iamscope.reasoner.fact_graph import FactGraph


def find_admin_witness_edge(
    facts: FactGraph,
    target_role: Node,
) -> Edge | None:
    """Return the witness edge proving admin equivalence, or None.

    Detection is two-tier to handle both unit-test fixtures and real
    collected data:

    1. **Explicit `*` or `iam:*` permission edge** — what unit tests
       build directly via fixture helpers. The §4B.3 admin-equivalence
       definition. Matches `edge_type == "*_permission"` or
       `"iam:*_permission"`.

    2. **Wildcard parser provenance on wildcard resources** — what the
       real collector produces when a policy has `Action: "*"` or
       `Action: "iam:*"` with `Resource: "*"`. The collector expands
       wildcards into one permission edge per relevant action class and
       preserves `action_matched_via` plus wildcard-resource metadata
       on each edge. A literal `Action: "*"` is a direct admin signal.
       A literal `Action: "iam:*"` is also admin-equivalent once the
       parser/edge-builder output shows multiple IAM actions came from
       the same wildcard action over wildcard resources.

    3. **Wildcard expansion hyperedges across ≥3 distinct service
       prefixes** — the historical fallback for collected data where a
       policy has `Action: "*"` but the direct wildcard provenance is
       not available. A genuinely-admin role will have wildcard edges
       spanning many service prefixes (sts, iam, lambda, ec2, ecs,
       secretsmanager), whereas a merely-permissive role with one
       scoped wildcard grant like `Action: "lambda:CreateFunction",
       Resource: "*"` will have wildcard edges in only ONE service
       prefix.

       The ≥3 threshold distinguishes:
       - AdminRole with `Action: "*"` → 6 distinct prefixes → admin ✓
       - Alice with `lambda:CreateFunction` + `ecs:*` wildcards →
         2 distinct prefixes → NOT admin ✓

    Without tier 2 the severity bump from "high" to "critical" is
    silently dead code on real collected data. Without the ≥3
    threshold, tier 2 over-triggers on any principal with a single
    scoped wildcard resource grant, producing false positives
    (e.g., a user with `lambda:CreateFunction` on `Resource: "*"`
    being classified as admin-equivalent, which is wrong).

    Used by reasoners that need to cite a concrete witness edge in
    `Check.evidence_refs` for the admin-equivalence check, instead
    of citing an opaque node identifier (which would fail
    `Finding._validate_evidence_cross_references`).
    """
    iam_wildcard_witnesses_by_action: dict[str, Edge] = {}
    wildcard_witnesses_by_prefix: dict[str, Edge] = {}
    for edge in facts.edges_from(target_role.provider_id):
        if not edge.edge_type.endswith("_permission"):
            continue
        # Tier 1: explicit `*` or `iam:*` action
        action = edge.edge_type[: -len("_permission")]
        if action == "*" or action == "iam:*":
            return edge
        # Tier 2: real parser/edge-builder wildcard provenance. This
        # uses statement-derived metadata instead of action-name
        # guessing. Require wildcard-resource scope so service-level
        # wildcard actions over a narrow resource pattern do not become
        # broad admin-equivalence witnesses.
        action_matched_via = edge.features.get("action_matched_via")
        if _is_wildcard_resource_grant(edge):
            if action_matched_via == "wildcard_star":
                return edge
            if action_matched_via == "wildcard_iam" and action.startswith("iam:"):
                iam_wildcard_witnesses_by_action.setdefault(action, edge)
        # Tier 3 signal: wildcard expansion hyperedge dst. Collect
        # witness edges keyed by service prefix (the part of the
        # action before the colon). If we end up with ≥3 distinct
        # prefixes, tier 3 fires.
        if edge.dst.provider_id.startswith("__hyperedge__:wildcard_"):
            service_prefix = action.split(":", 1)[0] if ":" in action else action
            if service_prefix not in wildcard_witnesses_by_prefix:
                wildcard_witnesses_by_prefix[service_prefix] = edge
    # Tier 2b: require multiple IAM actions from literal `iam:*`.
    # This distinguishes real `Action: "iam:*", Resource: "*"` parser
    # output from a narrow exact grant like
    # `Action: "iam:PassRole", Resource: "*"`.
    if len(iam_wildcard_witnesses_by_action) >= 2:
        first_action = sorted(iam_wildcard_witnesses_by_action.keys())[0]
        return iam_wildcard_witnesses_by_action[first_action]
    # Tier 3: require ≥3 distinct service prefixes with wildcard grants
    if len(wildcard_witnesses_by_prefix) >= 3:
        # Return the lex-first witness for deterministic output
        first_prefix = sorted(wildcard_witnesses_by_prefix.keys())[0]
        return wildcard_witnesses_by_prefix[first_prefix]
    return None


def _is_wildcard_resource_grant(edge: Edge) -> bool:
    """Return True when an edge came from a broad wildcard resource grant."""
    return edge.features.get("is_wildcard_resource") is True and edge.features.get("resource_pattern") == "*"


def is_admin_equivalent(facts: FactGraph, target_role: Node) -> bool:
    """Convenience wrapper: True if the role has admin-equivalent permissions.

    Equivalent to `find_admin_witness_edge(facts, target_role) is not None`.
    Use this when you only need the boolean answer; use the witness-edge
    function when you also need to cite the proof in evidence_refs.
    """
    return find_admin_witness_edge(facts, target_role) is not None
