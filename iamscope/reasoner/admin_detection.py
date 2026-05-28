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

    2. **Wildcard expansion hyperedges across ≥3 distinct service
       prefixes** — what the real collector produces when a policy has
       `Action: "*"`. The collector expands `*` into one permission
       edge per relevant action class, each pointing to a synthetic
       `__hyperedge__:wildcard_*` dst. A genuinely-admin role will
       have wildcard edges spanning many service prefixes (sts, iam,
       lambda, ec2, ecs, secretsmanager), whereas a merely-permissive
       role with one scoped wildcard grant like
       `Action: "lambda:CreateFunction", Resource: "*"` will have
       wildcard edges in only ONE service prefix.

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
    wildcard_witnesses_by_prefix: dict[str, Edge] = {}
    for edge in facts.edges_from(target_role.provider_id):
        if not edge.edge_type.endswith("_permission"):
            continue
        # Tier 1: explicit `*` or `iam:*` action
        action = edge.edge_type[: -len("_permission")]
        if action == "*" or action == "iam:*":
            return edge
        # Tier 2 signal: wildcard expansion hyperedge dst. Collect
        # witness edges keyed by service prefix (the part of the
        # action before the colon). If we end up with ≥3 distinct
        # prefixes, tier 2 fires.
        if edge.dst.provider_id.startswith("__hyperedge__:wildcard_"):
            service_prefix = action.split(":", 1)[0] if ":" in action else action
            if service_prefix not in wildcard_witnesses_by_prefix:
                wildcard_witnesses_by_prefix[service_prefix] = edge
    # Tier 2: require ≥3 distinct service prefixes with wildcard grants
    if len(wildcard_witnesses_by_prefix) >= 3:
        # Return the lex-first witness for deterministic output
        first_prefix = sorted(wildcard_witnesses_by_prefix.keys())[0]
        return wildcard_witnesses_by_prefix[first_prefix]
    return None


def is_admin_equivalent(facts: FactGraph, target_role: Node) -> bool:
    """Convenience wrapper: True if the role has admin-equivalent permissions.

    Equivalent to `find_admin_witness_edge(facts, target_role) is not None`.
    Use this when you only need the boolean answer; use the witness-edge
    function when you also need to cite the proof in evidence_refs.
    """
    return find_admin_witness_edge(facts, target_role) is not None
