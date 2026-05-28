"""Shared chain walking primitives for BFS-based chain reasoners.

Pure helper functions for walking `sts:AssumeRole` chains in the fact
graph. Used by `assume_role_chain` and `admin_reachability` reasoners,
which both walk the same edge types with the same trust-edge admission
logic but produce different finding shapes from the walks.

History: these helpers were originally inlined in `assume_role_chain`,
then cloned into `admin_reachability`. Two copies of identical logic
across two reasoners. Promoted here in priority 3c-refactor as the
canonical source of truth, so future BFS reasoners (e.g., a hypothetical
"reachable secrets" reasoner that walks AssumeRole + GetSecretValue)
can import these primitives instead of cloning.

Design notes:
    - All functions are pure: same inputs → same outputs, no state.
    - Account-root principal handling in `find_admitting_trust_edge`
      is the only non-trivial logic — same-account principals can be
      admitted by an `arn:aws:iam::ACCOUNT:root` trust principal even
      though the ARN doesn't directly match.
    - These helpers do NOT enforce cycle detection or depth limits —
      that's the caller's responsibility (each reasoner has different
      limits and termination semantics).
"""

from __future__ import annotations

from iamscope.models import Edge, Node
from iamscope.reasoner.fact_graph import FactGraph

ASSUMEROLE_ACTION: str = "sts:AssumeRole"


def find_node(facts: FactGraph, provider_id: str) -> Node | None:
    """O(1) lookup of a node by provider_id via the FactGraph index.

    Delegates to `facts.node_by_provider_id(...)` which uses the
    `_node_by_provider_id` dict built at `FactGraph.__post_init__`.

    History: pre-v0.2.29 this was a linear scan with a docstring
    comment claiming "acceptable for the chain walking use case where
    each BFS step does a small constant number of node lookups." That
    reasoning was wrong — the BFS walker calls this function for EVERY
    visited node, and on a dense graph the cumulative cost dominates
    reasoner runtime. v0.2.29 replaced the scan with the O(1)
    delegation. See the v0.2.28 performance work for the related
    fixes in `secrets_blast_radius`, `s3_bucket_takeover`, and
    `iam_group_membership_escalation` — this file was missed in that
    pass because the benchmark fixture didn't exercise the BFS walker.
    """
    return facts.node_by_provider_id(provider_id)


def assumerole_permission_edges_from(
    facts: FactGraph,
    src_provider_id: str,
) -> tuple[Edge, ...]:
    """All `sts:AssumeRole_permission` edges originating at src.

    Filtered subset of `facts.edges_from(src)`. Returns edges in the
    same order they appear in the fact graph (which is the order they
    were collected — deterministic across runs because the collector
    sorts before emit).
    """
    expected_type = f"{ASSUMEROLE_ACTION}_permission"
    return tuple(e for e in facts.edges_from(src_provider_id) if e.edge_type == expected_type)


def find_admitting_trust_edge(
    facts: FactGraph,
    *,
    current_arn: str,
    next_arn: str,
) -> Edge | None:
    """Find a trust edge on next_arn that admits current_arn as a principal.

    Walks the next role's trust policy via `facts.trust_policy_of` and
    returns the first edge whose src admits current_arn. Considers
    both direct ARN match and account-root principals.

    Account-root admission rule: a trust edge whose src is
    `arn:aws:iam::<ACCOUNT>:root` admits any principal in the same
    AWS account, even if their specific ARN doesn't appear in the
    trust policy. This matches AWS IAM's actual semantics — adding
    account-root to a role's trust policy delegates trust decisions
    to the account's IAM policies, effectively trusting any IAM
    principal in that account.

    Returns None if no admitting trust edge exists. Callers should
    skip the hop entirely in that case (the chain is broken).
    """
    for trust_edge in facts.trust_policy_of(next_arn):
        if not trust_edge.edge_type.endswith("_trust"):
            continue
        src_pid = trust_edge.src.provider_id
        # Direct ARN match
        if src_pid == current_arn:
            return trust_edge
        # Account-root principal: current_arn must be in the same account
        if src_pid.endswith(":root"):
            parts = src_pid.split(":")
            if len(parts) >= 5:
                src_account = parts[4]
                cur_parts = current_arn.split(":")
                if len(cur_parts) >= 5 and cur_parts[4] == src_account:
                    return trust_edge
    return None
