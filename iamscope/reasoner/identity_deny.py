"""Shared identity-policy Deny blocker checks for reasoners."""

from __future__ import annotations

from iamscope.constants import CONSTRAINT_TYPE_IDENTITY_DENY
from iamscope.models import Edge
from iamscope.reasoner.fact_graph import FactGraph
from iamscope.reasoner.verdict import Blocker, CheckState


def check_identity_deny_blockers(
    facts: FactGraph,
    edge: Edge | None,
    constraint_refs: set[str],
    edge_constraint_refs: set[str],
    *,
    action_label: str,
    edge_constraint_ref_separator: str = ":",
) -> tuple[CheckState, str, list[Blocker]]:
    """Evaluate IDENTITY_DENY bindings on one permission edge."""
    if edge is None:
        return (
            CheckState.UNKNOWN,
            f"no witness edge available for {action_label} identity-deny check",
            [],
        )

    deny_bindings = []
    for binding in facts.bindings_for_edge(edge.edge_id):
        constraint = facts.constraint_by_id(binding.constraint_id)
        if constraint is None:
            continue
        if constraint.constraint_type == CONSTRAINT_TYPE_IDENTITY_DENY:
            deny_bindings.append(binding)

    if not deny_bindings:
        return (
            CheckState.PASS,
            f"no identity policy Deny bindings observed on {action_label} witness edge",
            [],
        )

    for binding in deny_bindings:
        constraint_refs.add(binding.constraint_id)
        edge_constraint_refs.add(f"{binding.edge_id}{edge_constraint_ref_separator}{binding.constraint_id}")

    blocking_complete = []
    ambiguous = []
    for binding in deny_bindings:
        confidence = binding.governance_confidence
        if binding.likely_blocking and confidence == "complete":
            blocking_complete.append(binding)
        elif confidence in ("partial", "needs_review"):
            ambiguous.append(binding)

    if blocking_complete:
        blockers = [
            Blocker(
                kind="identity_deny",
                constraint_id=b.constraint_id,
                edge_id=edge.edge_id,
                reason=b.binding_reason or f"identity policy Deny blocks {action_label}",
            )
            for b in blocking_complete
        ]
        return (
            CheckState.FAIL,
            f"{len(blocking_complete)} identity policy Deny binding(s) "
            f"likely_blocking with governance_confidence=complete on {action_label}",
            blockers,
        )

    if ambiguous:
        return (
            CheckState.UNKNOWN,
            f"{len(ambiguous)} identity policy Deny binding(s) with "
            f"governance_confidence partial/needs_review on {action_label}",
            [],
        )

    return (
        CheckState.PASS,
        f"{len(deny_bindings)} identity policy Deny binding(s) all non-blocking "
        f"with governance_confidence=complete on {action_label}",
        [],
    )
