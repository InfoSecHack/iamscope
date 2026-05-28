"""Shared stale principal unique-ID drift blocker checks for reasoners."""

from __future__ import annotations

from iamscope.constants import CONSTRAINT_TYPE_STALE_PRINCIPAL_DRIFT
from iamscope.models import Edge
from iamscope.reasoner.fact_graph import FactGraph
from iamscope.reasoner.verdict import Blocker, CheckState


def has_stale_principal_drift_binding(facts: FactGraph, edge: Edge | None) -> bool:
    """Return True when an edge has bound stale principal drift evidence."""
    if edge is None:
        return False
    for binding in facts.bindings_for_edge(edge.edge_id):
        constraint = facts.constraint_by_id(binding.constraint_id)
        if constraint is None:
            continue
        if constraint.constraint_type == CONSTRAINT_TYPE_STALE_PRINCIPAL_DRIFT:
            return True
    return False


def check_stale_principal_drift_blockers(
    facts: FactGraph,
    edge: Edge | None,
    constraint_refs: set[str],
    edge_constraint_refs: set[str],
    *,
    action_label: str,
    edge_constraint_ref_separator: str = ":",
) -> tuple[CheckState, str, list[Blocker]]:
    """Evaluate STALE_PRINCIPAL_DRIFT bindings on one trust/resource edge."""
    if edge is None:
        return (
            CheckState.UNKNOWN,
            f"no witness edge available for {action_label} stale-principal check",
            [],
        )

    drift_bindings = []
    for binding in facts.bindings_for_edge(edge.edge_id):
        constraint = facts.constraint_by_id(binding.constraint_id)
        if constraint is None:
            continue
        if constraint.constraint_type == CONSTRAINT_TYPE_STALE_PRINCIPAL_DRIFT:
            drift_bindings.append(binding)

    if not drift_bindings:
        return (
            CheckState.PASS,
            f"no stale principal drift bindings observed on {action_label} edge",
            [],
        )

    for binding in drift_bindings:
        constraint_refs.add(binding.constraint_id)
        edge_constraint_refs.add(f"{binding.edge_id}{edge_constraint_ref_separator}{binding.constraint_id}")

    blocking_complete = []
    ambiguous = []
    for binding in drift_bindings:
        confidence = binding.governance_confidence
        if binding.likely_blocking and confidence == "complete":
            blocking_complete.append(binding)
        elif confidence in ("partial", "needs_review"):
            ambiguous.append(binding)

    if blocking_complete:
        blockers = [
            Blocker(
                kind="stale_principal_drift",
                constraint_id=b.constraint_id,
                edge_id=edge.edge_id,
                reason=b.binding_reason or f"stale principal drift blocks {action_label}",
            )
            for b in blocking_complete
        ]
        return (
            CheckState.FAIL,
            f"{len(blocking_complete)} stale principal drift binding(s) "
            f"likely_blocking with governance_confidence=complete on {action_label}",
            blockers,
        )

    if ambiguous:
        return (
            CheckState.UNKNOWN,
            f"{len(ambiguous)} stale principal drift binding(s) with "
            f"governance_confidence partial/needs_review on {action_label}",
            [],
        )

    return (
        CheckState.PASS,
        f"{len(drift_bindings)} stale principal drift binding(s) all non-blocking "
        f"with governance_confidence=complete on {action_label}",
        [],
    )
