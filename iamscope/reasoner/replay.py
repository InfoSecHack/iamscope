"""Replay reasoners over frozen scenario artifacts.

This module intentionally does not collect AWS data. It reconstructs the
FactGraph from scenario.json plus binding_metadata.json and optional
probe_overlay.json so operators can prove overlay-aware finding mutation on a
stable artifact.
"""

from __future__ import annotations

import json
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from iamscope.models import Constraint, Edge, EdgeConstraint, Node, NodeRef
from iamscope.output.findings_json import emit_findings
from iamscope.output.probe_overlay_json import load_probe_overlay
from iamscope.output.scenario_json import assert_scenario_canonical_hash_stable
from iamscope.reasoner import (
    FactGraph,
    Finding,
    Reasoner,
    Registry,
)
from iamscope.reasoner.cross_reasoner_consistency import apply_cross_reasoner_demotions
from iamscope.truth.probe_overlay import ProbeRecord, join_probe_overlay_to_scenario


@dataclass(frozen=True)
class ReplayResult:
    findings: tuple[Finding, ...]
    findings_bytes: bytes
    findings_hash: str
    scenario_hash: str
    reasoners_run: tuple[str, ...]
    reasoners_skipped: dict[str, str]


def load_frozen_fact_graph(
    *,
    scenario_path: str | Path,
    binding_metadata_path: str | Path,
    probe_overlay_path: str | Path | None = None,
) -> FactGraph:
    """Load a FactGraph from frozen scenario/binding/probe sidecars."""
    scenario = json.loads(Path(scenario_path).read_bytes())
    scenario_hash = assert_scenario_canonical_hash_stable(scenario)
    binding_metadata = json.loads(Path(binding_metadata_path).read_bytes())
    probe_records_by_edge: dict[str, tuple[ProbeRecord, ...]] = {}
    if probe_overlay_path:
        overlay = load_probe_overlay(probe_overlay_path)
        probe_records_by_edge = join_probe_overlay_to_scenario(scenario, overlay)

    nodes = tuple(_node_from_dict(d) for d in scenario.get("nodes", []))
    edges = tuple(_edge_from_dict(d) for d in scenario.get("edges", []))
    constraints = tuple(_constraint_from_dict(d) for d in scenario.get("constraints", []))
    edge_constraints = tuple(_edge_constraint_from_dict(d) for d in binding_metadata)

    return FactGraph(
        nodes=nodes,
        edges=edges,
        constraints=constraints,
        edge_constraints=edge_constraints,
        scenario_hash=scenario_hash,
        edge_budget_exhausted=bool(scenario.get("metadata", {}).get("edge_budget_exhausted", False)),
        probe_records_by_edge=probe_records_by_edge,
    )


def run_reasoners_on_frozen_artifacts(
    *,
    scenario_path: str | Path,
    binding_metadata_path: str | Path,
    probe_overlay_path: str | Path | None,
    reasoner_instances: tuple[Reasoner, ...],
    apply_consistency: bool = True,
    reasoning_timestamp: str = "",
) -> ReplayResult:
    """Run selected reasoners over frozen artifacts and emit findings bytes."""
    facts = load_frozen_fact_graph(
        scenario_path=scenario_path,
        binding_metadata_path=binding_metadata_path,
        probe_overlay_path=probe_overlay_path,
    )
    registry = Registry()
    for instance in reasoner_instances:
        registry.register(instance)

    reasoners_skipped: dict[str, str] = {}
    for instance in reasoner_instances:
        try:
            ran, reason = instance.preconditions_met(facts)
            if not ran:
                reasoners_skipped[instance.pattern_id] = f"preconditions_not_met: {reason}"
        except Exception as e:  # noqa: BLE001
            reasoners_skipped[instance.pattern_id] = f"precondition_check_error: {type(e).__name__}: {e}"

    start = time.monotonic()
    findings = registry.run_all(facts)
    duration = time.monotonic() - start
    if apply_consistency:
        findings = apply_cross_reasoner_demotions(findings)

    reasoners_used = {
        instance.pattern_id: {
            "version": instance.pattern_version,
            "title": instance.pattern_title,
        }
        for instance in reasoner_instances
    }
    findings_bytes, findings_hash = emit_findings(
        findings,
        scenario_hash=facts.scenario_hash,
        reasoners_used=reasoners_used,
        reasoners_skipped=reasoners_skipped or None,
        reasoning_timestamp=reasoning_timestamp,
        reasoning_duration_seconds=duration,
    )
    return ReplayResult(
        findings=tuple(findings),
        findings_bytes=findings_bytes,
        findings_hash=findings_hash,
        scenario_hash=facts.scenario_hash,
        reasoners_run=tuple(instance.pattern_id for instance in reasoner_instances),
        reasoners_skipped=reasoners_skipped,
    )


def _node_ref_from_dict(data: dict[str, Any]) -> NodeRef:
    return NodeRef(
        provider=str(data.get("provider", "")),
        node_type=str(data.get("node_type", "")),
        provider_id=str(data.get("provider_id", "")),
        region=str(data.get("region", "-")),
    )


def _node_from_dict(data: dict[str, Any]) -> Node:
    return Node(
        provider=str(data.get("provider", "")),
        node_type=str(data.get("node_type", "")),
        provider_id=str(data.get("provider_id", "")),
        region=str(data.get("region", "-")),
        properties=dict(data.get("properties", {})),
        _node_id=str(data.get("node_id", "")) or None,
    )


def _edge_from_dict(data: dict[str, Any]) -> Edge:
    return Edge(
        edge_type=str(data.get("edge_type", "")),
        src=_node_ref_from_dict(dict(data.get("src", {}))),
        dst=_node_ref_from_dict(dict(data.get("dst", {}))),
        region=str(data.get("region", "-")),
        features=dict(data.get("features", {})),
        _edge_id=str(data.get("edge_id", "")) or None,
    )


def _constraint_from_dict(data: dict[str, Any]) -> Constraint:
    return Constraint(
        provider=str(data.get("provider", "")),
        constraint_type=str(data.get("constraint_type", "")),
        scope_type=str(data.get("scope_type", "")),
        scope_id=str(data.get("scope_id", "")),
        policy_id=str(data.get("policy_id", "")),
        statement_id=str(data.get("statement_id", "")),
        region=str(data.get("region", "-")),
        properties=dict(data.get("properties", {})),
        status=str(data.get("status", "ACTIVE")),
        validation_status=str(data.get("validation_status", "UNVALIDATED")),
        confidence_q=int(data.get("confidence_q", 500)),
        _constraint_id=str(data.get("constraint_id", "")) or None,
    )


def _edge_constraint_from_dict(data: dict[str, Any]) -> EdgeConstraint:
    metadata = dict(data.get("binding_metadata", {}))
    return EdgeConstraint(
        edge_id=str(data.get("edge_id", "")),
        constraint_id=str(data.get("constraint_id", "")),
        governance_confidence=str(metadata.get("governance_confidence", "needs_review")),
        likely_blocking=bool(metadata.get("likely_blocking", False)),
        binding_reason=str(metadata.get("binding_reason", "")),
    )
