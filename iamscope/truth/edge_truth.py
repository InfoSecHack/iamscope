"""Sidecar-backed edge truth view for operators."""

from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from iamscope.constants import (
    ACTION_CLASS_STS_ASSUME_ROLE,
    DECLARED_STATE_ALLOW,
    DECLARED_STATE_UNKNOWN,
    PROBE_STATE_CONFOUNDED_SKIP,
    SIMULATOR_STATE_NOT_RUN,
    VALIDATED_STATE_NOT_PROBED,
    VALIDATED_STATE_VALUES,
)
from iamscope.output.probe_overlay_json import load_probe_overlay
from iamscope.truth.action_class import validate_action_class
from iamscope.truth.confounded import ConfoundedJudgment, judge_edge_confounding
from iamscope.truth.probe_overlay import ProbeRecord, join_probe_overlay_to_scenario

VERDICT_CONFOUNDED_SKIP = PROBE_STATE_CONFOUNDED_SKIP
VERDICT_VALIDATED_ALLOW = "validated_allow"
VERDICT_VALIDATED_DENY = "validated_deny"
VERDICT_SIMULATOR_ADVISORY = "simulator_advisory"
VERDICT_HYPOTHESIS_ONLY = "hypothesis_only"
VERDICT_NOT_DECLARED = "not_declared"
EDGE_TRUTH_VERDICT_VALUES = frozenset(
    {
        VERDICT_CONFOUNDED_SKIP,
        VERDICT_VALIDATED_ALLOW,
        VERDICT_VALIDATED_DENY,
        VERDICT_SIMULATOR_ADVISORY,
        VERDICT_HYPOTHESIS_ONLY,
        VERDICT_NOT_DECLARED,
    }
)


@dataclass(frozen=True)
class EdgeTruthSummary:
    edge_id: str
    source_arn: str
    target_arn: str
    action_class: str
    declared_state: str
    simulator_state: str
    validated_state: str
    probe_state: str
    confounded: bool
    confounded_reason: str
    contributing_scps: tuple[str, ...]
    consolidated_verdict: str

    def __post_init__(self) -> None:
        if self.consolidated_verdict not in EDGE_TRUTH_VERDICT_VALUES:
            raise ValueError(
                "consolidated_verdict must be one of "
                f"{sorted(EDGE_TRUTH_VERDICT_VALUES)}, got {self.consolidated_verdict!r}"
            )
        if self.validated_state not in VALIDATED_STATE_VALUES:
            raise ValueError(
                f"validated_state must be one of {sorted(VALIDATED_STATE_VALUES)}, got {self.validated_state!r}"
            )
        object.__setattr__(self, "contributing_scps", tuple(self.contributing_scps))


def build_edge_truth_summary(
    scenario: dict[str, Any],
    binding_metadata: list[dict[str, Any]] | None,
    probe_records_by_edge: dict[str, tuple[ProbeRecord, ...]] | None,
    source_arn: str,
    target_arn: str,
    action_class: str = ACTION_CLASS_STS_ASSUME_ROLE,
) -> EdgeTruthSummary:
    """Build a declared/simulated/validated/confounded summary for one edge."""
    validate_action_class(action_class)
    edge = _find_edge(scenario, source_arn, target_arn, action_class)
    if edge is None:
        return EdgeTruthSummary(
            edge_id="",
            source_arn=source_arn,
            target_arn=target_arn,
            action_class=action_class,
            declared_state=DECLARED_STATE_UNKNOWN,
            simulator_state=SIMULATOR_STATE_NOT_RUN,
            validated_state=VALIDATED_STATE_NOT_PROBED,
            probe_state="not_probed",
            confounded=False,
            confounded_reason="edge_not_declared",
            contributing_scps=(),
            consolidated_verdict=VERDICT_NOT_DECLARED,
        )

    edge_id = str(edge["edge_id"])
    latest_probe = _latest_probe((probe_records_by_edge or {}).get(edge_id, ()))
    simulator_state = (
        latest_probe.simulator_state if latest_probe and latest_probe.simulator_state else SIMULATOR_STATE_NOT_RUN
    )
    validated_state = (
        latest_probe.runtime_state if latest_probe and latest_probe.runtime_state else VALIDATED_STATE_NOT_PROBED
    )
    probe_state = latest_probe.probe_state if latest_probe else "not_probed"

    confounded = judge_edge_confounding(
        edge=edge,
        constraints=list(scenario.get("constraints", [])),
        edge_constraints=list(scenario.get("edge_constraints", [])),
        action_class=action_class,
    )
    if latest_probe and latest_probe.confounded:
        confounded = _overlay_confounded_judgment(confounded, latest_probe)

    verdict = _consolidated_verdict(confounded, validated_state, simulator_state)
    return EdgeTruthSummary(
        edge_id=edge_id,
        source_arn=source_arn,
        target_arn=target_arn,
        action_class=action_class,
        declared_state=DECLARED_STATE_ALLOW,
        simulator_state=simulator_state,
        validated_state=validated_state,
        probe_state=probe_state,
        confounded=confounded.confounded,
        confounded_reason=confounded.reason,
        contributing_scps=confounded.contributing_scps,
        consolidated_verdict=verdict,
    )


def render_edge_truth_summary(summary: EdgeTruthSummary) -> str:
    """Render compact human-readable edge truth output."""
    contributing = ",".join(summary.contributing_scps) if summary.contributing_scps else "none"
    edge_label = f"{summary.source_arn} -> {summary.target_arn}"
    return "\n".join(
        [
            f"Edge: {edge_label}",
            f"Edge ID: {summary.edge_id or 'not_found'}",
            f"Action class: {summary.action_class}",
            f"Declared: {summary.declared_state}",
            f"Simulator: {summary.simulator_state}",
            f"Validated: {summary.validated_state}",
            f"Probe state: {summary.probe_state}",
            f"Confounded: {str(summary.confounded).lower()}",
            f"Reason: {summary.confounded_reason}",
            f"Contributing SCPs: {contributing}",
            f"Consolidated verdict: {summary.consolidated_verdict}",
        ]
    )


def load_edge_truth_inputs(
    scenario_path: str | Path,
    binding_metadata_path: str | Path | None = None,
    probe_overlay_path: str | Path | None = None,
) -> tuple[dict[str, Any], list[dict[str, Any]], dict[str, tuple[ProbeRecord, ...]]]:
    """Load scenario and optional sidecars for edge-truth rendering."""
    scenario = json.loads(Path(scenario_path).read_bytes())
    binding_metadata = []
    if binding_metadata_path:
        binding_metadata = json.loads(Path(binding_metadata_path).read_bytes())
    records_by_edge: dict[str, tuple[ProbeRecord, ...]] = {}
    if probe_overlay_path:
        overlay = load_probe_overlay(probe_overlay_path)
        records_by_edge = join_probe_overlay_to_scenario(scenario, overlay)
    return scenario, binding_metadata, records_by_edge


def summarize_from_paths(
    *,
    scenario_path: str | Path,
    binding_metadata_path: str | Path | None,
    probe_overlay_path: str | Path | None,
    source_arn: str,
    target_arn: str,
    action_class: str,
) -> EdgeTruthSummary:
    scenario, binding_metadata, records_by_edge = load_edge_truth_inputs(
        scenario_path,
        binding_metadata_path,
        probe_overlay_path,
    )
    return build_edge_truth_summary(
        scenario=scenario,
        binding_metadata=binding_metadata,
        probe_records_by_edge=records_by_edge,
        source_arn=source_arn,
        target_arn=target_arn,
        action_class=action_class,
    )


def _find_edge(
    scenario: dict[str, Any],
    source_arn: str,
    target_arn: str,
    action_class: str,
) -> dict[str, Any] | None:
    matches = []
    for edge in scenario.get("edges", []):
        edge_type = str(edge.get("edge_type", ""))
        if not edge_type.lower().startswith(action_class.lower()):
            continue
        if edge.get("src", {}).get("provider_id") != source_arn:
            continue
        if edge.get("dst", {}).get("provider_id") != target_arn:
            continue
        matches.append(edge)
    return sorted(matches, key=lambda e: str(e.get("edge_id", "")))[0] if matches else None


def _latest_probe(records: tuple[ProbeRecord, ...]) -> ProbeRecord | None:
    if not records:
        return None
    return sorted(records, key=lambda p: (p.probed_at_utc, p.probe_id))[-1]


def _overlay_confounded_judgment(
    base: ConfoundedJudgment,
    probe: ProbeRecord,
) -> ConfoundedJudgment:
    refs = tuple(sorted(set(base.contributing_scps + probe.contributing_control_refs)))
    reason = probe.confounded_reason or base.reason
    return ConfoundedJudgment(
        account_id=base.account_id,
        action_class=base.action_class,
        confounded=True,
        reason=reason,
        contributing_scps=refs,
        evidence_level=base.evidence_level,
    )


def _consolidated_verdict(
    confounded: ConfoundedJudgment,
    validated_state: str,
    simulator_state: str,
) -> str:
    if confounded.confounded:
        return VERDICT_CONFOUNDED_SKIP
    if validated_state == "allowed":
        return VERDICT_VALIDATED_ALLOW
    if validated_state == "denied":
        return VERDICT_VALIDATED_DENY
    if simulator_state != SIMULATOR_STATE_NOT_RUN:
        return VERDICT_SIMULATOR_ADVISORY
    return VERDICT_HYPOTHESIS_ONLY
