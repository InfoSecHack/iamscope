"""Probe overlay sidecar schema and scenario join helpers."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from iamscope.constants import (
    ACTION_CLASS_VALUES,
    PROBE_KIND_VALUES,
    PROBE_STATE_VALUES,
    SIMULATOR_STATE_VALUES,
    VALIDATED_STATE_VALUES,
)

PROBE_OVERLAY_SCHEMA_VERSION = "iamscope.probe_overlay.v1"


@dataclass(frozen=True)
class ProbeRecord:
    """One probe observation for one graph edge."""

    probe_id: str
    edge_id: str
    action_class: str
    probe_kind: str
    probe_state: str
    probed_at_utc: str
    authorization_ref: str | None
    confounded: bool
    confounded_reason: str
    contributing_control_refs: tuple[str, ...]
    simulator_state: str | None
    runtime_state: str | None
    cloudtrail_state: str | None
    notes_digest: str | None

    def __post_init__(self) -> None:
        _require_enum("action_class", self.action_class, ACTION_CLASS_VALUES)
        _require_enum("probe_kind", self.probe_kind, PROBE_KIND_VALUES)
        _require_enum("probe_state", self.probe_state, PROBE_STATE_VALUES)
        _optional_enum("simulator_state", self.simulator_state, SIMULATOR_STATE_VALUES)
        _optional_enum("runtime_state", self.runtime_state, VALIDATED_STATE_VALUES)
        object.__setattr__(
            self,
            "contributing_control_refs",
            tuple(self.contributing_control_refs),
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "action_class": self.action_class,
            "authorization_ref": self.authorization_ref,
            "cloudtrail_state": self.cloudtrail_state,
            "confounded": self.confounded,
            "confounded_reason": self.confounded_reason,
            "contributing_control_refs": list(self.contributing_control_refs),
            "edge_id": self.edge_id,
            "notes_digest": self.notes_digest,
            "probe_id": self.probe_id,
            "probe_kind": self.probe_kind,
            "probe_state": self.probe_state,
            "probed_at_utc": self.probed_at_utc,
            "runtime_state": self.runtime_state,
            "simulator_state": self.simulator_state,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> ProbeRecord:
        return cls(
            probe_id=str(data["probe_id"]),
            edge_id=str(data["edge_id"]),
            action_class=str(data["action_class"]),
            probe_kind=str(data["probe_kind"]),
            probe_state=str(data["probe_state"]),
            probed_at_utc=str(data["probed_at_utc"]),
            authorization_ref=data.get("authorization_ref"),
            confounded=bool(data.get("confounded", False)),
            confounded_reason=str(data.get("confounded_reason", "")),
            contributing_control_refs=tuple(data.get("contributing_control_refs", ())),
            simulator_state=data.get("simulator_state"),
            runtime_state=data.get("runtime_state"),
            cloudtrail_state=data.get("cloudtrail_state"),
            notes_digest=data.get("notes_digest"),
        )


@dataclass(frozen=True)
class ProbeOverlay:
    """Canonical sidecar for edge probe observations."""

    schema_version: str
    engagement_run_id: str
    scenario_canonical_hash: str
    generated_at_utc: str
    probes: tuple[ProbeRecord, ...]

    def __post_init__(self) -> None:
        if self.schema_version != PROBE_OVERLAY_SCHEMA_VERSION:
            raise ValueError(f"schema_version must be {PROBE_OVERLAY_SCHEMA_VERSION!r}, got {self.schema_version!r}")
        object.__setattr__(self, "probes", tuple(self.probes))

    def to_dict(self) -> dict[str, Any]:
        return {
            "engagement_run_id": self.engagement_run_id,
            "generated_at_utc": self.generated_at_utc,
            "probes": [probe.to_dict() for probe in sorted(self.probes, key=lambda p: (p.edge_id, p.probe_id))],
            "scenario_canonical_hash": self.scenario_canonical_hash,
            "schema_version": self.schema_version,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> ProbeOverlay:
        return cls(
            schema_version=str(data["schema_version"]),
            engagement_run_id=str(data["engagement_run_id"]),
            scenario_canonical_hash=str(data["scenario_canonical_hash"]),
            generated_at_utc=str(data["generated_at_utc"]),
            probes=tuple(ProbeRecord.from_dict(p) for p in data.get("probes", [])),
        )


def join_probe_overlay_to_scenario(
    scenario: dict[str, Any],
    overlay: ProbeOverlay,
) -> dict[str, tuple[ProbeRecord, ...]]:
    """Validate and index overlay records by edge_id for a scenario."""
    scenario_hash = scenario.get("metadata", {}).get("canonical_hash")
    if scenario_hash != overlay.scenario_canonical_hash:
        raise ValueError("probe overlay scenario_canonical_hash does not match scenario metadata.canonical_hash")

    edge_ids = {str(edge.get("edge_id", "")) for edge in scenario.get("edges", [])}
    records_by_edge: dict[str, list[ProbeRecord]] = {}
    for probe in overlay.probes:
        if probe.edge_id not in edge_ids:
            raise ValueError(f"probe {probe.probe_id!r} references unknown edge_id {probe.edge_id!r}")
        records_by_edge.setdefault(probe.edge_id, []).append(probe)

    return {
        edge_id: tuple(sorted(records, key=lambda p: (p.probed_at_utc, p.probe_id)))
        for edge_id, records in sorted(records_by_edge.items())
    }


def _require_enum(field_name: str, value: str, allowed: frozenset[str]) -> None:
    if value not in allowed:
        raise ValueError(f"{field_name} must be one of {sorted(allowed)}, got {value!r}")


def _optional_enum(field_name: str, value: str | None, allowed: frozenset[str]) -> None:
    if value is not None and value not in allowed:
        raise ValueError(f"{field_name} must be one of {sorted(allowed)}, got {value!r}")
