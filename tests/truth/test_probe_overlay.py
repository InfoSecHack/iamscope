"""Tests for probe overlay sidecar schema."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from iamscope.constants import (
    ACTION_CLASS_STS_ASSUME_ROLE,
    PROBE_KIND_SIMULATOR,
    PROBE_STATE_SIMULATOR_ONLY_ALLOWED,
    SIMULATOR_STATE_ALLOWED,
)
from iamscope.output.probe_overlay_json import (
    emit_probe_overlay,
    load_probe_overlay,
    write_probe_overlay,
)
from iamscope.truth.probe_overlay import (
    PROBE_OVERLAY_SCHEMA_VERSION,
    ProbeOverlay,
    ProbeRecord,
    join_probe_overlay_to_scenario,
)


def _record(edge_id: str = "edge-1") -> ProbeRecord:
    return ProbeRecord(
        probe_id="probe-1",
        edge_id=edge_id,
        action_class=ACTION_CLASS_STS_ASSUME_ROLE,
        probe_kind=PROBE_KIND_SIMULATOR,
        probe_state=PROBE_STATE_SIMULATOR_ONLY_ALLOWED,
        probed_at_utc="2026-01-01T00:00:00Z",
        authorization_ref=None,
        confounded=False,
        confounded_reason="",
        contributing_control_refs=(),
        simulator_state=SIMULATOR_STATE_ALLOWED,
        runtime_state=None,
        cloudtrail_state=None,
        notes_digest=None,
    )


def _overlay(edge_id: str = "edge-1", scenario_hash: str = "hash-123") -> ProbeOverlay:
    return ProbeOverlay(
        schema_version=PROBE_OVERLAY_SCHEMA_VERSION,
        engagement_run_id="run-1",
        scenario_canonical_hash=scenario_hash,
        generated_at_utc="2026-01-01T00:00:01Z",
        probes=(_record(edge_id),),
    )


def _scenario(edge_id: str = "edge-1", scenario_hash: str = "hash-123") -> dict:
    return {
        "metadata": {"canonical_hash": scenario_hash},
        "edges": [{"edge_id": edge_id}],
        "nodes": [],
        "constraints": [],
        "edge_constraints": [],
    }


def test_probe_overlay_round_trips_canonically(tmp_path: Path) -> None:
    overlay = _overlay()
    path = tmp_path / "probe_overlay.json"

    write_probe_overlay(path, overlay)
    loaded = load_probe_overlay(path)

    assert loaded == overlay
    assert path.read_bytes() == emit_probe_overlay(loaded)


def test_probe_overlay_rejects_invalid_enum() -> None:
    with pytest.raises(ValueError, match="probe_state"):
        ProbeRecord(
            probe_id="probe-1",
            edge_id="edge-1",
            action_class=ACTION_CLASS_STS_ASSUME_ROLE,
            probe_kind=PROBE_KIND_SIMULATOR,
            probe_state="maybe",
            probed_at_utc="2026-01-01T00:00:00Z",
            authorization_ref=None,
            confounded=False,
            confounded_reason="",
            contributing_control_refs=(),
            simulator_state=None,
            runtime_state=None,
            cloudtrail_state=None,
            notes_digest=None,
        )


def test_probe_overlay_join_rejects_hash_mismatch() -> None:
    with pytest.raises(ValueError, match="scenario_canonical_hash"):
        join_probe_overlay_to_scenario(_scenario(scenario_hash="hash-a"), _overlay(scenario_hash="hash-b"))


def test_probe_overlay_join_indexes_known_edge() -> None:
    records = join_probe_overlay_to_scenario(_scenario(), _overlay())

    assert tuple(records) == ("edge-1",)
    assert records["edge-1"][0].probe_id == "probe-1"


def test_example_fixture_loads() -> None:
    path = Path("tests/fixtures/truth_contract/probe_overlay_example.json")
    data = json.loads(path.read_text(encoding="utf-8"))
    overlay = ProbeOverlay.from_dict(data)

    assert overlay.schema_version == PROBE_OVERLAY_SCHEMA_VERSION
