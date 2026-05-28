"""Truth-contract regression tests for scenario compatibility."""

from __future__ import annotations

import json

from iamscope.models import ScenarioMetadata
from iamscope.output.scenario_json import emit_scenario


def test_empty_scenario_metadata_does_not_emit_truth_fields() -> None:
    scenario_bytes, _ = emit_scenario(
        nodes=[],
        edges=[],
        constraints=[],
        edge_constraints=[],
        metadata=ScenarioMetadata(collection_timestamp="2026-01-01T00:00:00Z"),
    )
    scenario = json.loads(scenario_bytes)

    assert "truth_contract" not in scenario["metadata"]
    assert "effective_org_controls" not in scenario["metadata"]
    assert "confounded_accounts" not in scenario["metadata"]
