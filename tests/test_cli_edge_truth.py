"""CLI tests for iamscope edge-truth."""

from __future__ import annotations

import json
from pathlib import Path

from pytest import CaptureFixture

from iamscope.cli import main
from iamscope.constants import (
    ACTION_CLASS_STS_ASSUME_ROLE,
    PROBE_KIND_SIMULATOR,
    PROBE_STATE_SIMULATOR_ONLY_ALLOWED,
    SIMULATOR_STATE_ALLOWED,
)
from iamscope.models import Constraint
from iamscope.output.probe_overlay_json import write_probe_overlay
from iamscope.truth.probe_overlay import PROBE_OVERLAY_SCHEMA_VERSION, ProbeOverlay, ProbeRecord


def test_edge_truth_cli_renders_confounder_and_probe_state(tmp_path: Path, capsys: CaptureFixture[str]) -> None:
    source = "arn:aws:iam::111111111111:role/Dev"
    target = "arn:aws:iam::222222222222:role/Prod"
    edge_id = "edge-1"
    scenario_hash = "hash-cli"
    constraint = Constraint(
        provider="aws",
        constraint_type="SCP",
        scope_type="OU",
        scope_id="ou-prod",
        policy_id="p-deny-prod-assume",
        statement_id="DenyAssumeRole",
        properties={
            "deny_actions": ["sts:AssumeRole"],
            "deny_not_actions": [],
            "resource_patterns": ["*"],
        },
    ).to_dict()
    scenario = {
        "metadata": {"canonical_hash": scenario_hash},
        "nodes": [],
        "edges": [
            {
                "edge_id": edge_id,
                "edge_type": "sts:AssumeRole_trust",
                "src": {"provider_id": source},
                "dst": {"provider_id": target},
            }
        ],
        "constraints": [constraint],
        "edge_constraints": [{"edge_id": edge_id, "constraint_id": constraint["constraint_id"]}],
        "objectives": [],
        "observations": [],
    }
    scenario_path = tmp_path / "scenario.json"
    scenario_path.write_text(json.dumps(scenario), encoding="utf-8")
    binding_path = tmp_path / "binding_metadata.json"
    binding_path.write_text("[]", encoding="utf-8")
    overlay_path = tmp_path / "probe_overlay.json"
    write_probe_overlay(
        overlay_path,
        ProbeOverlay(
            schema_version=PROBE_OVERLAY_SCHEMA_VERSION,
            engagement_run_id="run-cli",
            scenario_canonical_hash=scenario_hash,
            generated_at_utc="2026-01-01T00:00:01Z",
            probes=(
                ProbeRecord(
                    probe_id="probe-cli",
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
                ),
            ),
        ),
    )

    exit_code = main(
        [
            "edge-truth",
            "--scenario",
            str(scenario_path),
            "--binding-metadata",
            str(binding_path),
            "--probe-overlay",
            str(overlay_path),
            "--source-arn",
            source,
            "--target-arn",
            target,
            "--action-class",
            ACTION_CLASS_STS_ASSUME_ROLE,
        ]
    )

    out = capsys.readouterr().out
    assert exit_code == 0
    assert "Declared: allow" in out
    assert "Simulator: allowed" in out
    assert "Validated: not_probed" in out
    assert "Confounded: true" in out
    assert "Contributing SCPs: p-deny-prod-assume" in out
    assert "Consolidated verdict: confounded_skip" in out


def test_stale_drift_cli_renders_evidence_for_finding_key(tmp_path: Path, capsys: CaptureFixture[str]) -> None:
    edge_id = "edge-stale"
    constraint = {
        "constraint_id": "constraint-stale",
        "provider": "aws",
        "constraint_type": "STALE_PRINCIPAL_DRIFT",
        "scope_type": "EDGE",
        "scope_id": edge_id,
        "policy_id": "arn:aws:iam::111111111111:role/Target",
        "statement_id": "stmt-stale",
        "region": "aws-global",
        "properties": {
            "principal_id": "AROAABCDEFGHIJKLMNOP",
            "principal_id_kind": "role",
            "evidence_level": "complete",
            "drift_state": "stale_unique_id_suspected",
            "reason": "stale principal unique ID in trust",
            "target": "arn:aws:iam::111111111111:role/Target",
        },
        "status": "ACTIVE",
        "validation_status": "UNVALIDATED",
        "confidence_q": 100,
    }
    scenario = {
        "metadata": {"canonical_hash": "hash-stale"},
        "nodes": [],
        "edges": [
            {
                "edge_id": edge_id,
                "edge_type": "sts:AssumeRole_trust",
                "src": {"provider_id": "AROAABCDEFGHIJKLMNOP"},
                "dst": {"provider_id": "arn:aws:iam::111111111111:role/Target"},
            }
        ],
        "constraints": [constraint],
        "edge_constraints": [{"edge_id": edge_id, "constraint_id": "constraint-stale"}],
        "objectives": [],
        "observations": [],
    }
    findings = {
        "findings": [
            {
                "finding_id": "finding-1",
                "finding_key": "finding-key-1",
                "pattern_id": "assume_role_chain",
                "verdict": "blocked",
                "evidence": {"edge_refs": [edge_id], "constraint_refs": ["constraint-stale"]},
            }
        ]
    }
    scenario_path = tmp_path / "scenario.json"
    findings_path = tmp_path / "findings.json"
    scenario_path.write_text(json.dumps(scenario), encoding="utf-8")
    findings_path.write_text(json.dumps(findings), encoding="utf-8")

    exit_code = main(
        [
            "stale-drift",
            "--scenario",
            str(scenario_path),
            "--findings",
            str(findings_path),
            "--finding-key",
            "finding-key-1",
        ]
    )

    out = capsys.readouterr().out
    assert exit_code == 0
    assert "Stale Principal Drift Evidence" in out
    assert "finding_key: finding-key-1" in out
    assert "AROAABCDEFGHIJKLMNOP" in out
    assert edge_id in out
