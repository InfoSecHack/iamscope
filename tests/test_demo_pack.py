"""Tests for the small truth-aware demo-pack builder."""

from __future__ import annotations

import json
from pathlib import Path

from iamscope.constants import (
    ACTION_CLASS_STS_ASSUME_ROLE,
    NODE_TYPE_IAM_ROLE,
    NODE_TYPE_IAM_USER,
    PROBE_KIND_RUNTIME,
    PROBE_STATE_PROBED_CORRELATED_DENIED,
    PROVIDER_AWS,
    REGION_GLOBAL,
    VALIDATED_STATE_DENIED,
)
from iamscope.demo_pack import build_demo_pack
from iamscope.models import Edge, Node, ScenarioMetadata
from iamscope.output.probe_overlay_json import write_probe_overlay
from iamscope.output.scenario_json import emit_binding_metadata, emit_scenario
from iamscope.reasoner import AssumeRoleChainReasoner
from iamscope.truth.probe_overlay import PROBE_OVERLAY_SCHEMA_VERSION, ProbeOverlay, ProbeRecord

_ACCOUNT = "111111\u003111111"
_ALICE = f"arn:aws:iam::{_ACCOUNT}:user/Alice"
_DEVOPS = f"arn:aws:iam::{_ACCOUNT}:role/DevOps"
_ADMIN = f"arn:aws:iam::{_ACCOUNT}:role/Admin"


def _node(arn: str, node_type: str) -> Node:
    return Node(
        provider=PROVIDER_AWS,
        node_type=node_type,
        provider_id=arn,
        region=REGION_GLOBAL,
        properties={"account_id": _ACCOUNT},
    )


def _assume_permission(src: Node, dst: Node, digest: str) -> Edge:
    return Edge(
        edge_type="sts:AssumeRole_permission",
        src=src.to_ref(),
        dst=dst.to_ref(),
        region=REGION_GLOBAL,
        features={
            "allow_controls": [
                {
                    "control_type": "PERMISSION",
                    "digest": digest,
                    "policy_arn": f"arn:aws:iam::{_ACCOUNT}:policy/AssumeRole",
                    "statement_index": 0,
                    "summary": "sts:AssumeRole grant",
                }
            ],
            "effect": "Allow",
            "has_conditions": False,
            "is_wildcard_resource": False,
            "layer": "permission",
            "raw_conditions": {},
            "resource_pattern": dst.provider_id,
            "statement_index": 0,
        },
    )


def _trust(src: Node, dst: Node, digest: str) -> Edge:
    return Edge(
        edge_type="sts:AssumeRole_trust",
        src=src.to_ref(),
        dst=dst.to_ref(),
        region=REGION_GLOBAL,
        features={
            "allow_controls": [
                {
                    "control_type": "TRUST",
                    "digest": digest,
                    "policy_arn": dst.provider_id,
                    "statement_index": 0,
                    "summary": "trust statement",
                }
            ],
            "effect": "Allow",
            "has_conditions": False,
            "is_wildcard_principal": False,
            "layer": "trust",
            "principal_type": "AWS",
            "raw_conditions": {},
            "statement_index": 0,
        },
    )


def _admin_grant(role: Node) -> Edge:
    return Edge(
        edge_type="iam:*_permission",
        src=role.to_ref(),
        dst=role.to_ref(),
        region=REGION_GLOBAL,
        features={
            "allow_controls": [
                {
                    "control_type": "PERMISSION",
                    "digest": "a" * 64,
                    "policy_arn": "arn:aws:iam::aws:policy/AdministratorAccess",
                    "statement_index": 0,
                    "summary": "iam:*",
                }
            ],
            "effect": "Allow",
            "has_conditions": False,
            "is_wildcard_resource": True,
            "layer": "permission",
            "raw_conditions": {},
            "resource_pattern": "*",
            "statement_index": 0,
        },
    )


def _write_frozen_chain(tmp_path: Path) -> tuple[Path, Path, str, str]:
    alice = _node(_ALICE, NODE_TYPE_IAM_USER)
    devops = _node(_DEVOPS, NODE_TYPE_IAM_ROLE)
    admin = _node(_ADMIN, NODE_TYPE_IAM_ROLE)
    perm_1 = _assume_permission(alice, devops, "1" * 64)
    trust_1 = _trust(alice, devops, "2" * 64)
    perm_2 = _assume_permission(devops, admin, "3" * 64)
    trust_2 = _trust(devops, admin, "4" * 64)
    admin_grant = _admin_grant(admin)
    scenario_bytes, scenario_hash = emit_scenario(
        nodes=[alice, devops, admin],
        edges=[perm_1, trust_1, perm_2, trust_2, admin_grant],
        constraints=[],
        edge_constraints=[],
        metadata=ScenarioMetadata(collection_timestamp="2026-01-01T00:00:00Z"),
    )
    scenario_path = tmp_path / "scenario.json"
    scenario_path.write_bytes(scenario_bytes)
    binding_path = tmp_path / "binding_metadata.json"
    binding_path.write_bytes(emit_binding_metadata([]))
    return scenario_path, binding_path, scenario_hash, perm_2.edge_id


def _write_denied_overlay(overlay_path: Path, *, scenario_hash: str, edge_id: str, probe_id: str) -> None:
    write_probe_overlay(
        overlay_path,
        ProbeOverlay(
            schema_version=PROBE_OVERLAY_SCHEMA_VERSION,
            engagement_run_id="run-demo-pack",
            scenario_canonical_hash=scenario_hash,
            generated_at_utc="2026-01-01T00:00:01Z",
            probes=(
                ProbeRecord(
                    probe_id=probe_id,
                    edge_id=edge_id,
                    action_class=ACTION_CLASS_STS_ASSUME_ROLE,
                    probe_kind=PROBE_KIND_RUNTIME,
                    probe_state=PROBE_STATE_PROBED_CORRELATED_DENIED,
                    probed_at_utc="2026-01-01T00:00:00Z",
                    authorization_ref=None,
                    confounded=False,
                    confounded_reason="",
                    contributing_control_refs=("p-runtime-deny",),
                    simulator_state=None,
                    runtime_state=VALIDATED_STATE_DENIED,
                    cloudtrail_state=None,
                    notes_digest=None,
                ),
            ),
        ),
    )


def test_demo_pack_builds_replay_and_diff_artifacts(tmp_path: Path) -> None:
    scenario_path, binding_path, scenario_hash, permission_edge_id = _write_frozen_chain(tmp_path)
    overlay_path = tmp_path / "probe_overlay.json"
    _write_denied_overlay(
        overlay_path,
        scenario_hash=scenario_hash,
        edge_id=permission_edge_id,
        probe_id="probe-demo-pack",
    )

    output_dir = tmp_path / "demo-pack"
    result = build_demo_pack(
        scenario_path=scenario_path,
        binding_metadata_path=binding_path,
        probe_overlay_path=overlay_path,
        output_dir=output_dir,
        reasoner_instances=(AssumeRoleChainReasoner(),),
        reasoner_ids=("assume_role_chain",),
    )

    assert result.baseline_findings_path.exists()
    assert result.overlay_findings_path is not None
    assert result.overlay_findings_path.exists()
    assert result.diff_json_path is not None
    assert result.diff_json_path.exists()
    assert result.diff_markdown_path is not None
    assert result.diff_markdown_path.exists()
    assert result.readme_path.exists()
    assert result.manifest_path.exists()

    diff = json.loads(result.diff_json_path.read_text(encoding="utf-8"))
    baseline = json.loads(result.baseline_findings_path.read_text(encoding="utf-8"))
    overlay = json.loads(result.overlay_findings_path.read_text(encoding="utf-8"))
    assert diff["summary"]["verdict_changes"] == 1
    assert diff["summary"]["probe_evidence_additions"] == 1
    assert diff["changes"][0]["baseline_verdict"] == "validated"
    assert diff["changes"][0]["candidate_verdict"] == "blocked"
    assert "finding_key" in diff["changes"][0]
    assert baseline["findings"][0]["finding_key"] == overlay["findings"][0]["finding_key"]
    assert diff["changes"][0]["finding_key"] == baseline["findings"][0]["finding_key"]
