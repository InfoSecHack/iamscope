"""Tests for frozen-artifact reasoner replay with probe overlays."""

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
from iamscope.models import Edge, Node, ScenarioMetadata
from iamscope.output.probe_overlay_json import write_probe_overlay
from iamscope.output.scenario_json import emit_binding_metadata, emit_scenario
from iamscope.reasoner import AssumeRoleChainReasoner
from iamscope.reasoner.replay import run_reasoners_on_frozen_artifacts
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


def _write_frozen_chain(
    tmp_path: Path,
    *,
    collection_failures: list[dict] | None = None,
    policy_parse_failures: list[dict] | None = None,
) -> tuple[Path, Path, str, str]:
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
        metadata=ScenarioMetadata(
            collection_timestamp="2026-01-01T00:00:00Z",
            collection_failures=collection_failures or [],
            policy_parse_failures=policy_parse_failures or [],
        ),
    )
    scenario_path = tmp_path / "scenario.json"
    scenario_path.write_bytes(scenario_bytes)
    binding_path = tmp_path / "binding_metadata.json"
    binding_path.write_bytes(emit_binding_metadata([]))
    return scenario_path, binding_path, scenario_hash, perm_2.edge_id


def test_replay_overlay_mutates_finding_on_frozen_scenario(tmp_path: Path) -> None:
    scenario_path, binding_path, scenario_hash, denied_permission_edge_id = _write_frozen_chain(tmp_path)

    baseline = run_reasoners_on_frozen_artifacts(
        scenario_path=scenario_path,
        binding_metadata_path=binding_path,
        probe_overlay_path=None,
        reasoner_instances=(AssumeRoleChainReasoner(),),
        reasoning_timestamp="2026-01-01T00:00:00Z",
    )
    assert len(baseline.findings) == 1
    assert baseline.findings[0].verdict.value == "validated"

    overlay_path = tmp_path / "probe_overlay.json"
    write_probe_overlay(
        overlay_path,
        ProbeOverlay(
            schema_version=PROBE_OVERLAY_SCHEMA_VERSION,
            engagement_run_id="run-replay-test",
            scenario_canonical_hash=scenario_hash,
            generated_at_utc="2026-01-01T00:00:01Z",
            probes=(
                ProbeRecord(
                    probe_id="probe-denied-hop",
                    edge_id=denied_permission_edge_id,
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

    overlay_result = run_reasoners_on_frozen_artifacts(
        scenario_path=scenario_path,
        binding_metadata_path=binding_path,
        probe_overlay_path=overlay_path,
        reasoner_instances=(AssumeRoleChainReasoner(),),
        reasoning_timestamp="2026-01-01T00:00:00Z",
    )

    changed = overlay_result.findings[0]
    assert changed.verdict.value == "blocked"
    assert changed.finding_key == baseline.findings[0].finding_key
    assert changed.finding_id != baseline.findings[0].finding_id
    assert any(b.kind == "probe_overlay" for b in changed.blockers_observed)
    trace_inputs = [entry.inputs for entry in changed.evidence.reasoning_trace]
    assert any("probe-denied-hop" in inputs for inputs in trace_inputs)
    assert "p-runtime-deny" in changed.evidence.constraint_refs


def test_replay_attaches_collection_context_from_scenario_metadata(tmp_path: Path) -> None:
    scenario_path, binding_path, _, _ = _write_frozen_chain(
        tmp_path,
        collection_failures=[
            {
                "account_id": _ACCOUNT,
                "collector": "lambda",
                "error_class": "ClientError",
                "error_message": "collection partial",
                "region": "us-east-1",
            }
        ],
    )

    replay_result = run_reasoners_on_frozen_artifacts(
        scenario_path=scenario_path,
        binding_metadata_path=binding_path,
        probe_overlay_path=None,
        reasoner_instances=(AssumeRoleChainReasoner(),),
        reasoning_timestamp="2026-01-01T00:00:00Z",
    )
    findings_json = json.loads(replay_result.findings_bytes)
    context = findings_json["findings"][0]["collection_context"]

    assert replay_result.findings[0].verdict.value == "validated"
    assert context["graph_collection_complete"] is False
    assert context["has_collection_failures"] is True
    assert context["affected_accounts"] == [_ACCOUNT]
    assert context["related_collection_failures"][0]["account_id"] == _ACCOUNT


def test_replay_cli_writes_findings_with_overlay(tmp_path: Path) -> None:
    from iamscope.cli import main

    scenario_path, binding_path, scenario_hash, denied_permission_edge_id = _write_frozen_chain(tmp_path)
    overlay_path = tmp_path / "probe_overlay.json"
    write_probe_overlay(
        overlay_path,
        ProbeOverlay(
            schema_version=PROBE_OVERLAY_SCHEMA_VERSION,
            engagement_run_id="run-replay-cli",
            scenario_canonical_hash=scenario_hash,
            generated_at_utc="2026-01-01T00:00:01Z",
            probes=(
                ProbeRecord(
                    probe_id="probe-cli-denied-hop",
                    edge_id=denied_permission_edge_id,
                    action_class=ACTION_CLASS_STS_ASSUME_ROLE,
                    probe_kind=PROBE_KIND_RUNTIME,
                    probe_state=PROBE_STATE_PROBED_CORRELATED_DENIED,
                    probed_at_utc="2026-01-01T00:00:00Z",
                    authorization_ref=None,
                    confounded=False,
                    confounded_reason="",
                    contributing_control_refs=(),
                    simulator_state=None,
                    runtime_state=VALIDATED_STATE_DENIED,
                    cloudtrail_state=None,
                    notes_digest=None,
                ),
            ),
        ),
    )
    output_path = tmp_path / "findings.json"

    rc = main(
        [
            "replay-findings",
            "--scenario",
            str(scenario_path),
            "--binding-metadata",
            str(binding_path),
            "--probe-overlay",
            str(overlay_path),
            "--reasoners",
            "assume_role_chain",
            "--output",
            str(output_path),
        ]
    )

    findings = json.loads(output_path.read_text(encoding="utf-8"))
    assert rc == 0
    assert findings["findings"][0]["verdict"] == "blocked"
    assert "finding_key" in findings["findings"][0]
    assert findings["findings"][0]["evidence"]["reasoning_trace"][-1]["action"] == "apply_probe_overlay"
