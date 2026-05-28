"""Tests for thin IAMScope truth-artifact ingestion in the SeRIM ARF wrapper."""

from __future__ import annotations

import builtins
import importlib.util
import json
import os
import subprocess
import sys
from pathlib import Path
from types import ModuleType
from typing import Any

import pytest
from pytest import CaptureFixture, MonkeyPatch

from iamscope.constants import (
    ACTION_CLASS_STS_ASSUME_ROLE,
    CONSTRAINT_TYPE_PERMISSION_BOUNDARY,
    CONSTRAINT_TYPE_RESOURCE_POLICY_DENY,
    CONSTRAINT_TYPE_STALE_PRINCIPAL_DRIFT,
    PROBE_KIND_RUNTIME,
    PROBE_STATE_CONFOUNDED_SKIP,
    PROBE_STATE_PROBED_CORRELATED_ALLOWED,
    PROBE_STATE_PROBED_CORRELATED_DENIED,
    VALIDATED_STATE_ALLOWED,
    VALIDATED_STATE_DENIED,
)
from iamscope.truth.probe_overlay import PROBE_OVERLAY_SCHEMA_VERSION

_TOOL_PATH = Path(__file__).resolve().parents[1] / "tools" / "serim_arf_rt_compare.py"


def _load_wrapper() -> ModuleType:
    spec = importlib.util.spec_from_file_location("serim_arf_rt_compare", _TOOL_PATH)
    assert spec is not None
    assert spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _scenario(edge_ids: list[str]) -> dict[str, Any]:
    return {
        "metadata": {"canonical_hash": "scenario-hash"},
        "edges": [{"edge_id": edge_id} for edge_id in edge_ids],
        "constraints": [],
        "edge_constraints": [],
    }


def _scenario_with_roles() -> dict[str, Any]:
    return {
        "metadata": {"canonical_hash": "scenario-hash"},
        "nodes": [
            {
                "node_id": "node-start",
                "provider": "aws",
                "node_type": "IAMRole",
                "provider_id": "arn:aws:iam::111111111111:role/Start",
            },
            {
                "node_id": "node-target",
                "provider": "aws",
                "node_type": "IAMRole",
                "provider_id": "arn:aws:iam::222222222222:role/Target",
            },
        ],
        "edges": [],
        "constraints": [],
        "edge_constraints": [],
    }


def _probe(edge_id: str, probe_state: str, runtime_state: str | None) -> dict[str, Any]:
    return {
        "action_class": ACTION_CLASS_STS_ASSUME_ROLE,
        "authorization_ref": None,
        "cloudtrail_state": None,
        "confounded": probe_state == PROBE_STATE_CONFOUNDED_SKIP,
        "confounded_reason": "inherited SCP" if probe_state == PROBE_STATE_CONFOUNDED_SKIP else "",
        "contributing_control_refs": ["scp-prod"] if probe_state == PROBE_STATE_CONFOUNDED_SKIP else [],
        "edge_id": edge_id,
        "notes_digest": None,
        "probe_id": f"probe-{edge_id}",
        "probe_kind": PROBE_KIND_RUNTIME,
        "probe_state": probe_state,
        "probed_at_utc": "2026-01-01T00:00:00Z",
        "runtime_state": runtime_state,
        "simulator_state": None,
    }


def _write_overlay(path: Path, probes: list[dict[str, Any]]) -> None:
    path.write_text(
        json.dumps(
            {
                "engagement_run_id": "run-test",
                "generated_at_utc": "2026-01-01T00:00:00Z",
                "probes": probes,
                "scenario_canonical_hash": "scenario-hash",
                "schema_version": PROBE_OVERLAY_SCHEMA_VERSION,
            }
        ),
        encoding="utf-8",
    )


def test_plain_scenario_accepts_explicit_objective_args() -> None:
    wrapper = _load_wrapper()
    raw = _scenario_with_roles()

    prepared = wrapper.prepare_scenario_for_arf(
        raw,
        start_role_arn="arn:aws:iam::111111111111:role/Start",
        target_role_arn="arn:aws:iam::222222222222:role/Target",
        max_depth=4,
    )
    normalized = wrapper.normalize_for_arf_rt(prepared)

    assert "objectives" not in raw
    assert prepared is not raw
    assert prepared["objectives"] == [
        {
            "objective_type": "reachability",
            "start_nodes": ["arn:aws:iam::111111111111:role/Start"],
            "target_nodes": ["arn:aws:iam::222222222222:role/Target"],
            "max_depth": 4,
            "k": 5,
        }
    ]
    assert normalized["objectives"][0]["objective_type"] == "REACHABILITY"
    assert normalized["objectives"][0]["start_nodes"][0]["provider_id"] == "arn:aws:iam::111111111111:role/Start"
    assert normalized["objectives"][0]["target_nodes"][0]["provider_id"] == "arn:aws:iam::222222222222:role/Target"
    assert normalized["objectives"][0]["max_depth"] == 4


def test_plain_scenario_without_objective_args_fails_clearly(
    monkeypatch: MonkeyPatch,
    capsys: CaptureFixture[str],
    tmp_path: Path,
) -> None:
    wrapper = _load_wrapper()
    scenario_path = tmp_path / "scenario.json"
    scenario_path.write_text(json.dumps(_scenario_with_roles()), encoding="utf-8")
    monkeypatch.setattr(sys, "argv", ["serim_arf_rt_compare.py", "--scenario", str(scenario_path)])

    exit_code = wrapper.main()
    captured = capsys.readouterr()

    assert exit_code == 2
    assert "Scenario has no objectives" in captured.err
    assert "--start-role-arn" in captured.err
    assert "scenario_with_objective.json" in captured.err


def test_objective_bearing_scenario_is_preserved() -> None:
    wrapper = _load_wrapper()
    raw = {
        **_scenario_with_roles(),
        "objectives": [
            {
                "objective_type": "reachability",
                "start_nodes": ["arn:aws:iam::111111111111:role/Start"],
                "target_nodes": ["arn:aws:iam::222222222222:role/Target"],
                "max_depth": 5,
                "k": 3,
            }
        ],
    }

    prepared = wrapper.prepare_scenario_for_arf(
        raw,
        start_role_arn="arn:aws:iam::000000000000:role/Ignored",
        target_role_arn="arn:aws:iam::000000000000:role/IgnoredTarget",
        max_depth=9,
    )

    assert prepared is raw
    assert prepared["objectives"][0]["max_depth"] == 5
    assert prepared["objectives"][0]["k"] == 3


def _scenario_with_edge_and_constraint() -> dict[str, Any]:
    raw = _scenario_with_roles()
    start, target = raw["nodes"]
    raw["edges"] = [
        {
            "edge_id": "edge-a",
            "edge_type": "sts:AssumeRole_permission",
            "src": start,
            "dst": target,
            "features": {},
        }
    ]
    raw["constraints"] = [
        {
            "constraint_id": "constraint-a",
            "provider": "aws",
            "constraint_type": "SCP",
            "scope_type": "OU",
            "scope_id": "ou-prod",
            "properties": {"policy_id": "p-prod"},
        }
    ]
    return raw


def test_edge_constraint_preflight_keeps_valid_translated_links() -> None:
    wrapper = _load_wrapper()
    raw = _scenario_with_edge_and_constraint()
    raw["edge_constraints"] = [{"edge_id": "edge-a", "constraint_id": "constraint-a", "relation_type": "DEPENDS_ON"}]

    normalized = wrapper.normalize_for_arf_rt(raw)
    cleaned, diagnostics = wrapper.preflight_arf_edge_constraints(normalized)

    assert cleaned["edge_constraints"] == normalized["edge_constraints"]
    assert diagnostics["edge_constraints_dropped"] == 0
    assert diagnostics["edge_constraints_kept"] == 1


def test_edge_constraint_preflight_prunes_dangling_links() -> None:
    wrapper = _load_wrapper()
    raw = _scenario_with_edge_and_constraint()
    raw["edge_constraints"] = [
        {"edge_id": "edge-a", "constraint_id": "constraint-a", "relation_type": "DEPENDS_ON"},
        {"edge_id": "missing-edge", "constraint_id": "constraint-a", "relation_type": "DEPENDS_ON"},
        {"edge_id": "edge-a", "constraint_id": "missing-constraint", "relation_type": "DEPENDS_ON"},
    ]

    normalized = wrapper.normalize_for_arf_rt(raw)
    cleaned, diagnostics = wrapper.preflight_arf_edge_constraints(normalized)

    assert len(cleaned["edge_constraints"]) == 1
    assert cleaned["edge_constraints"][0]["relation_type"] == "DEPENDS_ON"
    assert diagnostics["edge_constraints_input"] == 3
    assert diagnostics["edge_constraints_kept"] == 1
    assert diagnostics["edge_constraints_dropped"] == 2
    assert diagnostics["dropped_invalid_ref"] == 2
    assert diagnostics["constraints_pruned"] == 0


def test_edge_constraint_preflight_prunes_arf_unsupported_constraints() -> None:
    wrapper = _load_wrapper()
    raw = _scenario_with_edge_and_constraint()
    raw["constraints"].append(
        {
            "constraint_id": "constraint-resource-condition",
            "provider": "aws",
            "constraint_type": "RESOURCE_POLICY_CONDITION",
            "scope_type": "RESOURCE",
            "scope_id": "arn:aws:kms:us-east-1:111111111111:key/demo",
            "properties": {"statement_digest": "abc"},
        }
    )
    raw["edge_constraints"] = [
        {"edge_id": "edge-a", "constraint_id": "constraint-a", "relation_type": "APPLIES_TO"},
        {
            "edge_id": "edge-a",
            "constraint_id": "constraint-resource-condition",
            "relation_type": "APPLIES_TO",
        },
    ]

    normalized = wrapper.normalize_for_arf_rt(raw)
    assert len(normalized["constraints"]) == 2
    assert len(normalized["edge_constraints"]) == 2

    cleaned, diagnostics = wrapper.preflight_arf_edge_constraints(normalized)

    assert [c["constraint_type"] for c in cleaned["constraints"]] == ["SCP"]
    assert len(cleaned["edge_constraints"]) == 1
    assert diagnostics["constraints_input"] == 2
    assert diagnostics["constraints_kept"] == 1
    assert diagnostics["constraints_pruned"] == 1
    assert diagnostics["edge_constraints_input"] == 2
    assert diagnostics["edge_constraints_kept"] == 1
    assert diagnostics["edge_constraints_dropped"] == 1
    assert diagnostics["dropped_unsupported_constraint_type"] == 1


def test_no_overlay_leaves_wrapper_truth_unvalidated() -> None:
    wrapper = _load_wrapper()

    truth_index = wrapper.build_truth_index(_scenario(["edge-a"]))
    truth = wrapper.classify_candidate_truth("edge-a", truth_index)

    assert truth_index["truth_artifacts_present"] is False
    assert truth["declared_edge"] is True
    assert truth["validated_allow"] is False
    assert truth["validated_deny"] is False
    assert truth["confounded"] is False
    assert truth["probe_states"] == []


def test_overlay_surfaces_validated_allow_deny_and_confounded(tmp_path: Path) -> None:
    wrapper = _load_wrapper()
    scenario = _scenario(["edge-allow", "edge-deny", "edge-confounded"])
    overlay_path = tmp_path / "probe_overlay.json"
    _write_overlay(
        overlay_path,
        [
            _probe(
                "edge-allow",
                PROBE_STATE_PROBED_CORRELATED_ALLOWED,
                VALIDATED_STATE_ALLOWED,
            ),
            _probe(
                "edge-deny",
                PROBE_STATE_PROBED_CORRELATED_DENIED,
                VALIDATED_STATE_DENIED,
            ),
            _probe("edge-confounded", PROBE_STATE_CONFOUNDED_SKIP, None),
        ],
    )

    truth_index = wrapper.build_truth_index(scenario, probe_overlay_path=overlay_path)

    assert wrapper.classify_candidate_truth("edge-allow", truth_index)["validated_allow"] is True
    assert wrapper.classify_candidate_truth("edge-deny", truth_index)["validated_deny"] is True
    confounded = wrapper.classify_candidate_truth("edge-confounded", truth_index)
    assert confounded["confounded"] is True
    assert confounded["contributing_control_refs"] == ["scp-prod"]


def test_constraints_and_findings_surface_wrapper_truth(tmp_path: Path) -> None:
    wrapper = _load_wrapper()
    scenario = {
        **_scenario(["edge-a"]),
        "constraints": [
            {"constraint_id": "c-stale", "constraint_type": CONSTRAINT_TYPE_STALE_PRINCIPAL_DRIFT},
            {"constraint_id": "c-boundary", "constraint_type": CONSTRAINT_TYPE_PERMISSION_BOUNDARY},
            {"constraint_id": "c-resource", "constraint_type": CONSTRAINT_TYPE_RESOURCE_POLICY_DENY},
        ],
        "edge_constraints": [
            {"edge_id": "edge-a", "constraint_id": "c-stale"},
            {"edge_id": "edge-a", "constraint_id": "c-boundary"},
            {"edge_id": "edge-a", "constraint_id": "c-resource"},
        ],
    }
    findings_path = tmp_path / "findings.json"
    findings_path.write_text(
        json.dumps(
            {
                "findings": [
                    {
                        "finding_id": "finding-id",
                        "finding_key": "finding-key",
                        "pattern_id": "cross_account_trust",
                        "verdict": "blocked",
                        "evidence": {"edge_refs": ["edge-a"]},
                    }
                ]
            }
        ),
        encoding="utf-8",
    )

    truth_index = wrapper.build_truth_index(scenario, findings_path=findings_path)
    truth = wrapper.classify_candidate_truth("edge-a", truth_index)

    assert truth["stale_drift_evidence"] is True
    assert truth["permission_boundary_evidence"] is True
    assert truth["resource_policy_deny_evidence"] is True
    assert truth["constraint_types"] == [
        CONSTRAINT_TYPE_PERMISSION_BOUNDARY,
        CONSTRAINT_TYPE_RESOURCE_POLICY_DENY,
        CONSTRAINT_TYPE_STALE_PRINCIPAL_DRIFT,
    ]
    assert truth["finding_refs"] == [
        {
            "finding_id": "finding-id",
            "finding_key": "finding-key",
            "pattern_id": "cross_account_trust",
            "verdict": "blocked",
        }
    ]


def test_missing_arf_runtime_dependency_fails_actionably(
    monkeypatch: MonkeyPatch,
    capsys: CaptureFixture[str],
    tmp_path: Path,
) -> None:
    wrapper = _load_wrapper()
    scenario_path = tmp_path / "scenario_with_objective.json"
    scenario_path.write_text(
        json.dumps(
            {
                **_scenario_with_roles(),
                "objectives": [
                    {
                        "objective_type": "reachability",
                        "start_nodes": ["arn:aws:iam::111111111111:role/Start"],
                        "target_nodes": ["arn:aws:iam::222222222222:role/Target"],
                        "max_depth": 6,
                        "k": 5,
                    }
                ],
            }
        ),
        encoding="utf-8",
    )
    original_import = builtins.__import__

    def fake_import(name: str, *args: Any, **kwargs: Any) -> Any:
        if name.startswith("arf_rt"):
            raise ModuleNotFoundError("No module named 'arf_rt'")
        return original_import(name, *args, **kwargs)

    monkeypatch.setattr(builtins, "__import__", fake_import)
    monkeypatch.setattr(
        sys,
        "argv",
        [
            "serim_arf_rt_compare.py",
            "--scenario",
            str(scenario_path),
            "--arf-rt-repo",
            str(tmp_path),
        ],
    )

    exit_code = wrapper.main()
    captured = capsys.readouterr()

    assert exit_code == 2
    assert "ARF wrapper requires the external ARF runtime environment" in captured.err
    assert "IAMSCOPE_ARF_RT_REPO" in captured.err
    assert "Import error: No module named 'arf_rt'" in captured.err


def test_original_iamscope_edge_id_is_recovered_for_truth_join(tmp_path: Path) -> None:
    wrapper = _load_wrapper()
    scenario = _scenario_with_roles()
    start, target = scenario["nodes"]
    scenario["edges"] = [
        {
            "edge_id": "iamscope-edge-1",
            "edge_type": "sts:AssumeRole_permission",
            "src": start,
            "dst": target,
            "region": "aws-global",
            "features": {},
        }
    ]
    overlay_path = tmp_path / "probe_overlay.json"
    _write_overlay(
        overlay_path,
        [
            _probe(
                "iamscope-edge-1",
                PROBE_STATE_PROBED_CORRELATED_ALLOWED,
                VALIDATED_STATE_ALLOWED,
            )
        ],
    )

    normalized = wrapper.normalize_for_arf_rt(scenario)
    assert "edge_id" not in normalized["edges"][0]
    original_edge_ids, diagnostics = wrapper.build_original_edge_id_index(scenario)
    mapped_edge_id = wrapper.resolve_original_edge_id(
        {
            "edge_id": 17,
            "edge_type": normalized["edges"][0]["edge_type"],
            "src": normalized["edges"][0]["src"]["provider_id"],
            "dst": normalized["edges"][0]["dst"]["provider_id"],
            "region": normalized["edges"][0]["region"],
        },
        original_edge_ids,
    )
    truth_index = wrapper.build_truth_index(scenario, probe_overlay_path=overlay_path)
    truth = wrapper.classify_candidate_truth(mapped_edge_id, truth_index)

    assert diagnostics["unique_mappings"] == 1
    assert mapped_edge_id == "iamscope-edge-1"
    assert truth["validated_allow"] is True


def test_ambiguous_regionless_fallback_fails_closed() -> None:
    wrapper = _load_wrapper()
    scenario = _scenario_with_roles()
    start, target = scenario["nodes"]
    scenario["edges"] = [
        {
            "edge_id": "iamscope-edge-east",
            "edge_type": "sts:AssumeRole_permission",
            "src": start,
            "dst": target,
            "region": "us-east-1",
            "features": {},
        },
        {
            "edge_id": "iamscope-edge-west",
            "edge_type": "sts:AssumeRole_permission",
            "src": start,
            "dst": target,
            "region": "us-west-2",
            "features": {},
        },
    ]

    original_edge_ids, diagnostics = wrapper.build_original_edge_id_index(scenario)
    mapped_edge_id = wrapper.resolve_original_edge_id(
        {
            "edge_id": 17,
            "edge_type": "sts:AssumeRole_permission",
            "src": start["provider_id"],
            "dst": target["provider_id"],
        },
        original_edge_ids,
    )

    assert diagnostics["unique_mappings"] == 2
    assert diagnostics["regionless_unique_mappings"] == 0
    assert diagnostics["regionless_ambiguous_mappings"] == 1
    assert mapped_edge_id is None


_ARF_RT_REPO = Path(os.environ.get("IAMSCOPE_ARF_RT_REPO", str(Path.home() / "arf_rt_repro")))
_ARF_RT_PYTHON = _ARF_RT_REPO / ".venv/bin/python"


def test_live_runtime_wrapper_rejoins_original_edge_id_and_truth(tmp_path: Path) -> None:
    if not _ARF_RT_PYTHON.exists():
        pytest.skip("external arf_rt runtime not present")

    scenario = _scenario_with_roles()
    start, target = scenario["nodes"]
    scenario["metadata"] = {"canonical_hash": "scenario-hash"}
    scenario["edges"] = [
        {
            "edge_id": "iamscope-edge-live-1",
            "edge_type": "sts:AssumeRole_permission",
            "src": start,
            "dst": target,
            "region": "aws-global",
            "features": {},
            "status": "HYPOTHESIZED",
        }
    ]
    scenario["objectives"] = [
        {
            "objective_type": "reachability",
            "start_nodes": [start["provider_id"]],
            "target_nodes": [target["provider_id"]],
            "max_depth": 3,
            "k": 1,
        }
    ]
    scenario_path = tmp_path / "scenario_with_objective.json"
    scenario_path.write_text(json.dumps(scenario), encoding="utf-8")

    overlay_path = tmp_path / "probe_overlay.json"
    _write_overlay(
        overlay_path,
        [
            _probe(
                "iamscope-edge-live-1",
                PROBE_STATE_PROBED_CORRELATED_ALLOWED,
                VALIDATED_STATE_ALLOWED,
            )
        ],
    )

    findings_path = tmp_path / "findings.json"
    findings_path.write_text(
        json.dumps(
            {
                "findings": [
                    {
                        "finding_id": "finding-live-id",
                        "finding_key": "finding-live-key",
                        "pattern_id": "assume_role_chain",
                        "verdict": "validated",
                        "evidence": {"edge_refs": ["iamscope-edge-live-1"]},
                    }
                ]
            }
        ),
        encoding="utf-8",
    )

    output_dir = tmp_path / "out"
    env = dict(os.environ)
    env["PYTHONPATH"] = f"{_TOOL_PATH.parents[1]}:{_ARF_RT_REPO}"
    result = subprocess.run(
        [
            str(_ARF_RT_PYTHON),
            str(_TOOL_PATH),
            "--scenario",
            str(scenario_path),
            "--probe-overlay",
            str(overlay_path),
            "--findings",
            str(findings_path),
            "--output-dir",
            str(output_dir),
        ],
        capture_output=True,
        check=True,
        text=True,
        env=env,
    )

    stdout = json.loads(result.stdout)
    summary = json.loads((output_dir / "serim_arf_rt_first_probe_summary.json").read_text(encoding="utf-8"))

    for policy_name, policy_row in summary["policies"].items():
        first_probe = policy_row["first_probe"]
        truth = policy_row["truth"]
        assert stdout["policies"][policy_name]["edge"] == "iamscope-edge-live-1"
        assert first_probe["arf_edge_id"] != "iamscope-edge-live-1"
        assert first_probe["edge_id"] == "iamscope-edge-live-1"
        assert first_probe["iamscope_edge_id"] == "iamscope-edge-live-1"
        assert truth["validated_allow"] is True
        assert truth["probe_states"] == [PROBE_STATE_PROBED_CORRELATED_ALLOWED]
        assert truth["finding_refs"] == [
            {
                "finding_id": "finding-live-id",
                "finding_key": "finding-live-key",
                "pattern_id": "assume_role_chain",
                "verdict": "validated",
            }
        ]


def _write_runtime_scenario(path: Path) -> None:
    scenario = _scenario_with_roles()
    start, target = scenario["nodes"]
    scenario["metadata"] = {"canonical_hash": "scenario-hash"}
    scenario["edges"] = [
        {
            "edge_id": "iamscope-edge-runtime-1",
            "edge_type": "sts:AssumeRole_permission",
            "src": start,
            "dst": target,
            "region": "aws-global",
            "features": {},
            "status": "HYPOTHESIZED",
        }
    ]
    scenario["objectives"] = [
        {
            "objective_type": "reachability",
            "start_nodes": [start["provider_id"]],
            "target_nodes": [target["provider_id"]],
            "max_depth": 3,
            "k": 1,
        }
    ]
    path.write_text(json.dumps(scenario), encoding="utf-8")


def test_runtime_summary_omits_findings_input_when_not_supplied(tmp_path: Path) -> None:
    if not _ARF_RT_PYTHON.exists():
        pytest.skip("external arf_rt runtime not present")

    scenario_path = tmp_path / "scenario_with_objective.json"
    _write_runtime_scenario(scenario_path)
    output_dir = tmp_path / "out"
    env = dict(os.environ)
    env["PYTHONPATH"] = f"{_TOOL_PATH.parents[1]}:{_ARF_RT_REPO}"

    subprocess.run(
        [
            str(_ARF_RT_PYTHON),
            str(_TOOL_PATH),
            "--scenario",
            str(scenario_path),
            "--output-dir",
            str(output_dir),
        ],
        capture_output=True,
        check=True,
        text=True,
        env=env,
    )

    summary = json.loads((output_dir / "serim_arf_rt_first_probe_summary.json").read_text(encoding="utf-8"))

    assert "findings" not in summary["inputs"]


def test_runtime_summary_reports_findings_input_when_supplied(tmp_path: Path) -> None:
    if not _ARF_RT_PYTHON.exists():
        pytest.skip("external arf_rt runtime not present")

    scenario_path = tmp_path / "scenario_with_objective.json"
    _write_runtime_scenario(scenario_path)
    findings_path = tmp_path / "findings.json"
    findings_path.write_text(json.dumps({"findings": []}), encoding="utf-8")
    output_dir = tmp_path / "out"
    env = dict(os.environ)
    env["PYTHONPATH"] = f"{_TOOL_PATH.parents[1]}:{_ARF_RT_REPO}"

    subprocess.run(
        [
            str(_ARF_RT_PYTHON),
            str(_TOOL_PATH),
            "--scenario",
            str(scenario_path),
            "--findings",
            str(findings_path),
            "--output-dir",
            str(output_dir),
        ],
        capture_output=True,
        check=True,
        text=True,
        env=env,
    )

    summary = json.loads((output_dir / "serim_arf_rt_first_probe_summary.json").read_text(encoding="utf-8"))

    assert summary["inputs"]["findings"] == str(findings_path)


def test_runtime_missing_findings_input_does_not_emit_summary(tmp_path: Path) -> None:
    if not _ARF_RT_PYTHON.exists():
        pytest.skip("external arf_rt runtime not present")

    scenario_path = tmp_path / "scenario_with_objective.json"
    _write_runtime_scenario(scenario_path)
    missing_findings_path = tmp_path / "missing-findings.json"
    output_dir = tmp_path / "out"
    env = dict(os.environ)
    env["PYTHONPATH"] = f"{_TOOL_PATH.parents[1]}:{_ARF_RT_REPO}"

    result = subprocess.run(
        [
            str(_ARF_RT_PYTHON),
            str(_TOOL_PATH),
            "--scenario",
            str(scenario_path),
            "--findings",
            str(missing_findings_path),
            "--output-dir",
            str(output_dir),
        ],
        capture_output=True,
        check=False,
        text=True,
        env=env,
    )

    assert result.returncode != 0
    assert not (output_dir / "serim_arf_rt_first_probe_summary.json").exists()


def test_runtime_summary_omits_binding_metadata_when_not_supplied(tmp_path: Path) -> None:
    if not _ARF_RT_PYTHON.exists():
        pytest.skip("external arf_rt runtime not present")

    scenario_path = tmp_path / "scenario_with_objective.json"
    _write_runtime_scenario(scenario_path)
    output_dir = tmp_path / "out"
    env = dict(os.environ)
    env["PYTHONPATH"] = f"{_TOOL_PATH.parents[1]}:{_ARF_RT_REPO}"

    subprocess.run(
        [
            str(_ARF_RT_PYTHON),
            str(_TOOL_PATH),
            "--scenario",
            str(scenario_path),
            "--output-dir",
            str(output_dir),
        ],
        capture_output=True,
        check=True,
        text=True,
        env=env,
    )

    summary = json.loads((output_dir / "serim_arf_rt_first_probe_summary.json").read_text(encoding="utf-8"))

    assert "binding_metadata" not in summary["inputs"]


def test_runtime_summary_reports_binding_metadata_when_explicitly_supplied(tmp_path: Path) -> None:
    if not _ARF_RT_PYTHON.exists():
        pytest.skip("external arf_rt runtime not present")

    scenario_path = tmp_path / "scenario_with_objective.json"
    _write_runtime_scenario(scenario_path)
    binding_metadata_path = tmp_path / "binding_metadata.json"
    binding_metadata_path.write_text(json.dumps({"edge_bindings": []}), encoding="utf-8")
    output_dir = tmp_path / "out"
    env = dict(os.environ)
    env["PYTHONPATH"] = f"{_TOOL_PATH.parents[1]}:{_ARF_RT_REPO}"

    subprocess.run(
        [
            str(_ARF_RT_PYTHON),
            str(_TOOL_PATH),
            "--scenario",
            str(scenario_path),
            "--binding-metadata",
            str(binding_metadata_path),
            "--output-dir",
            str(output_dir),
        ],
        capture_output=True,
        check=True,
        text=True,
        env=env,
    )

    summary = json.loads((output_dir / "serim_arf_rt_first_probe_summary.json").read_text(encoding="utf-8"))

    assert summary["inputs"]["binding_metadata"] == str(binding_metadata_path)


def test_runtime_summary_does_not_report_invalid_binding_metadata_path(tmp_path: Path) -> None:
    if not _ARF_RT_PYTHON.exists():
        pytest.skip("external arf_rt runtime not present")

    scenario_path = tmp_path / "scenario_with_objective.json"
    _write_runtime_scenario(scenario_path)
    missing_binding_metadata_path = tmp_path / "missing-binding-metadata.json"
    output_dir = tmp_path / "out"
    env = dict(os.environ)
    env["PYTHONPATH"] = f"{_TOOL_PATH.parents[1]}:{_ARF_RT_REPO}"

    subprocess.run(
        [
            str(_ARF_RT_PYTHON),
            str(_TOOL_PATH),
            "--scenario",
            str(scenario_path),
            "--binding-metadata",
            str(missing_binding_metadata_path),
            "--output-dir",
            str(output_dir),
        ],
        capture_output=True,
        check=True,
        text=True,
        env=env,
    )

    summary = json.loads((output_dir / "serim_arf_rt_first_probe_summary.json").read_text(encoding="utf-8"))

    assert "binding_metadata" not in summary["inputs"]
    assert any(
        "binding_metadata input was supplied but is not a readable file" in warning
        for warning in summary["ingest_warnings"]
    )


def test_runtime_summary_omits_probe_overlay_when_not_supplied(tmp_path: Path) -> None:
    if not _ARF_RT_PYTHON.exists():
        pytest.skip("external arf_rt runtime not present")

    scenario_path = tmp_path / "scenario_with_objective.json"
    _write_runtime_scenario(scenario_path)
    output_dir = tmp_path / "out"
    env = dict(os.environ)
    env["PYTHONPATH"] = f"{_TOOL_PATH.parents[1]}:{_ARF_RT_REPO}"

    subprocess.run(
        [
            str(_ARF_RT_PYTHON),
            str(_TOOL_PATH),
            "--scenario",
            str(scenario_path),
            "--output-dir",
            str(output_dir),
        ],
        capture_output=True,
        check=True,
        text=True,
        env=env,
    )

    summary = json.loads((output_dir / "serim_arf_rt_first_probe_summary.json").read_text(encoding="utf-8"))

    assert "probe_overlay" not in summary["inputs"]


def test_runtime_summary_reports_probe_overlay_when_supplied_and_loaded(tmp_path: Path) -> None:
    if not _ARF_RT_PYTHON.exists():
        pytest.skip("external arf_rt runtime not present")

    scenario_path = tmp_path / "scenario_with_objective.json"
    _write_runtime_scenario(scenario_path)
    overlay_path = tmp_path / "probe_overlay.json"
    _write_overlay(
        overlay_path,
        [
            _probe(
                "iamscope-edge-runtime-1",
                PROBE_STATE_PROBED_CORRELATED_ALLOWED,
                VALIDATED_STATE_ALLOWED,
            )
        ],
    )
    output_dir = tmp_path / "out"
    env = dict(os.environ)
    env["PYTHONPATH"] = f"{_TOOL_PATH.parents[1]}:{_ARF_RT_REPO}"

    subprocess.run(
        [
            str(_ARF_RT_PYTHON),
            str(_TOOL_PATH),
            "--scenario",
            str(scenario_path),
            "--probe-overlay",
            str(overlay_path),
            "--output-dir",
            str(output_dir),
        ],
        capture_output=True,
        check=True,
        text=True,
        env=env,
    )

    summary = json.loads((output_dir / "serim_arf_rt_first_probe_summary.json").read_text(encoding="utf-8"))

    assert summary["inputs"]["probe_overlay"] == str(overlay_path)


def test_runtime_invalid_probe_overlay_does_not_emit_summary(tmp_path: Path) -> None:
    if not _ARF_RT_PYTHON.exists():
        pytest.skip("external arf_rt runtime not present")

    scenario_path = tmp_path / "scenario_with_objective.json"
    _write_runtime_scenario(scenario_path)
    missing_overlay_path = tmp_path / "missing-probe-overlay.json"
    output_dir = tmp_path / "out"
    env = dict(os.environ)
    env["PYTHONPATH"] = f"{_TOOL_PATH.parents[1]}:{_ARF_RT_REPO}"

    result = subprocess.run(
        [
            str(_ARF_RT_PYTHON),
            str(_TOOL_PATH),
            "--scenario",
            str(scenario_path),
            "--probe-overlay",
            str(missing_overlay_path),
            "--output-dir",
            str(output_dir),
        ],
        capture_output=True,
        check=False,
        text=True,
        env=env,
    )

    assert result.returncode != 0
    assert not (output_dir / "serim_arf_rt_first_probe_summary.json").exists()


def test_runtime_summary_reports_explicit_scenario_and_derived_normalized_path(tmp_path: Path) -> None:
    if not _ARF_RT_PYTHON.exists():
        pytest.skip("external arf_rt runtime not present")

    scenario_path = tmp_path / "scenario_with_objective.json"
    _write_runtime_scenario(scenario_path)
    output_dir = tmp_path / "out"
    env = dict(os.environ)
    env["PYTHONPATH"] = f"{_TOOL_PATH.parents[1]}:{_ARF_RT_REPO}"

    subprocess.run(
        [
            str(_ARF_RT_PYTHON),
            str(_TOOL_PATH),
            "--scenario",
            str(scenario_path),
            "--output-dir",
            str(output_dir),
        ],
        capture_output=True,
        check=True,
        text=True,
        env=env,
    )

    summary = json.loads((output_dir / "serim_arf_rt_first_probe_summary.json").read_text(encoding="utf-8"))

    assert summary["inputs"]["scenario"] == str(scenario_path)
    assert summary["inputs"]["normalized_scenario"] == str(output_dir / "serim_scenario_arf_compat.json")


def test_runtime_summary_reports_defaulted_scenario_from_input_dir(tmp_path: Path) -> None:
    if not _ARF_RT_PYTHON.exists():
        pytest.skip("external arf_rt runtime not present")

    input_dir = tmp_path / "input"
    input_dir.mkdir()
    scenario_path = input_dir / "scenario_with_objective.json"
    _write_runtime_scenario(scenario_path)
    output_dir = tmp_path / "out"
    env = dict(os.environ)
    env["PYTHONPATH"] = f"{_TOOL_PATH.parents[1]}:{_ARF_RT_REPO}"

    subprocess.run(
        [
            str(_ARF_RT_PYTHON),
            str(_TOOL_PATH),
            "--input-dir",
            str(input_dir),
            "--output-dir",
            str(output_dir),
        ],
        capture_output=True,
        check=True,
        text=True,
        env=env,
    )

    summary = json.loads((output_dir / "serim_arf_rt_first_probe_summary.json").read_text(encoding="utf-8"))

    assert summary["inputs"]["scenario"] == str(scenario_path)
    assert summary["inputs"]["normalized_scenario"] == str(output_dir / "serim_scenario_arf_compat.json")


def _write_ambiguous_runtime_scenario(path: Path) -> None:
    scenario = _scenario_with_roles()
    start, target = scenario["nodes"]
    scenario["metadata"] = {"canonical_hash": "scenario-hash"}
    scenario["edges"] = [
        {
            "edge_id": "iamscope-edge-east",
            "edge_type": "sts:AssumeRole_permission",
            "src": start,
            "dst": target,
            "region": "us-east-1",
            "features": {},
            "status": "HYPOTHESIZED",
        },
        {
            "edge_id": "iamscope-edge-west",
            "edge_type": "sts:AssumeRole_permission",
            "src": start,
            "dst": target,
            "region": "us-west-2",
            "features": {},
            "status": "HYPOTHESIZED",
        },
    ]
    scenario["objectives"] = [
        {
            "objective_type": "reachability",
            "start_nodes": [start["provider_id"]],
            "target_nodes": [target["provider_id"]],
            "max_depth": 3,
            "k": 2,
        }
    ]
    path.write_text(json.dumps(scenario), encoding="utf-8")


def test_live_runtime_ambiguous_regionless_overlay_fails_closed(tmp_path: Path) -> None:
    if not _ARF_RT_PYTHON.exists():
        pytest.skip("external arf_rt runtime not present")

    scenario_path = tmp_path / "scenario_with_objective.json"
    _write_ambiguous_runtime_scenario(scenario_path)
    overlay_path = tmp_path / "probe_overlay.json"
    _write_overlay(
        overlay_path,
        [
            _probe(
                "iamscope-edge-east",
                PROBE_STATE_PROBED_CORRELATED_ALLOWED,
                VALIDATED_STATE_ALLOWED,
            ),
            _probe(
                "iamscope-edge-west",
                PROBE_STATE_PROBED_CORRELATED_DENIED,
                VALIDATED_STATE_DENIED,
            ),
        ],
    )
    output_dir = tmp_path / "out"
    env = dict(os.environ)
    env["PYTHONPATH"] = f"{_TOOL_PATH.parents[1]}:{_ARF_RT_REPO}"

    subprocess.run(
        [
            str(_ARF_RT_PYTHON),
            str(_TOOL_PATH),
            "--scenario",
            str(scenario_path),
            "--probe-overlay",
            str(overlay_path),
            "--output-dir",
            str(output_dir),
        ],
        capture_output=True,
        check=True,
        text=True,
        env=env,
    )

    summary = json.loads((output_dir / "serim_arf_rt_first_probe_summary.json").read_text(encoding="utf-8"))

    assert summary["edge_id_mapping"]["regionless_ambiguous_mappings"] == 1
    assert summary["truth_artifacts"]["probe_edges"] == 2
    assert summary["truth_artifacts"]["probe_overlay"] == str(overlay_path)
    for policy_row in summary["policies"].values():
        first_probe = policy_row["first_probe"]
        truth = policy_row["truth"]
        assert first_probe["iamscope_edge_id"] is None
        assert first_probe["edge_id"] == first_probe["arf_edge_id"]
        assert truth["probe_ids"] == []
        assert truth["probe_states"] == []
        assert truth["validated_allow"] is False
        assert truth["validated_deny"] is False
        assert truth["confounded"] is False
