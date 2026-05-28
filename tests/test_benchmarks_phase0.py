from __future__ import annotations

import json
from pathlib import Path

from benchmarks.common import load_json
from benchmarks.reporting.render import render
from benchmarks.scoring.gates import evaluate_gates
from benchmarks.scoring.scorer import score_case
from benchmarks.scoring.validator import (
    validate_case_manifest,
    validate_gate_manifest,
    validate_run_manifest,
)

REPO_ROOT = Path(__file__).resolve().parent.parent


def _write_json(path: Path, payload: dict) -> None:
    path.write_text(json.dumps(payload))


def _minimal_benchmark_artifacts(tmp_path: Path, run_manifest: dict, findings_doc: dict) -> dict:
    artifact_dir = tmp_path / run_manifest["case_id"]
    artifact_dir.mkdir()
    scenario_path = artifact_dir / "scenario.json"
    findings_path = artifact_dir / "findings.json"
    binding_metadata_path = artifact_dir / "binding_metadata.json"
    run_log_path = artifact_dir / "run.log"
    scenario_validate_path = artifact_dir / "scenario_validate.txt"

    _write_json(scenario_path, {"edges": [], "constraints": [], "edge_constraints": []})
    _write_json(findings_path, findings_doc)
    _write_json(binding_metadata_path, {"edge_constraints": []})
    run_log_path.write_text("synthetic benchmark test fixture\n")
    scenario_validate_path.write_text("scenario validation passed\n")

    mutated_run = dict(run_manifest)
    mutated_run["artifacts"] = {
        **run_manifest["artifacts"],
        "scenario_json": str(scenario_path),
        "findings_json": str(findings_path),
        "binding_metadata_json": str(binding_metadata_path),
        "run_log": str(run_log_path),
        "scenario_validate_txt": str(scenario_validate_path),
    }
    return mutated_run


def _env03_findings(run_manifest: dict) -> dict:
    return {
        "findings": [
            {
                "pattern_id": "iam_group_membership_escalation",
                "verdict": "blocked",
                "source": {"provider_id": run_manifest["context"]["source_provider_id"]},
                "target": {"provider_id": run_manifest["context"]["target_provider_id"]},
                "blockers_observed": [
                    {
                        "kind": "identity_deny",
                        "constraint_id": "test-identity-deny-constraint",
                        "edge_id": "test-add-user-to-group-edge",
                    }
                ],
                "required_checks": [
                    {
                        "name": "no_identity_deny_blocks_add_user_to_group",
                        "state": "fail",
                    }
                ],
            }
        ]
    }


def _env05_findings(run_manifest: dict) -> dict:
    source = {"provider_id": run_manifest["context"]["source_provider_id"]}
    target = {"provider_id": run_manifest["context"]["target_provider_id"]}
    return {
        "findings": [
            {
                "pattern_id": "assume_role_chain",
                "verdict": "blocked",
                "source": source,
                "target": target,
                "blockers_observed": [],
                "required_checks": [],
            },
            {
                "pattern_id": "admin_reachability",
                "verdict": "blocked",
                "source": source,
                "target": target,
                "blockers_observed": [],
                "required_checks": [],
            },
        ]
    }


def _env03_run_with_artifacts(tmp_path: Path) -> dict:
    run_manifest = load_json(REPO_ROOT / "benchmarks/samples/env03_live_sample_run.json")
    return _minimal_benchmark_artifacts(tmp_path, run_manifest, _env03_findings(run_manifest))


def _env05_run_with_artifacts(tmp_path: Path) -> dict:
    run_manifest = load_json(REPO_ROOT / "benchmarks/samples/env05_live_sample_run.json")
    return _minimal_benchmark_artifacts(tmp_path, run_manifest, _env05_findings(run_manifest))


def test_sample_case_manifest_validates() -> None:
    case_manifest = load_json(REPO_ROOT / "benchmarks/cases/env03_identity_deny_group_escalation.json")
    assert validate_case_manifest(case_manifest) == []


def test_env07_case_manifest_validates_from_phase0_suite() -> None:
    case_manifest = load_json(REPO_ROOT / "benchmarks/cases/env07_validated_non_admin_reachability.json")
    assert validate_case_manifest(case_manifest) == []


def test_env08_case_manifest_validates_from_phase0_suite() -> None:
    case_manifest = load_json(REPO_ROOT / "benchmarks/cases/env08_trust_condition_blocked_admin.json")
    assert validate_case_manifest(case_manifest) == []


def test_env09_case_manifest_validates_from_phase0_suite() -> None:
    case_manifest = load_json(REPO_ROOT / "benchmarks/cases/env09_boundary_removed_validated_admin.json")
    assert validate_case_manifest(case_manifest) == []


def test_env10_case_manifest_validates_from_phase0_suite() -> None:
    case_manifest = load_json(REPO_ROOT / "benchmarks/cases/env10_trust_condition_removed_validated_admin.json")
    assert validate_case_manifest(case_manifest) == []


def test_env11_case_manifest_validates_from_phase0_suite() -> None:
    case_manifest = load_json(REPO_ROOT / "benchmarks/cases/env11_broad_trust_condition_blocked_admin.json")
    assert validate_case_manifest(case_manifest) == []


def test_env12_case_manifest_validates_from_phase0_suite() -> None:
    case_manifest = load_json(REPO_ROOT / "benchmarks/cases/env12_scp_blocked_assumerole.json")
    assert validate_case_manifest(case_manifest) == []


def test_env14_case_manifest_validates_from_phase0_suite() -> None:
    case_manifest = load_json(REPO_ROOT / "benchmarks/cases/env14_permission_condition_blocked_admin.json")
    assert validate_case_manifest(case_manifest) == []


def test_env18_case_manifest_validates_from_phase0_suite() -> None:
    case_manifest = load_json(REPO_ROOT / "benchmarks/cases/env18_lambda_passrole_validated.json")
    assert validate_case_manifest(case_manifest) == []


def test_env19_case_manifest_validates_from_phase0_suite() -> None:
    case_manifest = load_json(REPO_ROOT / "benchmarks/cases/env19_passedtoservice_scoped_away_nonvalidated.json")
    assert validate_case_manifest(case_manifest) == []


def test_env20_case_manifest_validates_from_phase0_suite() -> None:
    case_manifest = load_json(REPO_ROOT / "benchmarks/cases/env20_ecs_passrole_validated.json")
    assert validate_case_manifest(case_manifest) == []


def test_env21_case_manifest_validates_from_phase0_suite() -> None:
    case_manifest = load_json(REPO_ROOT / "benchmarks/cases/env21_ecs_passedtoservice_scoped_away_nonvalidated.json")
    assert validate_case_manifest(case_manifest) == []


def test_env22_case_manifest_validates_from_phase0_suite() -> None:
    case_manifest = load_json(REPO_ROOT / "benchmarks/cases/env22_cross_account_validated_admin.json")
    assert validate_case_manifest(case_manifest) == []


def test_env23_case_manifest_validates_from_phase0_suite() -> None:
    case_manifest = load_json(REPO_ROOT / "benchmarks/cases/env23_cross_account_trust_scoped_away_nonvalidated.json")
    assert validate_case_manifest(case_manifest) == []


def test_env24_case_manifest_validates_from_phase0_suite() -> None:
    case_manifest = load_json(REPO_ROOT / "benchmarks/cases/env24_s3_resource_policy_allow.json")
    assert validate_case_manifest(case_manifest) == []


def test_env25_case_manifest_validates_from_phase0_suite() -> None:
    case_manifest = load_json(
        REPO_ROOT / "benchmarks/cases/env25_s3_resource_policy_allow_scoped_away_nonvalidated.json"
    )
    assert validate_case_manifest(case_manifest) == []


def test_env26_case_manifest_validates_from_phase0_suite() -> None:
    case_manifest = load_json(REPO_ROOT / "benchmarks/cases/env26_multihop_chain_validated_admin.json")
    assert validate_case_manifest(case_manifest) == []


def test_env27_case_manifest_validates_from_phase0_suite() -> None:
    case_manifest = load_json(REPO_ROOT / "benchmarks/cases/env27_multihop_trust_scoped_away_nonvalidated.json")
    assert validate_case_manifest(case_manifest) == []


def test_env22_runner_exports_project_root_pythonpath_before_iamscope_invocations() -> None:
    """Env22 temp-copy runs must import this checkout, not a stale installed package."""
    export_line = 'export PYTHONPATH="$PROJECT_ROOT${PYTHONPATH:+:$PYTHONPATH}"'
    run_script = (REPO_ROOT / "acceptance/env22_cross_account_validated/run.sh").read_text()
    wrapper_script = (REPO_ROOT / "scripts/run_env22_cross_account_benchmark.sh").read_text()

    assert export_line in run_script
    assert run_script.index(export_line) < run_script.index('cd "$SCRIPT_DIR"')
    assert run_script.index(export_line) < run_script.index("iamscope collect")

    assert export_line in wrapper_script
    assert wrapper_script.index(export_line) < wrapper_script.index('bash "$WORK_DIR/run.sh"')
    assert wrapper_script.index(export_line) < wrapper_script.index("iamscope validate")


def test_env23_runner_exports_project_root_pythonpath_before_iamscope_invocations() -> None:
    """Env23 temp-copy runs must import this checkout, not a stale installed package."""
    export_line = 'export PYTHONPATH="$PROJECT_ROOT${PYTHONPATH:+:$PYTHONPATH}"'
    run_script = (REPO_ROOT / "acceptance/env23_env22_trust_scoped_away/run.sh").read_text()
    wrapper_script = (REPO_ROOT / "scripts/run_env23_cross_account_trust_scoped_away_benchmark.sh").read_text()

    assert export_line in run_script
    assert run_script.index(export_line) < run_script.index('cd "$SCRIPT_DIR"')
    assert run_script.index(export_line) < run_script.index("iamscope collect")

    assert export_line in wrapper_script
    assert wrapper_script.index(export_line) < wrapper_script.index('bash "$WORK_DIR/run.sh"')
    assert wrapper_script.index(export_line) < wrapper_script.index("iamscope validate")


def test_env24_runner_exports_project_root_pythonpath_before_iamscope_invocations() -> None:
    """Env24 temp-copy runs must import this checkout, not a stale installed package."""
    export_line = 'export PYTHONPATH="$PROJECT_ROOT${PYTHONPATH:+:$PYTHONPATH}"'
    run_script = (REPO_ROOT / "acceptance/env24_s3_resource_policy_allow/run.sh").read_text()
    wrapper_script = (REPO_ROOT / "scripts/run_env24_s3_resource_policy_allow_benchmark.sh").read_text()

    assert export_line in run_script
    assert run_script.index(export_line) < run_script.index('cd "$SCRIPT_DIR"')
    assert run_script.index(export_line) < run_script.index("iamscope collect")

    assert export_line in wrapper_script
    assert wrapper_script.index(export_line) < wrapper_script.index('bash "$WORK_DIR/run.sh"')
    assert wrapper_script.index(export_line) < wrapper_script.index("iamscope validate")


def test_env25_runner_exports_project_root_pythonpath_before_iamscope_invocations() -> None:
    """Env25 temp-copy runs must import this checkout, not a stale installed package."""
    export_line = 'export PYTHONPATH="$PROJECT_ROOT${PYTHONPATH:+:$PYTHONPATH}"'
    run_script = (REPO_ROOT / "acceptance/env25_env24_resource_policy_allow_scoped_away/run.sh").read_text()
    wrapper_script = (REPO_ROOT / "scripts/run_env25_s3_resource_policy_allow_scoped_away_benchmark.sh").read_text()

    assert export_line in run_script
    assert run_script.index(export_line) < run_script.index('cd "$SCRIPT_DIR"')
    assert run_script.index(export_line) < run_script.index("iamscope collect")

    assert export_line in wrapper_script
    assert wrapper_script.index(export_line) < wrapper_script.index('bash "$WORK_DIR/run.sh"')
    assert wrapper_script.index(export_line) < wrapper_script.index("iamscope validate")


def test_env26_runner_exports_project_root_pythonpath_before_iamscope_invocations() -> None:
    """Env26 temp-copy runs must import this checkout, not a stale installed package."""
    export_line = 'export PYTHONPATH="$PROJECT_ROOT${PYTHONPATH:+:$PYTHONPATH}"'
    run_script = (REPO_ROOT / "acceptance/env26_multihop_chain_validated/run.sh").read_text()
    wrapper_script = (REPO_ROOT / "scripts/run_env26_multihop_chain_benchmark.sh").read_text()

    assert export_line in run_script
    assert run_script.index(export_line) < run_script.index('cd "$SCRIPT_DIR"')
    assert run_script.index(export_line) < run_script.index("iamscope collect")

    assert export_line in wrapper_script
    assert wrapper_script.index(export_line) < wrapper_script.index('bash "$WORK_DIR/run.sh"')
    assert wrapper_script.index(export_line) < wrapper_script.index("iamscope validate")


def test_env27_runner_exports_project_root_pythonpath_before_iamscope_invocations() -> None:
    """Env27 temp-copy runs must import this checkout, not a stale installed package."""
    export_line = 'export PYTHONPATH="$PROJECT_ROOT${PYTHONPATH:+:$PYTHONPATH}"'
    run_script = (REPO_ROOT / "acceptance/env27_env26_multihop_trust_scoped_away/run.sh").read_text()
    wrapper_script = (REPO_ROOT / "scripts/run_env27_multihop_trust_scoped_away_benchmark.sh").read_text()

    assert export_line in run_script
    assert run_script.index(export_line) < run_script.index('cd "$SCRIPT_DIR"')
    assert run_script.index(export_line) < run_script.index("iamscope collect")

    assert export_line in wrapper_script
    assert wrapper_script.index(export_line) < wrapper_script.index('bash "$WORK_DIR/run.sh"')
    assert wrapper_script.index(export_line) < wrapper_script.index("iamscope validate")


def test_sample_run_manifest_validates() -> None:
    run_manifest = load_json(REPO_ROOT / "benchmarks/samples/env03_live_sample_run.json")
    assert validate_run_manifest(run_manifest) == []


def test_env03_semantic_assertions_score_correctly(tmp_path: Path) -> None:
    case_manifest = load_json(REPO_ROOT / "benchmarks/cases/env03_identity_deny_group_escalation.json")
    run_manifest = _env03_run_with_artifacts(tmp_path)
    score_result = score_case(case_manifest, run_manifest, REPO_ROOT)
    assert score_result["passed"] is True
    assert score_result["defects"] == []


def test_env05_semantic_assertions_score_correctly(tmp_path: Path) -> None:
    case_manifest = load_json(REPO_ROOT / "benchmarks/cases/env05_permission_boundary_blocked_chain.json")
    run_manifest = _env05_run_with_artifacts(tmp_path)
    score_result = score_case(case_manifest, run_manifest, REPO_ROOT)
    assert score_result["passed"] is True
    assert score_result["defects"] == []


def test_false_admin_claim_fails_gate(tmp_path: Path) -> None:
    case_manifest = load_json(REPO_ROOT / "benchmarks/cases/env05_permission_boundary_blocked_chain.json")
    base_run_manifest = load_json(REPO_ROOT / "benchmarks/samples/env05_live_sample_run.json")
    findings_doc = _env05_findings(base_run_manifest)
    findings_doc["findings"].append(
        {
            "pattern_id": "admin_reachability",
            "verdict": "validated",
            "source": {"provider_id": base_run_manifest["context"]["source_provider_id"]},
            "target": {"provider_id": base_run_manifest["context"]["target_provider_id"]},
            "blockers_observed": [],
            "required_checks": [],
        }
    )
    run_manifest = _minimal_benchmark_artifacts(tmp_path, base_run_manifest, findings_doc)
    score_result = score_case(case_manifest, run_manifest, REPO_ROOT)
    gate_manifest = load_json(REPO_ROOT / "benchmarks/scoring/promotion_gates_phase0.json")
    gate_result = evaluate_gates(case_manifest, run_manifest, score_result, gate_manifest, REPO_ROOT)
    assert any(defect["defect_class"] == "false_admin_claim" for defect in gate_result["defects"])
    false_admin_gate = next(gate for gate in gate_result["gate_results"] if gate["gate_id"] == "false_admin_claim")
    assert false_admin_gate["status"] == "block"


def test_dry_run_report_renders(tmp_path: Path) -> None:
    case_path = REPO_ROOT / "benchmarks/cases/env03_identity_deny_group_escalation.json"
    gates_path = REPO_ROOT / "benchmarks/scoring/promotion_gates_phase0.json"
    run_manifest = _env03_run_with_artifacts(tmp_path)
    run_path = tmp_path / "env03_test_run_manifest.json"
    output_path = tmp_path / "test_render_output.md"
    _write_json(run_path, run_manifest)
    report = render(case_path, run_path, gates_path, output_path=output_path, repo_root=REPO_ROOT)
    assert "## Directly Proven" in report
    assert "## Gate Results" in report
    assert output_path.exists()


def test_gate_manifest_validates() -> None:
    gate_manifest = load_json(REPO_ROOT / "benchmarks/scoring/promotion_gates_phase0.json")
    assert validate_gate_manifest(gate_manifest) == []
