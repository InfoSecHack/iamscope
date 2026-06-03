from __future__ import annotations

import json
from pathlib import Path

from benchmarks.common import load_json
from benchmarks.scoring.scorer import score_case
from benchmarks.scoring.validator import validate_case_manifest

REPO_ROOT = Path(__file__).resolve().parent.parent


def _write_json(path: Path, payload: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload))


def _env07_run_manifest(tmp_path: Path, scenario_doc: dict, findings_doc: dict) -> dict:
    scenario_path = tmp_path / "scenario.json"
    findings_path = tmp_path / "findings.json"
    _write_json(scenario_path, scenario_doc)
    _write_json(findings_path, findings_doc)
    return {
        "manifest_type": "benchmark_run_manifest",
        "schema_version": "0.1",
        "run_id": "env07-test",
        "case_id": "env07_validated_non_admin_reachability",
        "tool_name": "iamscope",
        "git_sha": None,
        "started_at": None,
        "ended_at": None,
        "authority": "fixture",
        "confidence": "high",
        "benchmark_date": "2026-04-24",
        "environment": "acceptance/env07_ar_validated_non_admin",
        "tool_claims": [],
        "context": {
            "source_provider_id": "arn:aws:iam::123456\u003789012:user/iamscope-test/env07-alice",
            "target_provider_id": "arn:aws:iam::123456\u003789012:role/iamscope-test/env07-reader",
        },
        "artifact_status": {
            "scenario_validation": "pass",
            "artifact_retention": "complete",
        },
        "artifacts": {
            "scenario_json": str(scenario_path),
            "findings_json": str(findings_path),
            "run_log": "/tmp/run.log",
            "scenario_validate_txt": "/tmp/scenario_validate.txt",
        },
    }


def test_env07_case_manifest_validates() -> None:
    case_manifest = load_json(REPO_ROOT / "benchmarks/cases/env07_validated_non_admin_reachability.json")
    assert validate_case_manifest(case_manifest) == []


def test_structural_edge_assertion_passes(tmp_path: Path) -> None:
    case_manifest = load_json(REPO_ROOT / "benchmarks/cases/env07_validated_non_admin_reachability.json")
    run_manifest = _env07_run_manifest(
        tmp_path,
        {
            "edges": [
                {
                    "edge_type": "sts:AssumeRole_permission",
                    "src": {"provider_id": "arn:aws:iam::123456\u003789012:user/iamscope-test/env07-alice"},
                    "dst": {"provider_id": "arn:aws:iam::123456\u003789012:role/iamscope-test/env07-reader"},
                },
                {
                    "edge_type": "sts:AssumeRole_trust",
                    "src": {"provider_id": "arn:aws:iam::123456\u003789012:user/iamscope-test/env07-alice"},
                    "dst": {"provider_id": "arn:aws:iam::123456\u003789012:role/iamscope-test/env07-reader"},
                },
            ]
        },
        {"findings": []},
    )
    score_result = score_case(case_manifest, run_manifest, REPO_ROOT)
    assert score_result["passed"] is True
    assert score_result["defects"] == []


def test_missing_structural_edge_emits_semantic_mismatch(tmp_path: Path) -> None:
    case_manifest = load_json(REPO_ROOT / "benchmarks/cases/env07_validated_non_admin_reachability.json")
    run_manifest = _env07_run_manifest(
        tmp_path,
        {
            "edges": [
                {
                    "edge_type": "sts:AssumeRole_permission",
                    "src": {"provider_id": "arn:aws:iam::123456\u003789012:user/iamscope-test/env07-alice"},
                    "dst": {"provider_id": "arn:aws:iam::123456\u003789012:role/iamscope-test/env07-reader"},
                }
            ]
        },
        {"findings": []},
    )
    score_result = score_case(case_manifest, run_manifest, REPO_ROOT)
    assert score_result["passed"] is False
    assert any(defect["defect_class"] == "semantic_mismatch" for defect in score_result["defects"])


def test_env07_structural_plus_false_admin_absence_scores_correctly(tmp_path: Path) -> None:
    case_manifest = load_json(REPO_ROOT / "benchmarks/cases/env07_validated_non_admin_reachability.json")
    run_manifest = _env07_run_manifest(
        tmp_path,
        {
            "edges": [
                {
                    "edge_type": "sts:AssumeRole_permission",
                    "src": {"provider_id": "arn:aws:iam::123456\u003789012:user/iamscope-test/env07-alice"},
                    "dst": {"provider_id": "arn:aws:iam::123456\u003789012:role/iamscope-test/env07-reader"},
                },
                {
                    "edge_type": "sts:AssumeRole_trust",
                    "src": {"provider_id": "arn:aws:iam::123456\u003789012:user/iamscope-test/env07-alice"},
                    "dst": {"provider_id": "arn:aws:iam::123456\u003789012:role/iamscope-test/env07-reader"},
                },
            ]
        },
        {
            "findings": [
                {
                    "pattern_id": "s3_bucket_takeover",
                    "verdict": "inconclusive",
                    "source": {"provider_id": "arn:aws:iam::123456\u003789012:user/other"},
                    "target": {"provider_id": "arn:aws:s3:::example"},
                    "blockers_observed": [],
                    "required_checks": [],
                }
            ]
        },
    )
    score_result = score_case(case_manifest, run_manifest, REPO_ROOT)
    assert score_result["passed"] is True
    assert score_result["defects"] == []


def _env08_run_manifest(tmp_path: Path, scenario_doc: dict, findings_doc: dict) -> dict:
    scenario_path = tmp_path / "env08-scenario.json"
    findings_path = tmp_path / "env08-findings.json"
    _write_json(scenario_path, scenario_doc)
    _write_json(findings_path, findings_doc)
    return {
        "manifest_type": "benchmark_run_manifest",
        "schema_version": "0.1",
        "run_id": "env08-test",
        "case_id": "env08_trust_condition_blocked_admin",
        "tool_name": "iamscope",
        "git_sha": None,
        "started_at": None,
        "ended_at": None,
        "authority": "fixture",
        "confidence": "high",
        "benchmark_date": "2026-04-24",
        "environment": "acceptance/env08_trust_condition_blocked_admin",
        "tool_claims": [],
        "context": {
            "source_provider_id": "arn:aws:iam::123456\u003789012:user/iamscope-test/env08-alice",
            "target_provider_id": "arn:aws:iam::123456\u003789012:role/iamscope-test/env08-conditioned-admin",
        },
        "artifact_status": {
            "scenario_validation": "pass",
            "artifact_retention": "complete",
        },
        "artifacts": {
            "scenario_json": str(scenario_path),
            "findings_json": str(findings_path),
            "run_log": "/tmp/run.log",
            "scenario_validate_txt": "/tmp/scenario_validate.txt",
        },
    }


def test_env08_case_manifest_validates() -> None:
    case_manifest = load_json(REPO_ROOT / "benchmarks/cases/env08_trust_condition_blocked_admin.json")
    assert validate_case_manifest(case_manifest) == []


def test_scenario_constraint_count_passes(tmp_path: Path) -> None:
    case_manifest = load_json(REPO_ROOT / "benchmarks/cases/env08_trust_condition_blocked_admin.json")
    run_manifest = _env08_run_manifest(
        tmp_path,
        {
            "edges": [],
            "constraints": [
                {
                    "constraint_id": "c1",
                    "constraint_type": "TRUST_CONDITION",
                    "properties": {
                        "condition_keys": ["aws:MultiFactorAuthPresent"],
                    },
                }
            ],
            "edge_constraints": [],
        },
        {
            "findings": [
                {
                    "pattern_id": "admin_reachability",
                    "verdict": "inconclusive",
                    "source": {"provider_id": "arn:aws:iam::123456\u003789012:user/iamscope-test/env08-alice"},
                    "target": {
                        "provider_id": "arn:aws:iam::123456\u003789012:role/iamscope-test/env08-conditioned-admin"
                    },
                    "blockers_observed": [],
                    "required_checks": [],
                }
            ]
        },
    )
    result = score_case(case_manifest, run_manifest, REPO_ROOT)
    constraint_result = next(
        item for item in result["assertion_results"] if item["type"] == "scenario_constraint_count"
    )
    assert constraint_result["passed"] is True
    assert constraint_result["actual_value"] == 1


def test_scenario_constraint_count_failure_emits_semantic_mismatch(tmp_path: Path) -> None:
    case_manifest = load_json(REPO_ROOT / "benchmarks/cases/env08_trust_condition_blocked_admin.json")
    run_manifest = _env08_run_manifest(
        tmp_path,
        {"edges": [], "constraints": [], "edge_constraints": []},
        {
            "findings": [
                {
                    "pattern_id": "admin_reachability",
                    "verdict": "inconclusive",
                    "source": {"provider_id": "arn:aws:iam::123456\u003789012:user/iamscope-test/env08-alice"},
                    "target": {
                        "provider_id": "arn:aws:iam::123456\u003789012:role/iamscope-test/env08-conditioned-admin"
                    },
                    "blockers_observed": [],
                    "required_checks": [],
                }
            ]
        },
    )
    result = score_case(case_manifest, run_manifest, REPO_ROOT)
    assert result["passed"] is False
    assert any(defect["defect_class"] == "semantic_mismatch" for defect in result["defects"])


def test_scenario_edge_constraint_count_passes(tmp_path: Path) -> None:
    case_manifest = load_json(REPO_ROOT / "benchmarks/cases/env08_trust_condition_blocked_admin.json")
    run_manifest = _env08_run_manifest(
        tmp_path,
        {
            "edges": [
                {
                    "edge_id": "e1",
                    "edge_type": "sts:AssumeRole_permission",
                    "src": {"provider_id": "arn:aws:iam::123456\u003789012:user/iamscope-test/env08-alice"},
                    "dst": {"provider_id": "arn:aws:iam::123456\u003789012:role/iamscope-test/env08-conditioned-admin"},
                },
                {
                    "edge_id": "e2",
                    "edge_type": "sts:AssumeRole_trust",
                    "src": {"provider_id": "arn:aws:iam::123456\u003789012:user/iamscope-test/env08-alice"},
                    "dst": {"provider_id": "arn:aws:iam::123456\u003789012:role/iamscope-test/env08-conditioned-admin"},
                },
            ],
            "constraints": [
                {
                    "constraint_id": "c1",
                    "constraint_type": "TRUST_CONDITION",
                    "properties": {
                        "condition_keys": ["aws:MultiFactorAuthPresent"],
                    },
                }
            ],
            "edge_constraints": [{"edge_id": "e2", "constraint_id": "c1"}],
        },
        {
            "findings": [
                {
                    "pattern_id": "admin_reachability",
                    "verdict": "inconclusive",
                    "source": {"provider_id": "arn:aws:iam::123456\u003789012:user/iamscope-test/env08-alice"},
                    "target": {
                        "provider_id": "arn:aws:iam::123456\u003789012:role/iamscope-test/env08-conditioned-admin"
                    },
                    "blockers_observed": [],
                    "required_checks": [],
                }
            ]
        },
    )
    result = score_case(case_manifest, run_manifest, REPO_ROOT)
    binding_result = next(
        item for item in result["assertion_results"] if item["type"] == "scenario_edge_constraint_count"
    )
    assert binding_result["passed"] is True
    assert binding_result["actual_value"] == 1


def test_env08_structural_and_finding_assertions_score_correctly(tmp_path: Path) -> None:
    case_manifest = load_json(REPO_ROOT / "benchmarks/cases/env08_trust_condition_blocked_admin.json")
    run_manifest = _env08_run_manifest(
        tmp_path,
        {
            "edges": [
                {
                    "edge_id": "e1",
                    "edge_type": "sts:AssumeRole_permission",
                    "src": {"provider_id": "arn:aws:iam::123456\u003789012:user/iamscope-test/env08-alice"},
                    "dst": {"provider_id": "arn:aws:iam::123456\u003789012:role/iamscope-test/env08-conditioned-admin"},
                },
                {
                    "edge_id": "e2",
                    "edge_type": "sts:AssumeRole_trust",
                    "src": {"provider_id": "arn:aws:iam::123456\u003789012:user/iamscope-test/env08-alice"},
                    "dst": {"provider_id": "arn:aws:iam::123456\u003789012:role/iamscope-test/env08-conditioned-admin"},
                },
            ],
            "constraints": [
                {
                    "constraint_id": "c1",
                    "constraint_type": "TRUST_CONDITION",
                    "properties": {
                        "condition_keys": ["aws:MultiFactorAuthPresent"],
                        "raw_conditions": {"Bool": {"aws:MultiFactorAuthPresent": "true"}},
                    },
                }
            ],
            "edge_constraints": [{"edge_id": "e2", "constraint_id": "c1"}],
        },
        {
            "findings": [
                {
                    "pattern_id": "admin_reachability",
                    "verdict": "inconclusive",
                    "source": {"provider_id": "arn:aws:iam::123456\u003789012:user/iamscope-test/env08-alice"},
                    "target": {
                        "provider_id": "arn:aws:iam::123456\u003789012:role/iamscope-test/env08-conditioned-admin"
                    },
                    "blockers_observed": [],
                    "required_checks": [],
                }
            ]
        },
    )
    result = score_case(case_manifest, run_manifest, REPO_ROOT)
    assert result["passed"] is True
    assert result["defects"] == []


def _env14_run_manifest(tmp_path: Path, scenario_doc: dict, findings_doc: dict) -> dict:
    scenario_path = tmp_path / "env14-scenario.json"
    findings_path = tmp_path / "env14-findings.json"
    _write_json(scenario_path, scenario_doc)
    _write_json(findings_path, findings_doc)
    return {
        "manifest_type": "benchmark_run_manifest",
        "schema_version": "0.1",
        "run_id": "env14-test",
        "case_id": "env14_permission_condition_blocked_admin",
        "tool_name": "iamscope",
        "git_sha": None,
        "started_at": None,
        "ended_at": None,
        "authority": "fixture",
        "confidence": "high",
        "benchmark_date": "2026-04-28",
        "environment": "acceptance/env14_permission_condition_blocked_admin",
        "tool_claims": [],
        "context": {
            "source_provider_id": "arn:aws:iam::123456\u003789012:user/iamscope-test/env14-alice",
            "target_provider_id": "arn:aws:iam::123456\u003789012:role/iamscope-test/env14-admin",
        },
        "artifact_status": {
            "scenario_validation": "pass",
            "artifact_retention": "complete",
        },
        "artifacts": {
            "scenario_json": str(scenario_path),
            "findings_json": str(findings_path),
            "run_log": "/tmp/run.log",
            "scenario_validate_txt": "/tmp/scenario_validate.txt",
        },
    }


def test_env14_conditioned_permission_edge_scores_correctly(tmp_path: Path) -> None:
    case_manifest = load_json(REPO_ROOT / "benchmarks/cases/env14_permission_condition_blocked_admin.json")
    run_manifest = _env14_run_manifest(
        tmp_path,
        {
            "edges": [
                {
                    "edge_id": "e1",
                    "edge_type": "sts:AssumeRole_permission",
                    "src": {"provider_id": "arn:aws:iam::123456\u003789012:user/iamscope-test/env14-alice"},
                    "dst": {"provider_id": "arn:aws:iam::123456\u003789012:role/iamscope-test/env14-admin"},
                    "features": {
                        "has_conditions": True,
                        "raw_conditions": {"Bool": {"aws:MultiFactorAuthPresent": "true"}},
                    },
                },
                {
                    "edge_id": "e2",
                    "edge_type": "sts:AssumeRole_trust",
                    "src": {"provider_id": "arn:aws:iam::123456\u003789012:user/iamscope-test/env14-alice"},
                    "dst": {"provider_id": "arn:aws:iam::123456\u003789012:role/iamscope-test/env14-admin"},
                    "features": {"has_conditions": False, "raw_conditions": {}},
                },
            ],
            "constraints": [],
            "edge_constraints": [],
        },
        {
            "findings": [
                {
                    "pattern_id": "admin_reachability",
                    "verdict": "inconclusive",
                    "source": {"provider_id": "arn:aws:iam::123456\u003789012:user/iamscope-test/env14-alice"},
                    "target": {"provider_id": "arn:aws:iam::123456\u003789012:role/iamscope-test/env14-admin"},
                    "blockers_observed": [],
                    "required_checks": [],
                }
            ]
        },
    )
    result = score_case(case_manifest, run_manifest, REPO_ROOT)
    assert result["passed"] is True
    assert result["defects"] == []


def test_env14_missing_permission_condition_evidence_fails(tmp_path: Path) -> None:
    case_manifest = load_json(REPO_ROOT / "benchmarks/cases/env14_permission_condition_blocked_admin.json")
    run_manifest = _env14_run_manifest(
        tmp_path,
        {
            "edges": [
                {
                    "edge_id": "e1",
                    "edge_type": "sts:AssumeRole_permission",
                    "src": {"provider_id": "arn:aws:iam::123456\u003789012:user/iamscope-test/env14-alice"},
                    "dst": {"provider_id": "arn:aws:iam::123456\u003789012:role/iamscope-test/env14-admin"},
                    "features": {"has_conditions": False, "raw_conditions": {}},
                },
                {
                    "edge_id": "e2",
                    "edge_type": "sts:AssumeRole_trust",
                    "src": {"provider_id": "arn:aws:iam::123456\u003789012:user/iamscope-test/env14-alice"},
                    "dst": {"provider_id": "arn:aws:iam::123456\u003789012:role/iamscope-test/env14-admin"},
                    "features": {"has_conditions": False, "raw_conditions": {}},
                },
            ],
            "constraints": [],
            "edge_constraints": [],
        },
        {
            "findings": [
                {
                    "pattern_id": "admin_reachability",
                    "verdict": "inconclusive",
                    "source": {"provider_id": "arn:aws:iam::123456\u003789012:user/iamscope-test/env14-alice"},
                    "target": {"provider_id": "arn:aws:iam::123456\u003789012:role/iamscope-test/env14-admin"},
                    "blockers_observed": [],
                    "required_checks": [],
                }
            ]
        },
    )
    result = score_case(case_manifest, run_manifest, REPO_ROOT)
    assert result["passed"] is False
    assert any(defect["defect_class"] == "semantic_mismatch" for defect in result["defects"])


def _env15_run_manifest(tmp_path: Path, scenario_doc: dict, findings_doc: dict) -> dict:
    scenario_path = tmp_path / "env15-scenario.json"
    findings_path = tmp_path / "env15-findings.json"
    _write_json(scenario_path, scenario_doc)
    _write_json(findings_path, findings_doc)
    return {
        "manifest_type": "benchmark_run_manifest",
        "schema_version": "0.1",
        "run_id": "env15-test",
        "case_id": "env15_permission_condition_removed_validated_admin",
        "tool_name": "iamscope",
        "git_sha": None,
        "started_at": None,
        "ended_at": None,
        "authority": "fixture",
        "confidence": "high",
        "benchmark_date": "2026-04-28",
        "environment": "acceptance/env15_env14_permission_condition_removed",
        "tool_claims": [],
        "context": {
            "source_provider_id": "arn:aws:iam::123456\u003789012:user/iamscope-test/env15-alice",
            "target_provider_id": "arn:aws:iam::123456\u003789012:role/iamscope-test/env15-admin",
        },
        "artifact_status": {
            "scenario_validation": "pass",
            "artifact_retention": "complete",
        },
        "artifacts": {
            "scenario_json": str(scenario_path),
            "findings_json": str(findings_path),
            "run_log": "/tmp/run.log",
            "scenario_validate_txt": "/tmp/scenario_validate.txt",
        },
    }


def test_env15_unconditioned_permission_mutation_scores_correctly(tmp_path: Path) -> None:
    case_manifest = load_json(REPO_ROOT / "benchmarks/cases/env15_permission_condition_removed_validated_admin.json")
    run_manifest = _env15_run_manifest(
        tmp_path,
        {
            "edges": [
                {
                    "edge_id": "e1",
                    "edge_type": "sts:AssumeRole_permission",
                    "src": {"provider_id": "arn:aws:iam::123456\u003789012:user/iamscope-test/env15-alice"},
                    "dst": {"provider_id": "arn:aws:iam::123456\u003789012:role/iamscope-test/env15-admin"},
                    "features": {"has_conditions": False, "raw_conditions": {}},
                },
                {
                    "edge_id": "e2",
                    "edge_type": "sts:AssumeRole_trust",
                    "src": {"provider_id": "arn:aws:iam::123456\u003789012:user/iamscope-test/env15-alice"},
                    "dst": {"provider_id": "arn:aws:iam::123456\u003789012:role/iamscope-test/env15-admin"},
                    "features": {"has_conditions": False, "raw_conditions": {}},
                },
            ],
            "constraints": [],
            "edge_constraints": [],
        },
        {
            "findings": [
                {
                    "pattern_id": "admin_reachability",
                    "verdict": "validated",
                    "source": {"provider_id": "arn:aws:iam::123456\u003789012:user/iamscope-test/env15-alice"},
                    "target": {"provider_id": "arn:aws:iam::123456\u003789012:role/iamscope-test/env15-admin"},
                    "blockers_observed": [],
                    "required_checks": [],
                }
            ]
        },
    )
    result = score_case(case_manifest, run_manifest, REPO_ROOT)
    assert result["passed"] is True
    assert result["defects"] == []


def test_env15_conditioned_permission_mutation_fails(tmp_path: Path) -> None:
    case_manifest = load_json(REPO_ROOT / "benchmarks/cases/env15_permission_condition_removed_validated_admin.json")
    run_manifest = _env15_run_manifest(
        tmp_path,
        {
            "edges": [
                {
                    "edge_id": "e1",
                    "edge_type": "sts:AssumeRole_permission",
                    "src": {"provider_id": "arn:aws:iam::123456\u003789012:user/iamscope-test/env15-alice"},
                    "dst": {"provider_id": "arn:aws:iam::123456\u003789012:role/iamscope-test/env15-admin"},
                    "features": {
                        "has_conditions": True,
                        "raw_conditions": {"Bool": {"aws:MultiFactorAuthPresent": "true"}},
                    },
                },
                {
                    "edge_id": "e2",
                    "edge_type": "sts:AssumeRole_trust",
                    "src": {"provider_id": "arn:aws:iam::123456\u003789012:user/iamscope-test/env15-alice"},
                    "dst": {"provider_id": "arn:aws:iam::123456\u003789012:role/iamscope-test/env15-admin"},
                    "features": {"has_conditions": False, "raw_conditions": {}},
                },
            ],
            "constraints": [],
            "edge_constraints": [],
        },
        {
            "findings": [
                {
                    "pattern_id": "admin_reachability",
                    "verdict": "validated",
                    "source": {"provider_id": "arn:aws:iam::123456\u003789012:user/iamscope-test/env15-alice"},
                    "target": {"provider_id": "arn:aws:iam::123456\u003789012:role/iamscope-test/env15-admin"},
                    "blockers_observed": [],
                    "required_checks": [],
                }
            ]
        },
    )
    result = score_case(case_manifest, run_manifest, REPO_ROOT)
    assert result["passed"] is False
    assert any(defect["defect_class"] == "semantic_mismatch" for defect in result["defects"])


def _env24_run_manifest(tmp_path: Path, scenario_doc: dict, findings_doc: dict) -> dict:
    scenario_path = tmp_path / "env24-scenario.json"
    findings_path = tmp_path / "env24-findings.json"
    _write_json(scenario_path, scenario_doc)
    _write_json(findings_path, findings_doc)
    return {
        "manifest_type": "benchmark_run_manifest",
        "schema_version": "0.1",
        "run_id": "env24-test",
        "case_id": "env24_s3_resource_policy_allow",
        "tool_name": "iamscope",
        "git_sha": None,
        "started_at": None,
        "ended_at": None,
        "authority": "fixture",
        "confidence": "high",
        "benchmark_date": "2026-05-07",
        "environment": "acceptance/env24_s3_resource_policy_allow",
        "tool_claims": [],
        "context": {
            "source_provider_id": "arn:aws:iam::123456\u003789012:user/iamscope-test/env24-reader",
            "target_provider_id": "arn:aws:s3:::env24-rp-allow-123456\u003789012-deadbeef",
        },
        "artifact_status": {
            "scenario_validation": "pass",
            "artifact_retention": "complete",
        },
        "artifacts": {
            "scenario_json": str(scenario_path),
            "findings_json": str(findings_path),
            "run_log": "/tmp/run.log",
            "scenario_validate_txt": "/tmp/scenario_validate.txt",
        },
    }


def test_env24_resource_policy_allow_edge_scores_correctly(tmp_path: Path) -> None:
    case_manifest = load_json(REPO_ROOT / "benchmarks/cases/env24_s3_resource_policy_allow.json")
    run_manifest = _env24_run_manifest(
        tmp_path,
        {
            "nodes": [
                {
                    "node_type": "IAMUser",
                    "provider_id": "arn:aws:iam::123456\u003789012:user/iamscope-test/env24-reader",
                },
                {
                    "node_type": "S3Bucket",
                    "provider_id": "arn:aws:s3:::env24-rp-allow-123456\u003789012-deadbeef",
                },
            ],
            "edges": [
                {
                    "edge_type": "s3:GetObject_resource_policy",
                    "src": {"provider_id": "arn:aws:iam::123456\u003789012:user/iamscope-test/env24-reader"},
                    "dst": {"provider_id": "arn:aws:s3:::env24-rp-allow-123456\u003789012-deadbeef"},
                    "features": {
                        "permission_source": "resource_policy",
                        "layer": "resource_policy",
                        "has_conditions": False,
                    },
                }
            ],
            "constraints": [],
            "edge_constraints": [],
        },
        {"findings": []},
    )
    result = score_case(case_manifest, run_manifest, REPO_ROOT)
    assert result["passed"] is True
    assert result["defects"] == []


def test_env24_resource_policy_allow_edge_requires_provenance(tmp_path: Path) -> None:
    case_manifest = load_json(REPO_ROOT / "benchmarks/cases/env24_s3_resource_policy_allow.json")
    run_manifest = _env24_run_manifest(
        tmp_path,
        {
            "nodes": [
                {
                    "node_type": "IAMUser",
                    "provider_id": "arn:aws:iam::123456\u003789012:user/iamscope-test/env24-reader",
                },
                {
                    "node_type": "S3Bucket",
                    "provider_id": "arn:aws:s3:::env24-rp-allow-123456\u003789012-deadbeef",
                },
            ],
            "edges": [
                {
                    "edge_type": "s3:GetObject_resource_policy",
                    "src": {"provider_id": "arn:aws:iam::123456\u003789012:user/iamscope-test/env24-reader"},
                    "dst": {"provider_id": "arn:aws:s3:::env24-rp-allow-123456\u003789012-deadbeef"},
                    "features": {
                        "permission_source": "identity_policy",
                        "layer": "resource_policy",
                        "has_conditions": False,
                    },
                }
            ],
            "constraints": [],
            "edge_constraints": [],
        },
        {"findings": []},
    )
    result = score_case(case_manifest, run_manifest, REPO_ROOT)
    assert result["passed"] is False
    assert any(defect["defect_class"] == "semantic_mismatch" for defect in result["defects"])


def _env25_run_manifest(tmp_path: Path, scenario_doc: dict, findings_doc: dict) -> dict:
    scenario_path = tmp_path / "env25-scenario.json"
    findings_path = tmp_path / "env25-findings.json"
    _write_json(scenario_path, scenario_doc)
    _write_json(findings_path, findings_doc)
    return {
        "manifest_type": "benchmark_run_manifest",
        "schema_version": "0.1",
        "run_id": "env25-test",
        "case_id": "env25_s3_resource_policy_allow_scoped_away_nonvalidated",
        "tool_name": "iamscope",
        "git_sha": None,
        "started_at": None,
        "ended_at": None,
        "authority": "fixture",
        "confidence": "high",
        "benchmark_date": "2026-05-08",
        "environment": "acceptance/env25_env24_resource_policy_allow_scoped_away",
        "tool_claims": [],
        "context": {
            "source_provider_id": "arn:aws:iam::123456\u003789012:user/iamscope-test/env25-reader",
            "decoy_provider_id": "arn:aws:iam::123456\u003789012:user/iamscope-test/env25-decoy",
            "target_provider_id": "arn:aws:s3:::env25-rp-scoped-away-123456\u003789012-deadbeef",
        },
        "artifact_status": {
            "scenario_validation": "pass",
            "artifact_retention": "complete",
        },
        "artifacts": {
            "scenario_json": str(scenario_path),
            "findings_json": str(findings_path),
            "run_log": "/tmp/run.log",
            "scenario_validate_txt": "/tmp/scenario_validate.txt",
        },
    }


def test_env25_scoped_away_resource_policy_allow_edge_scores_correctly(tmp_path: Path) -> None:
    case_manifest = load_json(
        REPO_ROOT / "benchmarks/cases/env25_s3_resource_policy_allow_scoped_away_nonvalidated.json"
    )
    run_manifest = _env25_run_manifest(
        tmp_path,
        {
            "nodes": [
                {
                    "node_type": "IAMUser",
                    "provider_id": "arn:aws:iam::123456\u003789012:user/iamscope-test/env25-reader",
                },
                {
                    "node_type": "IAMUser",
                    "provider_id": "arn:aws:iam::123456\u003789012:user/iamscope-test/env25-decoy",
                },
                {
                    "node_type": "S3Bucket",
                    "provider_id": "arn:aws:s3:::env25-rp-scoped-away-123456\u003789012-deadbeef",
                },
            ],
            "edges": [
                {
                    "edge_type": "s3:GetObject_resource_policy",
                    "src": {"provider_id": "arn:aws:iam::123456\u003789012:user/iamscope-test/env25-decoy"},
                    "dst": {"provider_id": "arn:aws:s3:::env25-rp-scoped-away-123456\u003789012-deadbeef"},
                    "features": {
                        "permission_source": "resource_policy",
                        "layer": "resource_policy",
                        "has_conditions": False,
                    },
                }
            ],
            "constraints": [],
            "edge_constraints": [],
        },
        {"findings": []},
    )
    result = score_case(case_manifest, run_manifest, REPO_ROOT)
    assert result["passed"] is True
    assert result["defects"] == []


def test_env25_scoped_away_resource_policy_allow_rejects_reader_edge(tmp_path: Path) -> None:
    case_manifest = load_json(
        REPO_ROOT / "benchmarks/cases/env25_s3_resource_policy_allow_scoped_away_nonvalidated.json"
    )
    run_manifest = _env25_run_manifest(
        tmp_path,
        {
            "nodes": [
                {
                    "node_type": "IAMUser",
                    "provider_id": "arn:aws:iam::123456\u003789012:user/iamscope-test/env25-reader",
                },
                {
                    "node_type": "IAMUser",
                    "provider_id": "arn:aws:iam::123456\u003789012:user/iamscope-test/env25-decoy",
                },
                {
                    "node_type": "S3Bucket",
                    "provider_id": "arn:aws:s3:::env25-rp-scoped-away-123456\u003789012-deadbeef",
                },
            ],
            "edges": [
                {
                    "edge_type": "s3:GetObject_resource_policy",
                    "src": {"provider_id": "arn:aws:iam::123456\u003789012:user/iamscope-test/env25-decoy"},
                    "dst": {"provider_id": "arn:aws:s3:::env25-rp-scoped-away-123456\u003789012-deadbeef"},
                    "features": {
                        "permission_source": "resource_policy",
                        "layer": "resource_policy",
                        "has_conditions": False,
                    },
                },
                {
                    "edge_type": "s3:GetObject_resource_policy",
                    "src": {"provider_id": "arn:aws:iam::123456\u003789012:user/iamscope-test/env25-reader"},
                    "dst": {"provider_id": "arn:aws:s3:::env25-rp-scoped-away-123456\u003789012-deadbeef"},
                    "features": {
                        "permission_source": "resource_policy",
                        "layer": "resource_policy",
                        "has_conditions": False,
                    },
                },
            ],
            "constraints": [],
            "edge_constraints": [],
        },
        {"findings": []},
    )
    result = score_case(case_manifest, run_manifest, REPO_ROOT)
    assert result["passed"] is False
    assert any(
        defect["assertion_id"] == "reader_s3_getobject_resource_policy_edge_absent"
        and defect["defect_class"] == "semantic_mismatch"
        for defect in result["defects"]
    )
