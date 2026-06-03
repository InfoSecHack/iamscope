from __future__ import annotations

import json
from pathlib import Path

from benchmarks.common import load_json
from benchmarks.reporting.evaluate import evaluate_archive
from benchmarks.reporting.render import build_report
from benchmarks.scoring.gates import evaluate_gates
from benchmarks.scoring.scorer import score_case
from benchmarks.scoring.validator import validate_case_manifest, validate_run_manifest

REPO_ROOT = Path(__file__).resolve().parent.parent
DEG01_CASE_ID = "deg01_missing_trust_edge"
DEG02_CASE_ID = "deg02_missing_permission_edge"
DEG03_CASE_ID = "deg03_missing_blocker_evidence"
DEG04_CASE_ID = "deg04_missing_edge_constraints"
DEG05_CASE_ID = "deg05_malformed_policy_parse"
DEG06_CASE_ID = "deg06_partial_account_collection"
DEG07_CASE_ID = "deg07_missing_required_artifacts"
DEG01_ALICE_ARN = "arn:aws:iam::123456\u003789012:user/iamscope-test/deg01-alice"
DEG01_ADMIN_ARN = "arn:aws:iam::123456\u003789012:role/iamscope-test/deg01-admin"
DEG02_ALICE_ARN = "arn:aws:iam::123456\u003789012:user/iamscope-test/deg02-alice"
DEG02_ADMIN_ARN = "arn:aws:iam::123456\u003789012:role/iamscope-test/deg02-admin"
DEG03_ALICE_ARN = "arn:aws:iam::123456\u003789012:user/iamscope-test/deg03-alice"
DEG03_ADMINS_ARN = "arn:aws:iam::123456\u003789012:group/iamscope-test/deg03-admins"
DEG04_ALICE_ARN = "arn:aws:iam::123456\u003789012:user/iamscope-test/deg04-alice"
DEG04_ADMIN_ARN = "arn:aws:iam::123456\u003789012:role/iamscope-test/deg04-admin"
DEG05_ALICE_ARN = "arn:aws:iam::123456\u003789012:user/iamscope-test/deg05-alice"
DEG05_ADMIN_ARN = "arn:aws:iam::123456\u003789012:role/iamscope-test/deg05-admin"
DEG06_CALLER_ACCOUNT_ID = "111122\u003223333"
DEG06_TARGET_ACCOUNT_ID = "444455\u003556666"
DEG06_ALICE_ARN = f"arn:aws:iam::{DEG06_CALLER_ACCOUNT_ID}:user/iamscope-test/deg06-alice"
DEG06_ADMIN_ARN = f"arn:aws:iam::{DEG06_TARGET_ACCOUNT_ID}:role/iamscope-test/deg06-admin"


def _write_json(path: Path, payload: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload))


def _make_deg07_archive(
    tmp_path: Path,
    name: str,
    *,
    include_scenario: bool,
    include_findings: bool,
) -> Path:
    archive_dir = tmp_path / name
    collect_dir = archive_dir / "collect"
    collect_dir.mkdir(parents=True)
    run_log = "\n".join(
        [
            "Resources deployed:",
            "  alice_arn : arn:aws:iam::123456\u003789012:user/iamscope-test/deg07-alice",
            "  admin_arn : arn:aws:iam::123456\u003789012:role/iamscope-test/deg07-admin",
            "  account_id : 123456\u003789012",
            "scenario validation: PASS",
            "benchmark semantic assertion: SKIP (degradation fixture)",
        ]
    )
    (archive_dir / "run.log").write_text(run_log + "\n")
    (archive_dir / "scenario_validate.txt").write_text("Validation PASSED - synthetic degradation fixture.\n")
    if include_scenario:
        _write_json(
            collect_dir / "scenario.json", {"nodes": [], "edges": [], "constraints": [], "edge_constraints": []}
        )
    if include_findings:
        _write_json(collect_dir / "findings.json", {"findings": []})
    return archive_dir


def _case_manifest() -> dict:
    return load_json(REPO_ROOT / f"benchmarks/cases/{DEG07_CASE_ID}.json")


def _deg01_case_manifest() -> dict:
    return load_json(REPO_ROOT / f"benchmarks/cases/{DEG01_CASE_ID}.json")


def _deg02_case_manifest() -> dict:
    return load_json(REPO_ROOT / f"benchmarks/cases/{DEG02_CASE_ID}.json")


def _deg03_case_manifest() -> dict:
    return load_json(REPO_ROOT / f"benchmarks/cases/{DEG03_CASE_ID}.json")


def _deg04_case_manifest() -> dict:
    return load_json(REPO_ROOT / f"benchmarks/cases/{DEG04_CASE_ID}.json")


def _deg05_case_manifest() -> dict:
    return load_json(REPO_ROOT / f"benchmarks/cases/{DEG05_CASE_ID}.json")


def _deg06_case_manifest() -> dict:
    return load_json(REPO_ROOT / f"benchmarks/cases/{DEG06_CASE_ID}.json")


def _gate_manifest() -> dict:
    return load_json(REPO_ROOT / "benchmarks/scoring/promotion_gates_phase0.json")


def test_deg07_case_manifest_validates() -> None:
    assert validate_case_manifest(_case_manifest()) == []


def test_deg01_case_manifest_validates() -> None:
    assert validate_case_manifest(_deg01_case_manifest()) == []


def test_deg02_case_manifest_validates() -> None:
    assert validate_case_manifest(_deg02_case_manifest()) == []


def test_deg03_case_manifest_validates() -> None:
    assert validate_case_manifest(_deg03_case_manifest()) == []


def test_deg04_case_manifest_validates() -> None:
    assert validate_case_manifest(_deg04_case_manifest()) == []


def test_deg05_case_manifest_validates() -> None:
    assert validate_case_manifest(_deg05_case_manifest()) == []


def test_deg06_case_manifest_validates() -> None:
    assert validate_case_manifest(_deg06_case_manifest()) == []


def test_missing_findings_artifact_blocks_promotion_and_reports_defect(tmp_path: Path) -> None:
    archive_dir = _make_deg07_archive(
        tmp_path,
        "iamscope-benchmark-deg07-20260430T000001Z",
        include_scenario=True,
        include_findings=False,
    )
    out_dir = tmp_path / "missing-findings-evaluation"

    result = evaluate_archive(DEG07_CASE_ID, archive_dir, out_dir, REPO_ROOT)

    gate_result = load_json(out_dir / "gate_result.json")
    scorer_result = load_json(out_dir / "scorer_result.json")
    report = (out_dir / "report.md").read_text()
    assert result["success"] is False
    assert scorer_result["passed"] is False
    assert scorer_result["assertion_results"] == []
    assert gate_result["artifact_sufficient"] is False
    assert gate_result["promotion_blocked"] is True
    assert gate_result["human_review_required"] is True
    assert any(defect["defect_class"] == "artifact_insufficient" for defect in gate_result["defects"])
    assert any("findings_json" in defect["message"] for defect in gate_result["defects"])
    assert "Artifact sufficient: `no`" in report
    assert "`artifact_insufficient` - artifact path does not exist for findings_json" in report
    assert "`artifact_sufficient`: `block`" in report
    assert "composite_score" not in report


def test_missing_scenario_and_findings_artifacts_block_promotion(tmp_path: Path) -> None:
    archive_dir = _make_deg07_archive(
        tmp_path,
        "iamscope-benchmark-deg07-20260430T000002Z",
        include_scenario=False,
        include_findings=False,
    )
    out_dir = tmp_path / "missing-both-evaluation"

    evaluate_archive(DEG07_CASE_ID, archive_dir, out_dir, REPO_ROOT)

    gate_result = load_json(out_dir / "gate_result.json")
    messages = [defect["message"] for defect in gate_result["defects"]]
    assert gate_result["artifact_sufficient"] is False
    assert gate_result["promotion_blocked"] is True
    assert any("scenario_json" in message for message in messages)
    assert any("findings_json" in message for message in messages)


def test_missing_artifact_key_is_explicit_artifact_insufficient() -> None:
    run_manifest = {
        "manifest_type": "benchmark_run_manifest",
        "schema_version": "0.1",
        "run_id": "deg07-missing-key",
        "case_id": DEG07_CASE_ID,
        "tool_name": "iamscope",
        "git_sha": None,
        "started_at": None,
        "ended_at": None,
        "authority": "fixture",
        "confidence": "high",
        "benchmark_date": "2026-04-30",
        "environment": "synthetic/deg07_missing_required_artifacts",
        "tool_claims": [],
        "context": {
            "source_provider_id": "arn:aws:iam::123456\u003789012:user/iamscope-test/deg07-alice",
            "target_provider_id": "arn:aws:iam::123456\u003789012:role/iamscope-test/deg07-admin",
        },
        "artifact_status": {
            "scenario_validation": "pass",
            "artifact_retention": "incomplete",
        },
        "artifacts": {"scenario_json": "synthetic/scenario.json"},
    }
    score_result = {
        "case_id": DEG07_CASE_ID,
        "run_id": "deg07-missing-key",
        "passed": False,
        "assertion_results": [],
        "defects": [],
    }

    assert validate_run_manifest(run_manifest) == []
    gate_result = evaluate_gates(_case_manifest(), run_manifest, score_result, _gate_manifest(), REPO_ROOT)
    report = build_report(_case_manifest(), run_manifest, score_result, gate_result)

    assert gate_result["artifact_sufficient"] is False
    assert gate_result["promotion_blocked"] is True
    assert gate_result["human_review_required"] is True
    assert any(defect["message"] == "missing artifact path for findings_json" for defect in gate_result["defects"])
    assert "`artifact_insufficient` - missing artifact path for findings_json" in report


def _deg01_run_manifest(tmp_path: Path, scenario_doc: dict, findings_doc: dict) -> dict:
    scenario_path = tmp_path / "deg01-scenario.json"
    findings_path = tmp_path / "deg01-findings.json"
    _write_json(scenario_path, scenario_doc)
    _write_json(findings_path, findings_doc)
    return {
        "manifest_type": "benchmark_run_manifest",
        "schema_version": "0.1",
        "run_id": "deg01-missing-trust-synthetic",
        "case_id": DEG01_CASE_ID,
        "tool_name": "iamscope",
        "git_sha": None,
        "started_at": None,
        "ended_at": None,
        "authority": "synthetic",
        "confidence": "high",
        "benchmark_date": "2026-04-30",
        "environment": "synthetic/deg01_missing_trust_edge",
        "tool_claims": [],
        "context": {
            "source_provider_id": DEG01_ALICE_ARN,
            "target_provider_id": DEG01_ADMIN_ARN,
        },
        "artifact_status": {
            "scenario_validation": "pass",
            "artifact_retention": "complete",
        },
        "artifacts": {
            "scenario_json": str(scenario_path),
            "findings_json": str(findings_path),
        },
    }


def _deg01_missing_trust_scenario() -> dict:
    return {
        "nodes": [
            {
                "node_type": "IAMUser",
                "provider_id": DEG01_ALICE_ARN,
                "name": "deg01-alice",
            },
            {
                "node_type": "IAMRole",
                "provider_id": DEG01_ADMIN_ARN,
                "name": "deg01-admin",
                "features": {"admin_equivalent": True},
            },
        ],
        "edges": [
            {
                "edge_id": "deg01-permission-edge",
                "edge_type": "sts:AssumeRole_permission",
                "src": {"provider_id": DEG01_ALICE_ARN},
                "dst": {"provider_id": DEG01_ADMIN_ARN},
            }
        ],
        "constraints": [],
        "edge_constraints": [],
    }


def test_deg01_missing_trust_edge_is_artifact_sufficient_and_not_validated(tmp_path: Path) -> None:
    case_manifest = _deg01_case_manifest()
    run_manifest = _deg01_run_manifest(
        tmp_path,
        _deg01_missing_trust_scenario(),
        {"findings": []},
    )

    assert validate_run_manifest(run_manifest) == []
    score_result = score_case(case_manifest, run_manifest, REPO_ROOT)
    gate_result = evaluate_gates(case_manifest, run_manifest, score_result, _gate_manifest(), REPO_ROOT)
    report = build_report(case_manifest, run_manifest, score_result, gate_result)

    assert score_result["passed"] is True
    assert score_result["defects"] == []
    assert {result["assertion_id"]: result["actual_value"] for result in score_result["assertion_results"]} == {
        "assumerole_permission_edge_present": 1,
        "assumerole_trust_edge_absent": 0,
        "validated_admin_absent": 0,
    }
    assert gate_result["artifact_sufficient"] is True
    assert gate_result["promotion_blocked"] is False
    assert gate_result["human_review_required"] is True
    assert "The degraded fixture is missing the required matching AssumeRole trust evidence." in report
    assert "Broader missing-trust behavior outside this exact synthetic fixture remains only implied." in report
    assert "composite_score" not in report


def test_deg01_false_validated_admin_claim_blocks_promotion(tmp_path: Path) -> None:
    case_manifest = _deg01_case_manifest()
    run_manifest = _deg01_run_manifest(
        tmp_path,
        _deg01_missing_trust_scenario(),
        {
            "findings": [
                {
                    "pattern_id": "admin_reachability",
                    "verdict": "validated",
                    "source": {"provider_id": DEG01_ALICE_ARN},
                    "target": {"provider_id": DEG01_ADMIN_ARN},
                    "blockers_observed": [],
                    "required_checks": [],
                }
            ]
        },
    )

    score_result = score_case(case_manifest, run_manifest, REPO_ROOT)
    gate_result = evaluate_gates(case_manifest, run_manifest, score_result, _gate_manifest(), REPO_ROOT)
    report = build_report(case_manifest, run_manifest, score_result, gate_result)

    assert score_result["passed"] is False
    assert any(defect["defect_class"] == "false_admin_claim" for defect in score_result["defects"])
    assert gate_result["artifact_sufficient"] is True
    assert gate_result["promotion_blocked"] is True
    assert gate_result["human_review_required"] is True
    assert any(defect["defect_class"] == "false_admin_claim" for defect in gate_result["defects"])
    assert "`false_admin_claim` - assertion validated_admin_absent failed" in report


def test_deg01_unexpected_trust_edge_blocks_promotion_as_semantic_mismatch(tmp_path: Path) -> None:
    case_manifest = _deg01_case_manifest()
    scenario_doc = _deg01_missing_trust_scenario()
    scenario_doc["edges"].append(
        {
            "edge_id": "deg01-unexpected-trust-edge",
            "edge_type": "sts:AssumeRole_trust",
            "src": {"provider_id": DEG01_ALICE_ARN},
            "dst": {"provider_id": DEG01_ADMIN_ARN},
        }
    )
    run_manifest = _deg01_run_manifest(
        tmp_path,
        scenario_doc,
        {"findings": []},
    )

    score_result = score_case(case_manifest, run_manifest, REPO_ROOT)
    gate_result = evaluate_gates(case_manifest, run_manifest, score_result, _gate_manifest(), REPO_ROOT)
    report = build_report(case_manifest, run_manifest, score_result, gate_result)

    assert score_result["passed"] is False
    assert any(defect["defect_class"] == "semantic_mismatch" for defect in score_result["defects"])
    assert gate_result["artifact_sufficient"] is True
    assert gate_result["promotion_blocked"] is True
    assert gate_result["human_review_required"] is True
    assert any(defect["defect_class"] == "semantic_mismatch" for defect in gate_result["defects"])
    assert "`semantic_mismatch` - assertion assumerole_trust_edge_absent failed" in report


def _deg02_run_manifest(tmp_path: Path, scenario_doc: dict, findings_doc: dict) -> dict:
    scenario_path = tmp_path / "deg02-scenario.json"
    findings_path = tmp_path / "deg02-findings.json"
    _write_json(scenario_path, scenario_doc)
    _write_json(findings_path, findings_doc)
    return {
        "manifest_type": "benchmark_run_manifest",
        "schema_version": "0.1",
        "run_id": "deg02-missing-permission-synthetic",
        "case_id": DEG02_CASE_ID,
        "tool_name": "iamscope",
        "git_sha": None,
        "started_at": None,
        "ended_at": None,
        "authority": "synthetic",
        "confidence": "high",
        "benchmark_date": "2026-04-30",
        "environment": "synthetic/deg02_missing_permission_edge",
        "tool_claims": [],
        "context": {
            "source_provider_id": DEG02_ALICE_ARN,
            "target_provider_id": DEG02_ADMIN_ARN,
        },
        "artifact_status": {
            "scenario_validation": "pass",
            "artifact_retention": "complete",
        },
        "artifacts": {
            "scenario_json": str(scenario_path),
            "findings_json": str(findings_path),
        },
    }


def _deg02_missing_permission_scenario() -> dict:
    return {
        "nodes": [
            {
                "node_type": "IAMUser",
                "provider_id": DEG02_ALICE_ARN,
                "name": "deg02-alice",
            },
            {
                "node_type": "IAMRole",
                "provider_id": DEG02_ADMIN_ARN,
                "name": "deg02-admin",
                "features": {"admin_equivalent": True},
            },
        ],
        "edges": [
            {
                "edge_id": "deg02-trust-edge",
                "edge_type": "sts:AssumeRole_trust",
                "src": {"provider_id": DEG02_ALICE_ARN},
                "dst": {"provider_id": DEG02_ADMIN_ARN},
            }
        ],
        "constraints": [],
        "edge_constraints": [],
    }


def test_deg02_missing_permission_edge_is_artifact_sufficient_and_not_validated(tmp_path: Path) -> None:
    case_manifest = _deg02_case_manifest()
    run_manifest = _deg02_run_manifest(
        tmp_path,
        _deg02_missing_permission_scenario(),
        {"findings": []},
    )

    assert validate_run_manifest(run_manifest) == []
    score_result = score_case(case_manifest, run_manifest, REPO_ROOT)
    gate_result = evaluate_gates(case_manifest, run_manifest, score_result, _gate_manifest(), REPO_ROOT)
    report = build_report(case_manifest, run_manifest, score_result, gate_result)

    assert score_result["passed"] is True
    assert score_result["defects"] == []
    assert {result["assertion_id"]: result["actual_value"] for result in score_result["assertion_results"]} == {
        "assumerole_trust_edge_present": 1,
        "assumerole_permission_edge_absent": 0,
        "validated_admin_absent": 0,
    }
    assert gate_result["artifact_sufficient"] is True
    assert gate_result["promotion_blocked"] is False
    assert gate_result["human_review_required"] is True
    assert "The degraded fixture is missing the required caller-side AssumeRole permission evidence." in report
    assert "Broader missing-permission behavior outside this exact synthetic fixture remains only implied." in report
    assert "composite_score" not in report


def test_deg02_false_validated_admin_claim_blocks_promotion(tmp_path: Path) -> None:
    case_manifest = _deg02_case_manifest()
    run_manifest = _deg02_run_manifest(
        tmp_path,
        _deg02_missing_permission_scenario(),
        {
            "findings": [
                {
                    "pattern_id": "admin_reachability",
                    "verdict": "validated",
                    "source": {"provider_id": DEG02_ALICE_ARN},
                    "target": {"provider_id": DEG02_ADMIN_ARN},
                    "blockers_observed": [],
                    "required_checks": [],
                }
            ]
        },
    )

    score_result = score_case(case_manifest, run_manifest, REPO_ROOT)
    gate_result = evaluate_gates(case_manifest, run_manifest, score_result, _gate_manifest(), REPO_ROOT)
    report = build_report(case_manifest, run_manifest, score_result, gate_result)

    assert score_result["passed"] is False
    assert any(defect["defect_class"] == "false_admin_claim" for defect in score_result["defects"])
    assert gate_result["artifact_sufficient"] is True
    assert gate_result["promotion_blocked"] is True
    assert gate_result["human_review_required"] is True
    assert any(defect["defect_class"] == "false_admin_claim" for defect in gate_result["defects"])
    assert "`false_admin_claim` - assertion validated_admin_absent failed" in report


def test_deg02_unexpected_permission_edge_blocks_promotion_as_semantic_mismatch(tmp_path: Path) -> None:
    case_manifest = _deg02_case_manifest()
    scenario_doc = _deg02_missing_permission_scenario()
    scenario_doc["edges"].append(
        {
            "edge_id": "deg02-unexpected-permission-edge",
            "edge_type": "sts:AssumeRole_permission",
            "src": {"provider_id": DEG02_ALICE_ARN},
            "dst": {"provider_id": DEG02_ADMIN_ARN},
        }
    )
    run_manifest = _deg02_run_manifest(
        tmp_path,
        scenario_doc,
        {"findings": []},
    )

    score_result = score_case(case_manifest, run_manifest, REPO_ROOT)
    gate_result = evaluate_gates(case_manifest, run_manifest, score_result, _gate_manifest(), REPO_ROOT)
    report = build_report(case_manifest, run_manifest, score_result, gate_result)

    assert score_result["passed"] is False
    assert any(defect["defect_class"] == "semantic_mismatch" for defect in score_result["defects"])
    assert gate_result["artifact_sufficient"] is True
    assert gate_result["promotion_blocked"] is True
    assert gate_result["human_review_required"] is True
    assert any(defect["defect_class"] == "semantic_mismatch" for defect in gate_result["defects"])
    assert "`semantic_mismatch` - assertion assumerole_permission_edge_absent failed" in report


def _deg03_run_manifest(tmp_path: Path, scenario_doc: dict, findings_doc: dict) -> dict:
    scenario_path = tmp_path / "deg03-scenario.json"
    findings_path = tmp_path / "deg03-findings.json"
    _write_json(scenario_path, scenario_doc)
    _write_json(findings_path, findings_doc)
    return {
        "manifest_type": "benchmark_run_manifest",
        "schema_version": "0.1",
        "run_id": "deg03-missing-blocker-synthetic",
        "case_id": DEG03_CASE_ID,
        "tool_name": "iamscope",
        "git_sha": None,
        "started_at": None,
        "ended_at": None,
        "authority": "synthetic",
        "confidence": "high",
        "benchmark_date": "2026-04-30",
        "environment": "synthetic/deg03_missing_blocker_evidence",
        "tool_claims": [],
        "context": {
            "source_provider_id": DEG03_ALICE_ARN,
            "target_provider_id": DEG03_ADMINS_ARN,
        },
        "artifact_status": {
            "scenario_validation": "pass",
            "artifact_retention": "complete",
        },
        "artifacts": {
            "scenario_json": str(scenario_path),
            "findings_json": str(findings_path),
        },
    }


def _deg03_group_path_scenario() -> dict:
    return {
        "nodes": [
            {
                "node_type": "IAMUser",
                "provider_id": DEG03_ALICE_ARN,
                "name": "deg03-alice",
            },
            {
                "node_type": "IAMGroup",
                "provider_id": DEG03_ADMINS_ARN,
                "name": "deg03-admins",
                "features": {"admin_equivalent": True},
            },
        ],
        "edges": [
            {
                "edge_id": "deg03-add-user-to-group-edge",
                "edge_type": "iam:AddUserToGroup_permission",
                "src": {"provider_id": DEG03_ALICE_ARN},
                "dst": {"provider_id": DEG03_ADMINS_ARN},
            }
        ],
        "constraints": [],
        "edge_constraints": [],
    }


def _deg03_finding(verdict: str, *, blockers: list[dict] | None = None, checks: list[dict] | None = None) -> dict:
    return {
        "pattern_id": "iam_group_membership_escalation",
        "verdict": verdict,
        "source": {"provider_id": DEG03_ALICE_ARN},
        "target": {"provider_id": DEG03_ADMINS_ARN},
        "blockers_observed": blockers or [],
        "required_checks": checks or [],
    }


def _deg03_missing_blocker_findings() -> dict:
    return {
        "findings": [
            _deg03_finding(
                "blocked",
                checks=[
                    {
                        "name": "source_has_add_user_to_group_permission",
                        "state": "pass",
                    }
                ],
            )
        ]
    }


def test_deg03_missing_blocker_evidence_is_artifact_sufficient_but_blocks_promotion(tmp_path: Path) -> None:
    case_manifest = _deg03_case_manifest()
    run_manifest = _deg03_run_manifest(
        tmp_path,
        _deg03_group_path_scenario(),
        _deg03_missing_blocker_findings(),
    )

    assert validate_run_manifest(run_manifest) == []
    score_result = score_case(case_manifest, run_manifest, REPO_ROOT)
    gate_result = evaluate_gates(case_manifest, run_manifest, score_result, _gate_manifest(), REPO_ROOT)
    report = build_report(case_manifest, run_manifest, score_result, gate_result)

    actual_by_id = {result["assertion_id"]: result["actual_value"] for result in score_result["assertion_results"]}
    assert actual_by_id == {
        "add_user_to_group_permission_edge_present": 1,
        "blocked_group_escalation_present": 1,
        "identity_deny_blocker_present": 0,
        "identity_deny_check_failed": 0,
        "validated_group_escalation_absent": 0,
    }
    assert score_result["passed"] is False
    assert any(
        defect["assertion_id"] == "identity_deny_blocker_present" and defect["defect_class"] == "semantic_mismatch"
        for defect in score_result["defects"]
    )
    assert any(
        defect["assertion_id"] == "identity_deny_check_failed" and defect["defect_class"] == "semantic_mismatch"
        for defect in score_result["defects"]
    )
    assert gate_result["artifact_sufficient"] is True
    assert gate_result["promotion_blocked"] is True
    assert gate_result["human_review_required"] is True
    assert "`semantic_mismatch` - assertion identity_deny_blocker_present failed" in report
    assert "`semantic_mismatch` - assertion identity_deny_check_failed failed" in report
    assert "composite_score" not in report


def test_deg03_false_validated_group_escalation_blocks_promotion(tmp_path: Path) -> None:
    case_manifest = _deg03_case_manifest()
    findings_doc = _deg03_missing_blocker_findings()
    findings_doc["findings"].append(_deg03_finding("validated"))
    run_manifest = _deg03_run_manifest(
        tmp_path,
        _deg03_group_path_scenario(),
        findings_doc,
    )

    score_result = score_case(case_manifest, run_manifest, REPO_ROOT)
    gate_result = evaluate_gates(case_manifest, run_manifest, score_result, _gate_manifest(), REPO_ROOT)
    report = build_report(case_manifest, run_manifest, score_result, gate_result)

    assert score_result["passed"] is False
    assert any(defect["defect_class"] == "false_admin_claim" for defect in score_result["defects"])
    assert gate_result["artifact_sufficient"] is True
    assert gate_result["promotion_blocked"] is True
    assert gate_result["human_review_required"] is True
    assert any(defect["defect_class"] == "false_admin_claim" for defect in gate_result["defects"])
    assert "`false_admin_claim` - assertion validated_group_escalation_absent failed" in report


def test_deg03_clean_missing_blocker_case_blocks_promotion_as_semantic_mismatch(tmp_path: Path) -> None:
    case_manifest = _deg03_case_manifest()
    run_manifest = _deg03_run_manifest(
        tmp_path,
        _deg03_group_path_scenario(),
        {"findings": []},
    )

    score_result = score_case(case_manifest, run_manifest, REPO_ROOT)
    gate_result = evaluate_gates(case_manifest, run_manifest, score_result, _gate_manifest(), REPO_ROOT)
    report = build_report(case_manifest, run_manifest, score_result, gate_result)

    assert score_result["passed"] is False
    assert any(
        defect["assertion_id"] == "blocked_group_escalation_present" and defect["defect_class"] == "semantic_mismatch"
        for defect in score_result["defects"]
    )
    assert gate_result["artifact_sufficient"] is True
    assert gate_result["promotion_blocked"] is True
    assert gate_result["human_review_required"] is True
    assert "`semantic_mismatch` - assertion blocked_group_escalation_present failed" in report


def _deg04_run_manifest(tmp_path: Path, scenario_doc: dict, findings_doc: dict) -> dict:
    scenario_path = tmp_path / "deg04-scenario.json"
    findings_path = tmp_path / "deg04-findings.json"
    _write_json(scenario_path, scenario_doc)
    _write_json(findings_path, findings_doc)
    return {
        "manifest_type": "benchmark_run_manifest",
        "schema_version": "0.1",
        "run_id": "deg04-missing-edge-constraints-synthetic",
        "case_id": DEG04_CASE_ID,
        "tool_name": "iamscope",
        "git_sha": None,
        "started_at": None,
        "ended_at": None,
        "authority": "synthetic",
        "confidence": "high",
        "benchmark_date": "2026-04-30",
        "environment": "synthetic/deg04_missing_edge_constraints",
        "tool_claims": [],
        "context": {
            "source_provider_id": DEG04_ALICE_ARN,
            "target_provider_id": DEG04_ADMIN_ARN,
        },
        "artifact_status": {
            "scenario_validation": "pass",
            "artifact_retention": "complete",
        },
        "artifacts": {
            "scenario_json": str(scenario_path),
            "findings_json": str(findings_path),
        },
    }


def _deg04_condition_stripped_scenario() -> dict:
    return {
        "nodes": [
            {
                "node_type": "IAMUser",
                "provider_id": DEG04_ALICE_ARN,
                "name": "deg04-alice",
            },
            {
                "node_type": "IAMRole",
                "provider_id": DEG04_ADMIN_ARN,
                "name": "deg04-admin",
                "features": {"admin_equivalent": True},
            },
        ],
        "edges": [
            {
                "edge_id": "deg04-permission-edge",
                "edge_type": "sts:AssumeRole_permission",
                "src": {"provider_id": DEG04_ALICE_ARN},
                "dst": {"provider_id": DEG04_ADMIN_ARN},
                "features": {
                    "has_conditions": False,
                    "raw_conditions": {},
                },
            },
            {
                "edge_id": "deg04-trust-edge",
                "edge_type": "sts:AssumeRole_trust",
                "src": {"provider_id": DEG04_ALICE_ARN},
                "dst": {"provider_id": DEG04_ADMIN_ARN},
            },
        ],
        "constraints": [],
        "edge_constraints": [],
    }


def _deg04_conditioned_scenario() -> dict:
    scenario_doc = _deg04_condition_stripped_scenario()
    scenario_doc["edges"][0]["features"] = {
        "has_conditions": True,
        "raw_conditions": {
            "Bool": {
                "aws:MultiFactorAuthPresent": "true",
            }
        },
    }
    return scenario_doc


def _deg04_admin_finding(verdict: str) -> dict:
    return {
        "pattern_id": "admin_reachability",
        "verdict": verdict,
        "source": {"provider_id": DEG04_ALICE_ARN},
        "target": {"provider_id": DEG04_ADMIN_ARN},
        "blockers_observed": [],
        "required_checks": [],
    }


def test_deg04_missing_condition_evidence_is_artifact_sufficient_but_blocks_promotion(tmp_path: Path) -> None:
    case_manifest = _deg04_case_manifest()
    run_manifest = _deg04_run_manifest(
        tmp_path,
        _deg04_condition_stripped_scenario(),
        {"findings": []},
    )

    assert validate_run_manifest(run_manifest) == []
    score_result = score_case(case_manifest, run_manifest, REPO_ROOT)
    gate_result = evaluate_gates(case_manifest, run_manifest, score_result, _gate_manifest(), REPO_ROOT)
    report = build_report(case_manifest, run_manifest, score_result, gate_result)

    actual_by_id = {result["assertion_id"]: result["actual_value"] for result in score_result["assertion_results"]}
    assert actual_by_id == {
        "conditioned_assumerole_permission_edge_present": 0,
        "clean_assumerole_trust_edge_present": 1,
        "validated_admin_absent": 0,
    }
    assert score_result["passed"] is False
    assert any(
        defect["assertion_id"] == "conditioned_assumerole_permission_edge_present"
        and defect["defect_class"] == "semantic_mismatch"
        for defect in score_result["defects"]
    )
    assert gate_result["artifact_sufficient"] is True
    assert gate_result["promotion_blocked"] is True
    assert gate_result["human_review_required"] is True
    assert "`semantic_mismatch` - assertion conditioned_assumerole_permission_edge_present failed" in report
    assert "composite_score" not in report


def test_deg04_false_validated_admin_claim_blocks_promotion(tmp_path: Path) -> None:
    case_manifest = _deg04_case_manifest()
    run_manifest = _deg04_run_manifest(
        tmp_path,
        _deg04_condition_stripped_scenario(),
        {"findings": [_deg04_admin_finding("validated")]},
    )

    score_result = score_case(case_manifest, run_manifest, REPO_ROOT)
    gate_result = evaluate_gates(case_manifest, run_manifest, score_result, _gate_manifest(), REPO_ROOT)
    report = build_report(case_manifest, run_manifest, score_result, gate_result)

    assert score_result["passed"] is False
    assert any(defect["defect_class"] == "false_admin_claim" for defect in score_result["defects"])
    assert gate_result["artifact_sufficient"] is True
    assert gate_result["promotion_blocked"] is True
    assert gate_result["human_review_required"] is True
    assert any(defect["defect_class"] == "false_admin_claim" for defect in gate_result["defects"])
    assert "`false_admin_claim` - assertion validated_admin_absent failed" in report


def test_deg04_conditioned_nonvalidated_fixture_scores_cleanly(tmp_path: Path) -> None:
    case_manifest = _deg04_case_manifest()
    run_manifest = _deg04_run_manifest(
        tmp_path,
        _deg04_conditioned_scenario(),
        {"findings": []},
    )

    score_result = score_case(case_manifest, run_manifest, REPO_ROOT)
    gate_result = evaluate_gates(case_manifest, run_manifest, score_result, _gate_manifest(), REPO_ROOT)
    report = build_report(case_manifest, run_manifest, score_result, gate_result)

    assert score_result["passed"] is True
    assert score_result["defects"] == []
    assert gate_result["artifact_sufficient"] is True
    assert gate_result["promotion_blocked"] is False
    assert gate_result["human_review_required"] is True
    assert "The benchmark requires explicit permission-side condition evidence" in report


def _deg05_run_manifest(tmp_path: Path, scenario_doc: dict, findings_doc: dict) -> dict:
    scenario_path = tmp_path / "deg05-scenario.json"
    findings_path = tmp_path / "deg05-findings.json"
    _write_json(scenario_path, scenario_doc)
    _write_json(findings_path, findings_doc)
    return {
        "manifest_type": "benchmark_run_manifest",
        "schema_version": "0.1",
        "run_id": "deg05-malformed-policy-parse-synthetic",
        "case_id": DEG05_CASE_ID,
        "tool_name": "iamscope",
        "git_sha": None,
        "started_at": None,
        "ended_at": None,
        "authority": "synthetic",
        "confidence": "high",
        "benchmark_date": "2026-05-09",
        "environment": "synthetic/deg05_malformed_policy_parse",
        "tool_claims": [],
        "context": {
            "source_provider_id": DEG05_ALICE_ARN,
            "target_provider_id": DEG05_ADMIN_ARN,
        },
        "artifact_status": {
            "scenario_validation": "pass",
            "artifact_retention": "complete",
        },
        "artifacts": {
            "scenario_json": str(scenario_path),
            "findings_json": str(findings_path),
        },
    }


def _deg05_malformed_policy_scenario(*, include_parse_marker: bool = True) -> dict:
    constraints = []
    if include_parse_marker:
        constraints.append(
            {
                "constraint_id": "deg05-malformed-policy-parse-error",
                "constraint_type": "POLICY_PARSE_ERROR",
                "scope_id": DEG05_ALICE_ARN,
                "statement_id": "deg05-malformed-assumerole-policy",
                "properties": {
                    "policy_source": "identity_policy",
                    "policy_name": "deg05-malformed-assume-admin",
                    "parse_status": "malformed",
                    "parse_error": "deg05 malformed policy parse fixture",
                    "condition_keys": ["deg05:malformed-policy-parse"],
                },
            }
        )
    return {
        "nodes": [
            {
                "node_type": "IAMUser",
                "provider_id": DEG05_ALICE_ARN,
                "name": "deg05-alice",
            },
            {
                "node_type": "IAMRole",
                "provider_id": DEG05_ADMIN_ARN,
                "name": "deg05-admin",
                "features": {"admin_equivalent": True},
            },
        ],
        "edges": [
            {
                "edge_id": "deg05-trust-edge",
                "edge_type": "sts:AssumeRole_trust",
                "src": {"provider_id": DEG05_ALICE_ARN},
                "dst": {"provider_id": DEG05_ADMIN_ARN},
            }
        ],
        "constraints": constraints,
        "edge_constraints": [],
    }


def _deg05_admin_finding(verdict: str) -> dict:
    return {
        "pattern_id": "admin_reachability",
        "verdict": verdict,
        "source": {"provider_id": DEG05_ALICE_ARN},
        "target": {"provider_id": DEG05_ADMIN_ARN},
        "blockers_observed": [],
        "required_checks": [],
    }


def test_deg05_malformed_policy_parse_is_explicit_and_blocks_promotion(tmp_path: Path) -> None:
    case_manifest = _deg05_case_manifest()
    run_manifest = _deg05_run_manifest(
        tmp_path,
        _deg05_malformed_policy_scenario(),
        {"findings": []},
    )

    assert validate_run_manifest(run_manifest) == []
    score_result = score_case(case_manifest, run_manifest, REPO_ROOT)
    gate_result = evaluate_gates(case_manifest, run_manifest, score_result, _gate_manifest(), REPO_ROOT)
    report = build_report(case_manifest, run_manifest, score_result, gate_result)

    actual_by_id = {result["assertion_id"]: result["actual_value"] for result in score_result["assertion_results"]}
    assert actual_by_id == {
        "malformed_policy_parse_marker_present": 1,
        "clean_assumerole_trust_edge_present": 1,
        "clean_assumerole_permission_edge_present": 0,
        "validated_admin_absent": 0,
    }
    assert score_result["passed"] is False
    assert any(
        defect["assertion_id"] == "clean_assumerole_permission_edge_present"
        and defect["defect_class"] == "semantic_mismatch"
        for defect in score_result["defects"]
    )
    assert gate_result["artifact_sufficient"] is True
    assert gate_result["promotion_blocked"] is True
    assert gate_result["human_review_required"] is True
    assert "`semantic_mismatch` - assertion clean_assumerole_permission_edge_present failed" in report
    assert "composite_score" not in report


def test_deg05_false_validated_admin_claim_blocks_promotion(tmp_path: Path) -> None:
    case_manifest = _deg05_case_manifest()
    run_manifest = _deg05_run_manifest(
        tmp_path,
        _deg05_malformed_policy_scenario(),
        {"findings": [_deg05_admin_finding("validated")]},
    )

    score_result = score_case(case_manifest, run_manifest, REPO_ROOT)
    gate_result = evaluate_gates(case_manifest, run_manifest, score_result, _gate_manifest(), REPO_ROOT)
    report = build_report(case_manifest, run_manifest, score_result, gate_result)

    assert score_result["passed"] is False
    assert any(defect["defect_class"] == "false_admin_claim" for defect in score_result["defects"])
    assert gate_result["artifact_sufficient"] is True
    assert gate_result["promotion_blocked"] is True
    assert gate_result["human_review_required"] is True
    assert any(defect["defect_class"] == "false_admin_claim" for defect in gate_result["defects"])
    assert "`false_admin_claim` - assertion validated_admin_absent failed" in report


def test_deg05_missing_parse_marker_is_explicit_semantic_mismatch(tmp_path: Path) -> None:
    case_manifest = _deg05_case_manifest()
    run_manifest = _deg05_run_manifest(
        tmp_path,
        _deg05_malformed_policy_scenario(include_parse_marker=False),
        {"findings": []},
    )

    score_result = score_case(case_manifest, run_manifest, REPO_ROOT)
    gate_result = evaluate_gates(case_manifest, run_manifest, score_result, _gate_manifest(), REPO_ROOT)
    report = build_report(case_manifest, run_manifest, score_result, gate_result)

    assert score_result["passed"] is False
    assert any(
        defect["assertion_id"] == "malformed_policy_parse_marker_present"
        and defect["defect_class"] == "semantic_mismatch"
        for defect in score_result["defects"]
    )
    assert gate_result["artifact_sufficient"] is True
    assert gate_result["promotion_blocked"] is True
    assert gate_result["human_review_required"] is True
    assert "`semantic_mismatch` - assertion malformed_policy_parse_marker_present failed" in report


def _deg06_run_manifest(tmp_path: Path, scenario_doc: dict, findings_doc: dict) -> dict:
    scenario_path = tmp_path / "deg06-scenario.json"
    findings_path = tmp_path / "deg06-findings.json"
    _write_json(scenario_path, scenario_doc)
    _write_json(findings_path, findings_doc)
    return {
        "manifest_type": "benchmark_run_manifest",
        "schema_version": "0.1",
        "run_id": "deg06-partial-account-collection-synthetic",
        "case_id": DEG06_CASE_ID,
        "tool_name": "iamscope",
        "git_sha": None,
        "started_at": None,
        "ended_at": None,
        "authority": "synthetic",
        "confidence": "high",
        "benchmark_date": "2026-05-09",
        "environment": "synthetic/deg06_partial_account_collection",
        "tool_claims": [],
        "context": {
            "source_provider_id": DEG06_ALICE_ARN,
            "target_provider_id": DEG06_ADMIN_ARN,
        },
        "artifact_status": {
            "scenario_validation": "pass",
            "artifact_retention": "complete",
        },
        "artifacts": {
            "scenario_json": str(scenario_path),
            "findings_json": str(findings_path),
        },
    }


def _deg06_partial_collection_scenario(*, include_marker: bool = True) -> dict:
    constraints = []
    if include_marker:
        constraints.append(
            {
                "constraint_id": "deg06-target-account-skipped",
                "constraint_type": "COLLECTION_PARTIAL",
                "scope_id": DEG06_TARGET_ACCOUNT_ID,
                "statement_id": "deg06-target-account-collection-status",
                "properties": {
                    "collection_status": "partial",
                    "accounts_collected": [DEG06_CALLER_ACCOUNT_ID],
                    "accounts_skipped": [DEG06_TARGET_ACCOUNT_ID],
                    "skipped_account_id": DEG06_TARGET_ACCOUNT_ID,
                    "reason": "deg06 synthetic target account collection skipped",
                    "condition_keys": ["deg06:target-account-skipped"],
                },
            }
        )
    return {
        "nodes": [
            {
                "node_type": "IAMUser",
                "provider_id": DEG06_ALICE_ARN,
                "name": "deg06-alice",
                "features": {"account_id": DEG06_CALLER_ACCOUNT_ID},
            }
        ],
        "edges": [
            {
                "edge_id": "deg06-caller-permission-edge",
                "edge_type": "sts:AssumeRole_permission",
                "src": {"provider_id": DEG06_ALICE_ARN},
                "dst": {"provider_id": DEG06_ADMIN_ARN},
                "features": {
                    "source_account_id": DEG06_CALLER_ACCOUNT_ID,
                    "target_account_id": DEG06_TARGET_ACCOUNT_ID,
                    "has_conditions": False,
                    "is_wildcard_resource": False,
                },
            }
        ],
        "constraints": constraints,
        "edge_constraints": [],
    }


def _deg06_finding(pattern_id: str, verdict: str) -> dict:
    return {
        "pattern_id": pattern_id,
        "verdict": verdict,
        "source": {"provider_id": DEG06_ALICE_ARN},
        "target": {"provider_id": DEG06_ADMIN_ARN},
        "blockers_observed": [],
        "required_checks": [],
    }


def test_deg06_partial_account_collection_is_explicit_and_blocks_promotion(tmp_path: Path) -> None:
    case_manifest = _deg06_case_manifest()
    run_manifest = _deg06_run_manifest(
        tmp_path,
        _deg06_partial_collection_scenario(),
        {"findings": []},
    )

    assert validate_run_manifest(run_manifest) == []
    score_result = score_case(case_manifest, run_manifest, REPO_ROOT)
    gate_result = evaluate_gates(case_manifest, run_manifest, score_result, _gate_manifest(), REPO_ROOT)
    report = build_report(case_manifest, run_manifest, score_result, gate_result)

    actual_by_id = {result["assertion_id"]: result["actual_value"] for result in score_result["assertion_results"]}
    assert actual_by_id == {
        "partial_collection_marker_present": 1,
        "caller_assumerole_permission_edge_present": 1,
        "target_admin_role_node_present": 0,
        "target_trust_edge_present": 0,
        "validated_admin_absent": 0,
        "validated_cross_account_trust_absent": 0,
    }
    assert score_result["passed"] is False
    assert any(
        defect["assertion_id"] == "target_admin_role_node_present" and defect["defect_class"] == "semantic_mismatch"
        for defect in score_result["defects"]
    )
    assert any(
        defect["assertion_id"] == "target_trust_edge_present" and defect["defect_class"] == "semantic_mismatch"
        for defect in score_result["defects"]
    )
    assert gate_result["artifact_sufficient"] is True
    assert gate_result["promotion_blocked"] is True
    assert gate_result["human_review_required"] is True
    assert "`semantic_mismatch` - assertion target_admin_role_node_present failed" in report
    assert "`semantic_mismatch` - assertion target_trust_edge_present failed" in report
    assert "composite_score" not in report


def test_deg06_missing_partial_collection_marker_blocks_as_semantic_mismatch(tmp_path: Path) -> None:
    case_manifest = _deg06_case_manifest()
    run_manifest = _deg06_run_manifest(
        tmp_path,
        _deg06_partial_collection_scenario(include_marker=False),
        {"findings": []},
    )

    score_result = score_case(case_manifest, run_manifest, REPO_ROOT)
    gate_result = evaluate_gates(case_manifest, run_manifest, score_result, _gate_manifest(), REPO_ROOT)
    report = build_report(case_manifest, run_manifest, score_result, gate_result)

    assert score_result["passed"] is False
    assert any(
        defect["assertion_id"] == "partial_collection_marker_present" and defect["defect_class"] == "semantic_mismatch"
        for defect in score_result["defects"]
    )
    assert gate_result["artifact_sufficient"] is True
    assert gate_result["promotion_blocked"] is True
    assert gate_result["human_review_required"] is True
    assert "`semantic_mismatch` - assertion partial_collection_marker_present failed" in report


def test_deg06_false_validated_admin_or_cross_account_claim_blocks_promotion(tmp_path: Path) -> None:
    case_manifest = _deg06_case_manifest()
    run_manifest = _deg06_run_manifest(
        tmp_path,
        _deg06_partial_collection_scenario(),
        {
            "findings": [
                _deg06_finding("admin_reachability", "validated"),
                _deg06_finding("cross_account_trust", "validated"),
            ]
        },
    )

    score_result = score_case(case_manifest, run_manifest, REPO_ROOT)
    gate_result = evaluate_gates(case_manifest, run_manifest, score_result, _gate_manifest(), REPO_ROOT)
    report = build_report(case_manifest, run_manifest, score_result, gate_result)

    assert score_result["passed"] is False
    assert any(
        defect["assertion_id"] == "validated_admin_absent" and defect["defect_class"] == "false_admin_claim"
        for defect in score_result["defects"]
    )
    assert any(
        defect["assertion_id"] == "validated_cross_account_trust_absent"
        and defect["defect_class"] == "false_admin_claim"
        for defect in score_result["defects"]
    )
    assert gate_result["artifact_sufficient"] is True
    assert gate_result["promotion_blocked"] is True
    assert gate_result["human_review_required"] is True
    assert "`false_admin_claim` - assertion validated_admin_absent failed" in report
    assert "`false_admin_claim` - assertion validated_cross_account_trust_absent failed" in report
