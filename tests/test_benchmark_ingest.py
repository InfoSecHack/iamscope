from __future__ import annotations

import json
from pathlib import Path

from benchmarks.common import load_json
from benchmarks.scoring.ingest import ingest_archive
from benchmarks.scoring.validator import validate_run_manifest

REPO_ROOT = Path(__file__).resolve().parent.parent


def _write_json(path: Path, payload: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload))


def _make_archive(tmp_path: Path, name: str, *, include_findings: bool = True, include_expected: bool = True) -> Path:
    archive_dir = tmp_path / name
    collect_dir = archive_dir / "collect"
    collect_dir.mkdir(parents=True)
    run_log = "\n".join(
        [
            "Resources deployed:",
            "  alice_arn  : arn:aws:iam::123456789012:user/iamscope-test/env03-cc1-alice",
            "  admins_arn : arn:aws:iam::123456789012:group/iamscope-test/env03-cc1-admins",
            "  account_id : 123456789012",
            "scenario validation: PASS",
            "benchmark semantic assertion: PASS",
        ]
    )
    (archive_dir / "run.log").write_text(run_log + "\n")
    (archive_dir / "scenario_validate.txt").write_text("Validation PASSED - scenario.json is structurally valid.\n")
    _write_json(collect_dir / "scenario.json", {"nodes": [], "edges": [], "constraints": []})
    if include_findings:
        _write_json(
            collect_dir / "findings.json",
            {
                "findings": [
                    {
                        "pattern_id": "iam_group_membership_escalation",
                        "verdict": "blocked",
                        "source": {"provider_id": "arn:aws:iam::123456789012:user/iamscope-test/env03-cc1-alice"},
                        "target": {"provider_id": "arn:aws:iam::123456789012:group/iamscope-test/env03-cc1-admins"},
                    }
                ]
            },
        )
    _write_json(collect_dir / "binding_metadata.json", {"bindings": []})
    if include_expected:
        _write_json(archive_dir / "expected_findings.json", {"environment": "env03_cc1_identity_deny"})
    return archive_dir


def test_successful_env03_style_ingest(tmp_path: Path) -> None:
    archive_dir = _make_archive(tmp_path, "iamscope-benchmark-env03-20260424T011802Z")
    out_path = tmp_path / "env03_run_manifest.json"
    run_manifest = ingest_archive("env03_identity_deny_group_escalation", archive_dir, out_path, REPO_ROOT)
    assert out_path.exists()
    assert run_manifest["run_id"] == "iamscope-benchmark-env03-20260424T011802Z"
    assert run_manifest["artifact_status"]["scenario_validation"] == "pass"
    assert run_manifest["context"]["source_provider_id"].endswith("env03-cc1-alice")
    assert run_manifest["context"]["target_provider_id"].endswith("env03-cc1-admins")
    assert "expected_findings_json" in run_manifest["artifacts"]
    assert validate_run_manifest(load_json(out_path)) == []


def test_missing_findings_is_retained_as_incomplete_artifact(tmp_path: Path) -> None:
    archive_dir = _make_archive(tmp_path, "iamscope-benchmark-env03-20260424T011803Z", include_findings=False)
    out_path = tmp_path / "missing_findings.json"
    run_manifest = ingest_archive("env03_identity_deny_group_escalation", archive_dir, out_path, REPO_ROOT)
    assert out_path.exists()
    assert run_manifest["artifact_status"]["artifact_retention"] == "incomplete"
    assert run_manifest["artifacts"]["findings_json"].endswith("collect/findings.json")
    assert validate_run_manifest(load_json(out_path)) == []


def test_optional_expected_findings_absent_is_honest(tmp_path: Path) -> None:
    archive_dir = _make_archive(tmp_path, "iamscope-benchmark-env03-20260424T011804Z", include_expected=False)
    out_path = tmp_path / "env03_without_expected.json"
    run_manifest = ingest_archive("env03_identity_deny_group_escalation", archive_dir, out_path, REPO_ROOT)
    assert "expected_findings_json" not in run_manifest["artifacts"]
    assert validate_run_manifest(load_json(out_path)) == []


def test_scenario_validation_pass_is_parsed_correctly(tmp_path: Path) -> None:
    archive_dir = _make_archive(tmp_path, "iamscope-benchmark-env03-20260424T011805Z")
    out_path = tmp_path / "env03_validation_pass.json"
    run_manifest = ingest_archive("env03_identity_deny_group_escalation", archive_dir, out_path, REPO_ROOT)
    assert run_manifest["artifact_status"]["scenario_validation"] == "pass"


def test_env14_ingest_parses_alice_admin_context(tmp_path: Path) -> None:
    archive_dir = tmp_path / "iamscope-benchmark-env14-20260428T220000Z"
    collect_dir = archive_dir / "collect"
    collect_dir.mkdir(parents=True)
    run_log = "\n".join(
        [
            "Resources deployed:",
            "  alice_arn  : arn:aws:iam::123456789012:user/iamscope-test/env14-alice",
            "  admin_arn  : arn:aws:iam::123456789012:role/iamscope-test/env14-admin",
            "  account_id : 123456789012",
            "scenario validation: PASS",
            "benchmark semantic assertion: PASS",
        ]
    )
    (archive_dir / "run.log").write_text(run_log + "\n")
    (archive_dir / "scenario_validate.txt").write_text("Validation PASSED - scenario.json is structurally valid.\n")
    _write_json(collect_dir / "scenario.json", {"nodes": [], "edges": [], "constraints": []})
    _write_json(collect_dir / "findings.json", {"findings": []})
    _write_json(collect_dir / "binding_metadata.json", {"bindings": []})
    _write_json(archive_dir / "expected_findings.json", {"environment": "env14_permission_condition_blocked_admin"})

    out_path = tmp_path / "env14_run_manifest.json"
    run_manifest = ingest_archive("env14_permission_condition_blocked_admin", archive_dir, out_path, REPO_ROOT)

    assert run_manifest["context"]["source_provider_id"].endswith("env14-alice")
    assert run_manifest["context"]["target_provider_id"].endswith("env14-admin")
    assert validate_run_manifest(load_json(out_path)) == []


def test_env18_ingest_parses_lambda_passrole_context(tmp_path: Path) -> None:
    archive_dir = tmp_path / "iamscope-benchmark-env18-20260429T030000Z"
    collect_dir = archive_dir / "collect"
    collect_dir.mkdir(parents=True)
    run_log = "\n".join(
        [
            "Resources deployed:",
            "  alice_arn             : arn:aws:iam::123456789012:user/iamscope-test/env18-alice",
            "  lambda_admin_role_arn : arn:aws:iam::123456789012:role/iamscope-test/env18-lambda-admin-exec",
            "  lambda_function_arn   : arn:aws:lambda:us-east-1:123456789012:function:env18-passrole-probe",
            "  account_id            : 123456789012",
            "scenario validation: PASS",
            "benchmark semantic assertion: PASS",
        ]
    )
    (archive_dir / "run.log").write_text(run_log + "\n")
    (archive_dir / "scenario_validate.txt").write_text("Validation PASSED - scenario.json is structurally valid.\n")
    _write_json(collect_dir / "scenario.json", {"nodes": [], "edges": [], "constraints": []})
    _write_json(collect_dir / "findings.json", {"findings": []})
    _write_json(collect_dir / "binding_metadata.json", {"bindings": []})
    _write_json(archive_dir / "expected_findings.json", {"environment": "env18_lambda_passrole_validated"})

    out_path = tmp_path / "env18_run_manifest.json"
    run_manifest = ingest_archive("env18_lambda_passrole_validated", archive_dir, out_path, REPO_ROOT)

    assert run_manifest["context"]["source_provider_id"].endswith("env18-alice")
    assert run_manifest["context"]["target_provider_id"].endswith("env18-lambda-admin-exec")
    assert validate_run_manifest(load_json(out_path)) == []


def test_env19_ingest_parses_passedtoservice_mutation_context(tmp_path: Path) -> None:
    archive_dir = tmp_path / "iamscope-benchmark-env19-20260429T040000Z"
    collect_dir = archive_dir / "collect"
    collect_dir.mkdir(parents=True)
    run_log = "\n".join(
        [
            "Resources deployed:",
            "  alice_arn             : arn:aws:iam::123456789012:user/iamscope-test/env19-alice",
            "  lambda_admin_role_arn : arn:aws:iam::123456789012:role/iamscope-test/env19-lambda-admin-exec",
            "  lambda_function_arn   : arn:aws:lambda:us-east-1:123456789012:function:env19-passrole-probe",
            "  account_id            : 123456789012",
            "scenario validation: PASS",
            "benchmark semantic assertion: PASS",
        ]
    )
    (archive_dir / "run.log").write_text(run_log + "\n")
    (archive_dir / "scenario_validate.txt").write_text("Validation PASSED - scenario.json is structurally valid.\n")
    _write_json(collect_dir / "scenario.json", {"nodes": [], "edges": [], "constraints": []})
    _write_json(collect_dir / "findings.json", {"findings": []})
    _write_json(collect_dir / "binding_metadata.json", {"bindings": []})
    _write_json(archive_dir / "expected_findings.json", {"environment": "env19_env18_passedtoservice_scoped_away"})

    out_path = tmp_path / "env19_run_manifest.json"
    run_manifest = ingest_archive("env19_passedtoservice_scoped_away_nonvalidated", archive_dir, out_path, REPO_ROOT)

    assert run_manifest["context"]["source_provider_id"].endswith("env19-alice")
    assert run_manifest["context"]["target_provider_id"].endswith("env19-lambda-admin-exec")
    assert validate_run_manifest(load_json(out_path)) == []


def test_env20_ingest_parses_ecs_passrole_context(tmp_path: Path) -> None:
    archive_dir = tmp_path / "iamscope-benchmark-env20-20260429T050000Z"
    collect_dir = archive_dir / "collect"
    collect_dir.mkdir(parents=True)
    run_log = "\n".join(
        [
            "Resources deployed:",
            "  alice_arn              : arn:aws:iam::123456789012:user/iamscope-test/env20-alice",
            "  ecs_admin_role_arn     : arn:aws:iam::123456789012:role/iamscope-test/env20-ecs-admin-task",
            "  ecs_task_definition_arn: arn:aws:ecs:us-east-1:123456789012:task-definition/env20-passrole-probe:1",
            "  account_id             : 123456789012",
            "scenario validation: PASS",
            "benchmark semantic assertion: PASS",
        ]
    )
    (archive_dir / "run.log").write_text(run_log + "\n")
    (archive_dir / "scenario_validate.txt").write_text("Validation PASSED - scenario.json is structurally valid.\n")
    _write_json(collect_dir / "scenario.json", {"nodes": [], "edges": [], "constraints": []})
    _write_json(collect_dir / "findings.json", {"findings": []})
    _write_json(collect_dir / "binding_metadata.json", {"bindings": []})
    _write_json(archive_dir / "expected_findings.json", {"environment": "env20_ecs_passrole_validated"})

    out_path = tmp_path / "env20_run_manifest.json"
    run_manifest = ingest_archive("env20_ecs_passrole_validated", archive_dir, out_path, REPO_ROOT)

    assert run_manifest["context"]["source_provider_id"].endswith("env20-alice")
    assert run_manifest["context"]["target_provider_id"].endswith("env20-ecs-admin-task")
    assert validate_run_manifest(load_json(out_path)) == []


def test_env21_ingest_parses_ecs_passedtoservice_mutation_context(tmp_path: Path) -> None:
    archive_dir = tmp_path / "iamscope-benchmark-env21-20260429T060000Z"
    collect_dir = archive_dir / "collect"
    collect_dir.mkdir(parents=True)
    run_log = "\n".join(
        [
            "Resources deployed:",
            "  alice_arn              : arn:aws:iam::123456789012:user/iamscope-test/env21-alice",
            "  ecs_admin_role_arn     : arn:aws:iam::123456789012:role/iamscope-test/env21-ecs-admin-task",
            "  ecs_task_definition_arn: arn:aws:ecs:us-east-1:123456789012:task-definition/env21-passrole-probe:1",
            "  account_id             : 123456789012",
            "scenario validation: PASS",
            "benchmark semantic assertion: PASS",
        ]
    )
    (archive_dir / "run.log").write_text(run_log + "\n")
    (archive_dir / "scenario_validate.txt").write_text("Validation PASSED - scenario.json is structurally valid.\n")
    _write_json(collect_dir / "scenario.json", {"nodes": [], "edges": [], "constraints": []})
    _write_json(collect_dir / "findings.json", {"findings": []})
    _write_json(collect_dir / "binding_metadata.json", {"bindings": []})
    _write_json(archive_dir / "expected_findings.json", {"environment": "env21_env20_passedtoservice_scoped_away"})

    out_path = tmp_path / "env21_run_manifest.json"
    run_manifest = ingest_archive(
        "env21_ecs_passedtoservice_scoped_away_nonvalidated", archive_dir, out_path, REPO_ROOT
    )

    assert run_manifest["context"]["source_provider_id"].endswith("env21-alice")
    assert run_manifest["context"]["target_provider_id"].endswith("env21-ecs-admin-task")
    assert validate_run_manifest(load_json(out_path)) == []


def test_env22_ingest_parses_cross_account_context(tmp_path: Path) -> None:
    archive_dir = tmp_path / "iamscope-benchmark-env22-20260430T010000Z"
    collect_dir = archive_dir / "collect"
    collect_dir.mkdir(parents=True)
    run_log = "\n".join(
        [
            "Resources deployed:",
            "  alice_arn                : arn:aws:iam::377114445031:user/iamscope-test/env22-alice",
            "  admin_arn                : arn:aws:iam::737923406074:role/iamscope-test/env22-cross-account-admin",
            "  caller_account_id        : 377114445031",
            "  target_account_id        : 737923406074",
            "  collection_role_name     : env22-iamscope-reader",
            "scenario validation: PASS",
            "benchmark semantic assertion: PASS",
        ]
    )
    (archive_dir / "run.log").write_text(run_log + "\n")
    (archive_dir / "scenario_validate.txt").write_text("Validation PASSED - scenario.json is structurally valid.\n")
    _write_json(collect_dir / "scenario.json", {"nodes": [], "edges": [], "constraints": []})
    _write_json(collect_dir / "findings.json", {"findings": []})
    _write_json(collect_dir / "binding_metadata.json", {"bindings": []})
    _write_json(archive_dir / "expected_findings.json", {"environment": "env22_cross_account_validated"})

    out_path = tmp_path / "env22_run_manifest.json"
    run_manifest = ingest_archive("env22_cross_account_validated_admin", archive_dir, out_path, REPO_ROOT)

    assert run_manifest["context"]["source_provider_id"].endswith("env22-alice")
    assert run_manifest["context"]["target_provider_id"].endswith("env22-cross-account-admin")
    assert validate_run_manifest(load_json(out_path)) == []


def test_env23_ingest_parses_cross_account_mutation_context(tmp_path: Path) -> None:
    archive_dir = tmp_path / "iamscope-benchmark-env23-20260506T010000Z"
    collect_dir = archive_dir / "collect"
    collect_dir.mkdir(parents=True)
    run_log = "\n".join(
        [
            "Resources deployed:",
            "  alice_arn                : arn:aws:iam::377114445031:user/iamscope-test/env23-alice",
            "  decoy_arn                : arn:aws:iam::377114445031:user/iamscope-test/env23-decoy",
            "  admin_arn                : arn:aws:iam::737923406074:role/iamscope-test/env23-cross-account-admin",
            "  caller_account_id        : 377114445031",
            "  target_account_id        : 737923406074",
            "  collection_role_name     : env23-iamscope-reader",
            "scenario validation: PASS",
            "benchmark semantic assertion: PASS",
        ]
    )
    (archive_dir / "run.log").write_text(run_log + "\n")
    (archive_dir / "scenario_validate.txt").write_text("Validation PASSED - scenario.json is structurally valid.\n")
    _write_json(collect_dir / "scenario.json", {"nodes": [], "edges": [], "constraints": []})
    _write_json(collect_dir / "findings.json", {"findings": []})
    _write_json(collect_dir / "binding_metadata.json", {"bindings": []})
    _write_json(archive_dir / "expected_findings.json", {"environment": "env23_env22_trust_scoped_away"})

    out_path = tmp_path / "env23_run_manifest.json"
    run_manifest = ingest_archive(
        "env23_cross_account_trust_scoped_away_nonvalidated", archive_dir, out_path, REPO_ROOT
    )

    assert run_manifest["context"]["source_provider_id"].endswith("env23-alice")
    assert run_manifest["context"]["target_provider_id"].endswith("env23-cross-account-admin")
    assert validate_run_manifest(load_json(out_path)) == []


def test_env24_ingest_parses_s3_resource_policy_context(tmp_path: Path) -> None:
    archive_dir = tmp_path / "iamscope-benchmark-env24-20260507T010000Z"
    collect_dir = archive_dir / "collect"
    collect_dir.mkdir(parents=True)
    run_log = "\n".join(
        [
            "Resources deployed:",
            "  reader_arn  : arn:aws:iam::123456789012:user/iamscope-test/env24-reader",
            "  bucket_arn  : arn:aws:s3:::env24-rp-allow-123456789012-deadbeef",
            "  bucket_name : env24-rp-allow-123456789012-deadbeef",
            "  account_id  : 123456789012",
            "scenario validation: PASS",
            "benchmark semantic assertion: PASS",
        ]
    )
    (archive_dir / "run.log").write_text(run_log + "\n")
    (archive_dir / "scenario_validate.txt").write_text("Validation PASSED - scenario.json is structurally valid.\n")
    _write_json(collect_dir / "scenario.json", {"nodes": [], "edges": [], "constraints": []})
    _write_json(collect_dir / "findings.json", {"findings": []})
    _write_json(collect_dir / "binding_metadata.json", {"bindings": []})
    _write_json(archive_dir / "expected_findings.json", {"environment": "env24_s3_resource_policy_allow"})

    out_path = tmp_path / "env24_run_manifest.json"
    run_manifest = ingest_archive("env24_s3_resource_policy_allow", archive_dir, out_path, REPO_ROOT)

    assert run_manifest["context"]["source_provider_id"].endswith("env24-reader")
    assert run_manifest["context"]["target_provider_id"] == "arn:aws:s3:::env24-rp-allow-123456789012-deadbeef"
    assert validate_run_manifest(load_json(out_path)) == []


def test_env25_ingest_parses_scoped_away_s3_resource_policy_context(tmp_path: Path) -> None:
    archive_dir = tmp_path / "iamscope-benchmark-env25-20260508T010000Z"
    collect_dir = archive_dir / "collect"
    collect_dir.mkdir(parents=True)
    run_log = "\n".join(
        [
            "Resources deployed:",
            "  reader_arn  : arn:aws:iam::123456789012:user/iamscope-test/env25-reader",
            "  decoy_arn   : arn:aws:iam::123456789012:user/iamscope-test/env25-decoy",
            "  bucket_arn  : arn:aws:s3:::env25-rp-scoped-away-123456789012-deadbeef",
            "  bucket_name : env25-rp-scoped-away-123456789012-deadbeef",
            "  account_id  : 123456789012",
            "scenario validation: PASS",
            "benchmark semantic assertion: PASS",
        ]
    )
    (archive_dir / "run.log").write_text(run_log + "\n")
    (archive_dir / "scenario_validate.txt").write_text("Validation PASSED - scenario.json is structurally valid.\n")
    _write_json(collect_dir / "scenario.json", {"nodes": [], "edges": [], "constraints": []})
    _write_json(collect_dir / "findings.json", {"findings": []})
    _write_json(collect_dir / "binding_metadata.json", {"bindings": []})
    _write_json(
        archive_dir / "expected_findings.json",
        {"environment": "env25_env24_resource_policy_allow_scoped_away"},
    )

    out_path = tmp_path / "env25_run_manifest.json"
    run_manifest = ingest_archive(
        "env25_s3_resource_policy_allow_scoped_away_nonvalidated", archive_dir, out_path, REPO_ROOT
    )

    assert run_manifest["context"]["source_provider_id"].endswith("env25-reader")
    assert run_manifest["context"]["decoy_provider_id"].endswith("env25-decoy")
    assert run_manifest["context"]["target_provider_id"] == "arn:aws:s3:::env25-rp-scoped-away-123456789012-deadbeef"
    assert validate_run_manifest(load_json(out_path)) == []


def test_env26_ingest_parses_multihop_context(tmp_path: Path) -> None:
    archive_dir = tmp_path / "iamscope-benchmark-env26-20260509T010000Z"
    collect_dir = archive_dir / "collect"
    collect_dir.mkdir(parents=True)
    run_log = "\n".join(
        [
            "Resources deployed:",
            "  alice_arn  : arn:aws:iam::123456789012:user/iamscope-test/env26-alice",
            "  hop1_arn   : arn:aws:iam::123456789012:role/iamscope-test/env26-hop1",
            "  hop2_arn   : arn:aws:iam::123456789012:role/iamscope-test/env26-hop2",
            "  admin_arn  : arn:aws:iam::123456789012:role/iamscope-test/env26-admin",
            "  account_id : 123456789012",
            "scenario validation: PASS",
            "benchmark semantic assertion: PASS",
        ]
    )
    (archive_dir / "run.log").write_text(run_log + "\n")
    (archive_dir / "scenario_validate.txt").write_text("Validation PASSED - scenario.json is structurally valid.\n")
    _write_json(collect_dir / "scenario.json", {"nodes": [], "edges": [], "constraints": []})
    _write_json(collect_dir / "findings.json", {"findings": []})
    _write_json(collect_dir / "binding_metadata.json", {"bindings": []})
    _write_json(archive_dir / "expected_findings.json", {"environment": "env26_multihop_chain_validated"})

    out_path = tmp_path / "env26_run_manifest.json"
    run_manifest = ingest_archive("env26_multihop_chain_validated_admin", archive_dir, out_path, REPO_ROOT)

    assert run_manifest["context"]["source_provider_id"].endswith("env26-alice")
    assert run_manifest["context"]["hop1_provider_id"].endswith("env26-hop1")
    assert run_manifest["context"]["hop2_provider_id"].endswith("env26-hop2")
    assert run_manifest["context"]["target_provider_id"].endswith("env26-admin")
    assert validate_run_manifest(load_json(out_path)) == []
