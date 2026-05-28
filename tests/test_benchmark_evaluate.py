from __future__ import annotations

import json
from pathlib import Path

from benchmarks.common import load_json
from benchmarks.reporting.evaluate import evaluate_archive

REPO_ROOT = Path(__file__).resolve().parent.parent


def _write_json(path: Path, payload: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload))


def _make_env03_archive(
    tmp_path: Path, name: str, *, include_findings: bool = True, correct_semantics: bool = True
) -> Path:
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
        finding = {
            "pattern_id": "iam_group_membership_escalation",
            "verdict": "blocked" if correct_semantics else "validated",
            "source": {"provider_id": "arn:aws:iam::123456789012:user/iamscope-test/env03-cc1-alice"},
            "target": {"provider_id": "arn:aws:iam::123456789012:group/iamscope-test/env03-cc1-admins"},
            "blockers_observed": [
                {
                    "kind": "identity_deny",
                    "constraint_id": "constraint-1",
                    "edge_id": "edge-1",
                }
            ]
            if correct_semantics
            else [],
            "required_checks": [
                {
                    "name": "no_identity_deny_blocks_add_user_to_group",
                    "state": "fail",
                }
            ]
            if correct_semantics
            else [],
        }
        _write_json(collect_dir / "findings.json", {"findings": [finding]})
    _write_json(collect_dir / "binding_metadata.json", {"bindings": []})
    _write_json(archive_dir / "expected_findings.json", {"environment": "env03_cc1_identity_deny"})
    return archive_dir


def test_successful_evaluation_produces_all_outputs(tmp_path: Path) -> None:
    archive_dir = _make_env03_archive(tmp_path, "iamscope-benchmark-env03-20260424T020000Z")
    out_dir = tmp_path / "evaluation"
    result = evaluate_archive("env03_identity_deny_group_escalation", archive_dir, out_dir, REPO_ROOT)
    assert result["success"] is True
    assert (out_dir / "run_manifest.json").exists()
    assert (out_dir / "scorer_result.json").exists()
    assert (out_dir / "gate_result.json").exists()
    assert (out_dir / "report.md").exists()


def test_failed_semantic_assertion_blocks_promotion(tmp_path: Path) -> None:
    archive_dir = _make_env03_archive(
        tmp_path,
        "iamscope-benchmark-env03-20260424T020001Z",
        correct_semantics=False,
    )
    out_dir = tmp_path / "blocked-evaluation"
    result = evaluate_archive("env03_identity_deny_group_escalation", archive_dir, out_dir, REPO_ROOT)
    gate_result = load_json(out_dir / "gate_result.json")
    assert result["success"] is False
    assert gate_result["promotion_blocked"] is True
    assert any(defect["defect_class"] == "semantic_mismatch" for defect in gate_result["defects"])


def test_missing_required_artifact_fails_clearly(tmp_path: Path) -> None:
    archive_dir = _make_env03_archive(tmp_path, "iamscope-benchmark-env03-20260424T020002Z", include_findings=False)
    out_dir = tmp_path / "missing-artifact"
    result = evaluate_archive("env03_identity_deny_group_escalation", archive_dir, out_dir, REPO_ROOT)
    gate_result = load_json(out_dir / "gate_result.json")
    report = (out_dir / "report.md").read_text()
    assert result["success"] is False
    assert gate_result["artifact_sufficient"] is False
    assert gate_result["promotion_blocked"] is True
    assert any(defect["defect_class"] == "artifact_insufficient" for defect in gate_result["defects"])
    assert any("findings_json" in defect["message"] for defect in gate_result["defects"])
    assert "Artifact sufficient: `no`" in report


def test_report_separates_truth_sections(tmp_path: Path) -> None:
    archive_dir = _make_env03_archive(tmp_path, "iamscope-benchmark-env03-20260424T020003Z")
    out_dir = tmp_path / "report-sections"
    evaluate_archive("env03_identity_deny_group_escalation", archive_dir, out_dir, REPO_ROOT)
    report = (out_dir / "report.md").read_text()
    assert "## Directly Proven" in report
    assert "## Strongly Supported" in report
    assert "## Only Implied" in report
    assert "## Still Unknown" in report


def _make_env16_archive(tmp_path: Path, name: str, *, include_blocked_deny: bool = False) -> Path:
    archive_dir = tmp_path / name
    collect_dir = archive_dir / "collect"
    collect_dir.mkdir(parents=True)
    run_log = "\n".join(
        [
            "Resources deployed:",
            "  alice_arn  : arn:aws:iam::123456789012:user/iamscope-test/env16-alice",
            "  admins_arn : arn:aws:iam::123456789012:group/iamscope-test/env16-admins",
            "  account_id : 123456789012",
            "scenario validation: PASS",
            "benchmark semantic assertion: PASS",
        ]
    )
    (archive_dir / "run.log").write_text(run_log + "\n")
    (archive_dir / "scenario_validate.txt").write_text("Validation PASSED - scenario.json is structurally valid.\n")
    _write_json(collect_dir / "scenario.json", {"nodes": [], "edges": [], "constraints": []})
    finding = {
        "pattern_id": "iam_group_membership_escalation",
        "verdict": "blocked" if include_blocked_deny else "validated",
        "source": {"provider_id": "arn:aws:iam::123456789012:user/iamscope-test/env16-alice"},
        "target": {"provider_id": "arn:aws:iam::123456789012:group/iamscope-test/env16-admins"},
        "blockers_observed": [
            {
                "kind": "identity_deny",
                "constraint_id": "constraint-1",
                "edge_id": "edge-1",
            }
        ]
        if include_blocked_deny
        else [],
        "required_checks": [
            {
                "name": "no_identity_deny_blocks_add_user_to_group",
                "state": "fail" if include_blocked_deny else "pass",
            }
        ],
    }
    _write_json(collect_dir / "findings.json", {"findings": [finding]})
    _write_json(collect_dir / "binding_metadata.json", {"bindings": []})
    _write_json(archive_dir / "expected_findings.json", {"environment": "env16_env03_identity_deny_removed"})
    return archive_dir


def test_env16_evaluation_succeeds_with_identity_deny_removed(tmp_path: Path) -> None:
    archive_dir = _make_env16_archive(tmp_path, "iamscope-benchmark-env16-20260429T010000Z")
    out_dir = tmp_path / "env16-evaluation"
    result = evaluate_archive("env16_identity_deny_removed_validated_group_escalation", archive_dir, out_dir, REPO_ROOT)
    assert result["success"] is True
    assert (out_dir / "run_manifest.json").exists()
    assert (out_dir / "scorer_result.json").exists()
    assert (out_dir / "gate_result.json").exists()
    assert (out_dir / "report.md").exists()


def test_env16_evaluation_fails_if_identity_deny_still_blocks(tmp_path: Path) -> None:
    archive_dir = _make_env16_archive(
        tmp_path,
        "iamscope-benchmark-env16-20260429T010001Z",
        include_blocked_deny=True,
    )
    out_dir = tmp_path / "env16-deny-still-present"
    result = evaluate_archive("env16_identity_deny_removed_validated_group_escalation", archive_dir, out_dir, REPO_ROOT)
    gate_result = load_json(out_dir / "gate_result.json")
    assert result["success"] is False
    assert gate_result["promotion_blocked"] is True
    assert any(defect["defect_class"] == "dishonest_degradation" for defect in gate_result["defects"])


def _make_env17_archive(tmp_path: Path, name: str, *, include_scp_block: bool = False) -> Path:
    archive_dir = tmp_path / name
    collect_dir = archive_dir / "collect"
    collect_dir.mkdir(parents=True)
    source = "arn:aws:iam::123456789012:user/iamscope-test/env17-alice"
    target = "arn:aws:iam::123456789012:role/iamscope-test/env17-admin"
    run_log = "\n".join(
        [
            "Resources deployed:",
            f"  alice_arn  : {source}",
            f"  admin_arn  : {target}",
            "  account_id : 123456789012",
            "scenario validation: PASS",
            "benchmark semantic assertion: PASS",
        ]
    )
    (archive_dir / "run.log").write_text(run_log + "\n")
    (archive_dir / "scenario_validate.txt").write_text("Validation PASSED - scenario.json is structurally valid.\n")
    scenario = {
        "nodes": [],
        "edges": [
            {
                "edge_id": "permission-edge-1",
                "edge_type": "sts:AssumeRole_permission",
                "src": {"provider_id": source},
                "dst": {"provider_id": target},
            },
            {
                "edge_id": "trust-edge-1",
                "edge_type": "sts:AssumeRole_trust",
                "src": {"provider_id": source},
                "dst": {"provider_id": target},
            },
        ],
        "constraints": [],
        "edge_constraints": [],
    }
    if include_scp_block:
        scenario["constraints"] = [
            {
                "constraint_id": "scp-constraint-1",
                "constraint_type": "SCP",
                "properties": {"condition_keys": ["sts:AssumeRole"]},
            }
        ]
        scenario["edge_constraints"] = [{"edge_id": "trust-edge-1", "constraint_id": "scp-constraint-1"}]
    _write_json(collect_dir / "scenario.json", scenario)
    finding = {
        "pattern_id": "admin_reachability",
        "verdict": "blocked" if include_scp_block else "validated",
        "source": {"provider_id": source},
        "target": {"provider_id": target},
        "blockers_observed": [
            {
                "kind": "scp",
                "constraint_id": "scp-constraint-1",
                "edge_id": "trust-edge-1",
            }
        ]
        if include_scp_block
        else [],
    }
    _write_json(collect_dir / "findings.json", {"findings": [finding]})
    _write_json(collect_dir / "binding_metadata.json", {"bindings": []})
    _write_json(archive_dir / "expected_findings.json", {"environment": "env17_env13_scp_removed"})
    return archive_dir


def test_env17_evaluation_succeeds_with_scp_removed(tmp_path: Path) -> None:
    archive_dir = _make_env17_archive(tmp_path, "iamscope-benchmark-env17-20260429T020000Z")
    out_dir = tmp_path / "env17-evaluation"
    result = evaluate_archive("env17_scp_removed_validated_admin", archive_dir, out_dir, REPO_ROOT)
    assert result["success"] is True
    assert (out_dir / "run_manifest.json").exists()
    assert (out_dir / "scorer_result.json").exists()
    assert (out_dir / "gate_result.json").exists()
    assert (out_dir / "report.md").exists()


def test_env17_evaluation_fails_if_scp_still_blocks(tmp_path: Path) -> None:
    archive_dir = _make_env17_archive(
        tmp_path,
        "iamscope-benchmark-env17-20260429T020001Z",
        include_scp_block=True,
    )
    out_dir = tmp_path / "env17-scp-still-present"
    result = evaluate_archive("env17_scp_removed_validated_admin", archive_dir, out_dir, REPO_ROOT)
    gate_result = load_json(out_dir / "gate_result.json")
    assert result["success"] is False
    assert gate_result["promotion_blocked"] is True
    assert any(defect["defect_class"] == "dishonest_degradation" for defect in gate_result["defects"])


def _make_env07_archive(tmp_path: Path, name: str, *, include_permission_edge: bool = True) -> Path:
    archive_dir = tmp_path / name
    collect_dir = archive_dir / "collect"
    collect_dir.mkdir(parents=True)
    run_log = "\n".join(
        [
            "Resources deployed:",
            "  alice_arn  : arn:aws:iam::123456789012:user/iamscope-test/env07-alice",
            "  reader_arn : arn:aws:iam::123456789012:role/iamscope-test/env07-reader",
            "  account_id : 123456789012",
            "scenario validation: PASS",
            "benchmark semantic assertion: PASS",
        ]
    )
    (archive_dir / "run.log").write_text(run_log + "\n")
    (archive_dir / "scenario_validate.txt").write_text("Validation PASSED - scenario.json is structurally valid.\n")
    edges = [
        {
            "edge_type": "sts:AssumeRole_trust",
            "src": {"provider_id": "arn:aws:iam::123456789012:user/iamscope-test/env07-alice"},
            "dst": {"provider_id": "arn:aws:iam::123456789012:role/iamscope-test/env07-reader"},
        }
    ]
    if include_permission_edge:
        edges.append(
            {
                "edge_type": "sts:AssumeRole_permission",
                "src": {"provider_id": "arn:aws:iam::123456789012:user/iamscope-test/env07-alice"},
                "dst": {"provider_id": "arn:aws:iam::123456789012:role/iamscope-test/env07-reader"},
            }
        )
    _write_json(collect_dir / "scenario.json", {"nodes": [], "edges": edges, "constraints": []})
    _write_json(collect_dir / "findings.json", {"findings": []})
    _write_json(collect_dir / "binding_metadata.json", {"bindings": []})
    _write_json(archive_dir / "expected_findings.json", {"environment": "env07_ar_validated_non_admin"})
    return archive_dir


def test_env07_evaluation_succeeds_with_structural_assertions(tmp_path: Path) -> None:
    archive_dir = _make_env07_archive(tmp_path, "iamscope-benchmark-env07-20260424T222444Z")
    out_dir = tmp_path / "env07-evaluation"
    result = evaluate_archive("env07_validated_non_admin_reachability", archive_dir, out_dir, REPO_ROOT)
    assert result["success"] is True
    assert (out_dir / "run_manifest.json").exists()
    assert (out_dir / "scorer_result.json").exists()
    assert (out_dir / "gate_result.json").exists()
    assert (out_dir / "report.md").exists()


def test_env07_evaluation_fails_when_required_edge_missing(tmp_path: Path) -> None:
    archive_dir = _make_env07_archive(
        tmp_path,
        "iamscope-benchmark-env07-20260424T222445Z",
        include_permission_edge=False,
    )
    out_dir = tmp_path / "env07-blocked"
    result = evaluate_archive("env07_validated_non_admin_reachability", archive_dir, out_dir, REPO_ROOT)
    gate_result = load_json(out_dir / "gate_result.json")
    assert result["success"] is False
    assert gate_result["promotion_blocked"] is True
    assert any(defect["defect_class"] == "semantic_mismatch" for defect in gate_result["defects"])


def _make_env08_archive(
    tmp_path: Path, name: str, *, include_binding: bool = True, false_validated: bool = False
) -> Path:
    archive_dir = tmp_path / name
    collect_dir = archive_dir / "collect"
    collect_dir.mkdir(parents=True)
    run_log = "\n".join(
        [
            "Resources deployed:",
            "  alice_arn            : arn:aws:iam::123456789012:user/iamscope-test/env08-alice",
            "  conditioned_admin_arn: arn:aws:iam::123456789012:role/iamscope-test/env08-conditioned-admin",
            "  account_id           : 123456789012",
            "scenario validation: PASS",
            "benchmark semantic assertion: PASS",
        ]
    )
    (archive_dir / "run.log").write_text(run_log + "\n")
    (archive_dir / "scenario_validate.txt").write_text("Validation PASSED - scenario.json is structurally valid.\n")
    scenario_doc = {
        "nodes": [],
        "edges": [
            {
                "edge_id": "e1",
                "edge_type": "sts:AssumeRole_permission",
                "src": {"provider_id": "arn:aws:iam::123456789012:user/iamscope-test/env08-alice"},
                "dst": {"provider_id": "arn:aws:iam::123456789012:role/iamscope-test/env08-conditioned-admin"},
            },
            {
                "edge_id": "e2",
                "edge_type": "sts:AssumeRole_trust",
                "src": {"provider_id": "arn:aws:iam::123456789012:user/iamscope-test/env08-alice"},
                "dst": {"provider_id": "arn:aws:iam::123456789012:role/iamscope-test/env08-conditioned-admin"},
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
        "edge_constraints": [{"edge_id": "e2", "constraint_id": "c1"}] if include_binding else [],
    }
    _write_json(collect_dir / "scenario.json", scenario_doc)
    findings = [
        {
            "pattern_id": "admin_reachability",
            "verdict": "validated" if false_validated else "inconclusive",
            "source": {"provider_id": "arn:aws:iam::123456789012:user/iamscope-test/env08-alice"},
            "target": {"provider_id": "arn:aws:iam::123456789012:role/iamscope-test/env08-conditioned-admin"},
            "blockers_observed": [],
            "required_checks": [],
        }
    ]
    _write_json(collect_dir / "findings.json", {"findings": findings})
    _write_json(collect_dir / "binding_metadata.json", {"bindings": []})
    _write_json(archive_dir / "expected_findings.json", {"environment": "env08_trust_condition_blocked_admin"})
    return archive_dir


def test_env08_evaluation_succeeds_with_structural_constraint_assertions(tmp_path: Path) -> None:
    archive_dir = _make_env08_archive(tmp_path, "iamscope-benchmark-env08-20260425T002835Z")
    out_dir = tmp_path / "env08-evaluation"
    result = evaluate_archive("env08_trust_condition_blocked_admin", archive_dir, out_dir, REPO_ROOT)
    assert result["success"] is True
    assert (out_dir / "run_manifest.json").exists()
    assert (out_dir / "scorer_result.json").exists()
    assert (out_dir / "gate_result.json").exists()
    assert (out_dir / "report.md").exists()


def test_env08_evaluation_fails_when_trust_condition_binding_missing(tmp_path: Path) -> None:
    archive_dir = _make_env08_archive(
        tmp_path,
        "iamscope-benchmark-env08-20260425T002836Z",
        include_binding=False,
    )
    out_dir = tmp_path / "env08-blocked"
    result = evaluate_archive("env08_trust_condition_blocked_admin", archive_dir, out_dir, REPO_ROOT)
    gate_result = load_json(out_dir / "gate_result.json")
    assert result["success"] is False
    assert gate_result["promotion_blocked"] is True
    assert any(defect["defect_class"] == "semantic_mismatch" for defect in gate_result["defects"])


def _make_env10_archive(tmp_path: Path, name: str) -> Path:
    archive_dir = tmp_path / name
    collect_dir = archive_dir / "collect"
    collect_dir.mkdir(parents=True)
    run_log = "\n".join(
        [
            "Resources deployed:",
            "  alice_arn  : arn:aws:iam::123456789012:user/iamscope-test/env10-alice",
            "  admin_arn  : arn:aws:iam::123456789012:role/iamscope-test/env10-admin",
            "  account_id : 123456789012",
            "scenario validation: PASS",
            "benchmark semantic assertion: PASS",
        ]
    )
    (archive_dir / "run.log").write_text(run_log + "\n")
    (archive_dir / "scenario_validate.txt").write_text("Validation PASSED - scenario.json is structurally valid.\n")
    scenario_doc = {
        "nodes": [],
        "edges": [
            {
                "edge_id": "e1",
                "edge_type": "sts:AssumeRole_permission",
                "src": {"provider_id": "arn:aws:iam::123456789012:user/iamscope-test/env10-alice"},
                "dst": {"provider_id": "arn:aws:iam::123456789012:role/iamscope-test/env10-admin"},
            },
            {
                "edge_id": "e2",
                "edge_type": "sts:AssumeRole_trust",
                "src": {"provider_id": "arn:aws:iam::123456789012:user/iamscope-test/env10-alice"},
                "dst": {"provider_id": "arn:aws:iam::123456789012:role/iamscope-test/env10-admin"},
            },
        ],
        "constraints": [],
        "edge_constraints": [],
    }
    _write_json(collect_dir / "scenario.json", scenario_doc)
    findings = [
        {
            "pattern_id": "admin_reachability",
            "verdict": "validated",
            "source": {"provider_id": "arn:aws:iam::123456789012:user/iamscope-test/env10-alice"},
            "target": {"provider_id": "arn:aws:iam::123456789012:role/iamscope-test/env10-admin"},
            "blockers_observed": [],
            "required_checks": [],
        }
    ]
    _write_json(collect_dir / "findings.json", {"findings": findings})
    _write_json(collect_dir / "binding_metadata.json", {"bindings": []})
    _write_json(archive_dir / "expected_findings.json", {"environment": "env10_env08_trust_condition_removed"})
    return archive_dir


def test_env10_evaluation_succeeds_with_condition_removed_mutation(tmp_path: Path) -> None:
    archive_dir = _make_env10_archive(tmp_path, "iamscope-benchmark-env10-20260425T020000Z")
    out_dir = tmp_path / "env10-evaluation"
    result = evaluate_archive("env10_trust_condition_removed_validated_admin", archive_dir, out_dir, REPO_ROOT)
    assert result["success"] is True
    assert (out_dir / "run_manifest.json").exists()
    assert (out_dir / "scorer_result.json").exists()
    assert (out_dir / "gate_result.json").exists()
    assert (out_dir / "report.md").exists()


def _make_env11_archive(tmp_path: Path, name: str) -> Path:
    archive_dir = tmp_path / name
    collect_dir = archive_dir / "collect"
    collect_dir.mkdir(parents=True)
    run_log = "\n".join(
        [
            "Resources deployed:",
            "  alice_arn                  : arn:aws:iam::123456789012:user/iamscope-test/env11-alice",
            "  broad_conditioned_admin_arn: arn:aws:iam::123456789012:role/iamscope-test/env11-broad-conditioned-admin",
            "  root_arn                   : arn:aws:iam::123456789012:root",
            "  account_id                 : 123456789012",
            "scenario validation: PASS",
            "benchmark semantic assertion: PASS",
        ]
    )
    (archive_dir / "run.log").write_text(run_log + "\n")
    (archive_dir / "scenario_validate.txt").write_text("Validation PASSED - scenario.json is structurally valid.\n")
    scenario_doc = {
        "nodes": [],
        "edges": [
            {
                "edge_id": "e1",
                "edge_type": "sts:AssumeRole_permission",
                "src": {"provider_id": "arn:aws:iam::123456789012:user/iamscope-test/env11-alice"},
                "dst": {"provider_id": "arn:aws:iam::123456789012:role/iamscope-test/env11-broad-conditioned-admin"},
            },
            {
                "edge_id": "e2",
                "edge_type": "sts:AssumeRole_trust",
                "src": {"provider_id": "arn:aws:iam::123456789012:root"},
                "dst": {"provider_id": "arn:aws:iam::123456789012:role/iamscope-test/env11-broad-conditioned-admin"},
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
    }
    _write_json(collect_dir / "scenario.json", scenario_doc)
    _write_json(collect_dir / "findings.json", {"findings": []})
    _write_json(collect_dir / "binding_metadata.json", {"bindings": []})
    _write_json(archive_dir / "expected_findings.json", {"environment": "env11_broad_trust_condition_blocked_admin"})
    return archive_dir


def test_env11_evaluation_succeeds_with_broad_conditioned_trust(tmp_path: Path) -> None:
    archive_dir = _make_env11_archive(tmp_path, "iamscope-benchmark-env11-20260425T030000Z")
    out_dir = tmp_path / "env11-evaluation"
    result = evaluate_archive("env11_broad_trust_condition_blocked_admin", archive_dir, out_dir, REPO_ROOT)
    assert result["success"] is True
    assert (out_dir / "run_manifest.json").exists()
    assert (out_dir / "scorer_result.json").exists()
    assert (out_dir / "gate_result.json").exists()
    assert (out_dir / "report.md").exists()


def _make_env12_archive(tmp_path: Path, name: str) -> Path:
    archive_dir = tmp_path / name
    collect_dir = archive_dir / "collect"
    collect_dir.mkdir(parents=True)
    run_log = "\n".join(
        [
            "Resources deployed:",
            "  management_account_id : 516525145310",
            "  member_account_id     : 377114445031",
            "  alice_arn             : arn:aws:iam::377114445031:user/iamscope-test/env12-alice",
            "  admin_arn             : arn:aws:iam::377114445031:role/iamscope-test/env12-admin",
            "  scp_policy_id         : p-env12",
            "scenario validation: PASS",
            "benchmark semantic assertion: PASS",
        ]
    )
    (archive_dir / "run.log").write_text(run_log + "\n")
    (archive_dir / "scenario_validate.txt").write_text("Validation PASSED - scenario.json is structurally valid.\n")
    scenario_doc = {
        "nodes": [],
        "edges": [
            {
                "edge_id": "e1",
                "edge_type": "sts:AssumeRole_permission",
                "src": {"provider_id": "arn:aws:iam::377114445031:user/iamscope-test/env12-alice"},
                "dst": {"provider_id": "arn:aws:iam::377114445031:role/iamscope-test/env12-admin"},
            },
            {
                "edge_id": "e2",
                "edge_type": "sts:AssumeRole_trust",
                "src": {"provider_id": "arn:aws:iam::377114445031:user/iamscope-test/env12-alice"},
                "dst": {"provider_id": "arn:aws:iam::377114445031:role/iamscope-test/env12-admin"},
            },
        ],
        "constraints": [
            {
                "constraint_id": "c-scp",
                "constraint_type": "SCP",
                "properties": {
                    "deny_actions": ["sts:AssumeRole"],
                    "parse_status": "complete",
                    "resource_patterns": ["*"],
                },
            }
        ],
        "edge_constraints": [{"edge_id": "e2", "constraint_id": "c-scp"}],
    }
    _write_json(collect_dir / "scenario.json", scenario_doc)
    _write_json(collect_dir / "findings.json", {"findings": []})
    _write_json(
        collect_dir / "binding_metadata.json",
        {
            "bindings": [
                {
                    "edge_id": "e2",
                    "constraint_id": "c-scp",
                    "binding_metadata": {
                        "governance_confidence": "complete",
                        "likely_blocking": True,
                        "binding_reason": "edge action sts:AssumeRole in SCP deny_actions",
                    },
                }
            ]
        },
    )
    _write_json(archive_dir / "expected_findings.json", {"environment": "env12_scp_blocked_assumerole"})
    return archive_dir


def test_env12_evaluation_succeeds_with_scp_blocked_assumerole(tmp_path: Path) -> None:
    archive_dir = _make_env12_archive(tmp_path, "iamscope-benchmark-env12-20260425T040000Z")
    out_dir = tmp_path / "env12-evaluation"
    result = evaluate_archive("env12_scp_blocked_assumerole", archive_dir, out_dir, REPO_ROOT)
    assert result["success"] is True
    assert (out_dir / "run_manifest.json").exists()
    assert (out_dir / "scorer_result.json").exists()
    assert (out_dir / "gate_result.json").exists()
    assert (out_dir / "report.md").exists()


def _make_env15_archive(tmp_path: Path, name: str, *, include_condition: bool = False) -> Path:
    archive_dir = tmp_path / name
    collect_dir = archive_dir / "collect"
    collect_dir.mkdir(parents=True)
    run_log = "\n".join(
        [
            "Resources deployed:",
            "  alice_arn  : arn:aws:iam::123456789012:user/iamscope-test/env15-alice",
            "  admin_arn  : arn:aws:iam::123456789012:role/iamscope-test/env15-admin",
            "  account_id : 123456789012",
            "scenario validation: PASS",
            "benchmark semantic assertion: PASS",
        ]
    )
    (archive_dir / "run.log").write_text(run_log + "\n")
    (archive_dir / "scenario_validate.txt").write_text("Validation PASSED - scenario.json is structurally valid.\n")
    permission_features = {"has_conditions": False, "raw_conditions": {}}
    if include_condition:
        permission_features = {
            "has_conditions": True,
            "raw_conditions": {"Bool": {"aws:MultiFactorAuthPresent": "true"}},
        }
    scenario_doc = {
        "nodes": [],
        "edges": [
            {
                "edge_id": "e1",
                "edge_type": "sts:AssumeRole_permission",
                "src": {"provider_id": "arn:aws:iam::123456789012:user/iamscope-test/env15-alice"},
                "dst": {"provider_id": "arn:aws:iam::123456789012:role/iamscope-test/env15-admin"},
                "features": permission_features,
            },
            {
                "edge_id": "e2",
                "edge_type": "sts:AssumeRole_trust",
                "src": {"provider_id": "arn:aws:iam::123456789012:user/iamscope-test/env15-alice"},
                "dst": {"provider_id": "arn:aws:iam::123456789012:role/iamscope-test/env15-admin"},
                "features": {"has_conditions": False, "raw_conditions": {}},
            },
        ],
        "constraints": [],
        "edge_constraints": [],
    }
    _write_json(collect_dir / "scenario.json", scenario_doc)
    findings = [
        {
            "pattern_id": "admin_reachability",
            "verdict": "validated",
            "source": {"provider_id": "arn:aws:iam::123456789012:user/iamscope-test/env15-alice"},
            "target": {"provider_id": "arn:aws:iam::123456789012:role/iamscope-test/env15-admin"},
            "blockers_observed": [],
            "required_checks": [],
        }
    ]
    _write_json(collect_dir / "findings.json", {"findings": findings})
    _write_json(collect_dir / "binding_metadata.json", {"bindings": []})
    _write_json(archive_dir / "expected_findings.json", {"environment": "env15_env14_permission_condition_removed"})
    return archive_dir


def test_env15_evaluation_succeeds_with_permission_condition_removed(tmp_path: Path) -> None:
    archive_dir = _make_env15_archive(tmp_path, "iamscope-benchmark-env15-20260428T220000Z")
    out_dir = tmp_path / "env15-evaluation"
    result = evaluate_archive("env15_permission_condition_removed_validated_admin", archive_dir, out_dir, REPO_ROOT)
    assert result["success"] is True
    assert (out_dir / "run_manifest.json").exists()
    assert (out_dir / "scorer_result.json").exists()
    assert (out_dir / "gate_result.json").exists()
    assert (out_dir / "report.md").exists()


def test_env15_evaluation_fails_if_permission_condition_remains(tmp_path: Path) -> None:
    archive_dir = _make_env15_archive(
        tmp_path,
        "iamscope-benchmark-env15-20260428T220001Z",
        include_condition=True,
    )
    out_dir = tmp_path / "env15-condition-still-present"
    result = evaluate_archive("env15_permission_condition_removed_validated_admin", archive_dir, out_dir, REPO_ROOT)
    gate_result = load_json(out_dir / "gate_result.json")
    assert result["success"] is False
    assert gate_result["promotion_blocked"] is True
    assert any(defect["defect_class"] == "semantic_mismatch" for defect in gate_result["defects"])


def _make_env18_archive(tmp_path: Path, name: str, *, include_validated: bool = True) -> Path:
    archive_dir = tmp_path / name
    collect_dir = archive_dir / "collect"
    collect_dir.mkdir(parents=True)
    source = "arn:aws:iam::123456789012:user/iamscope-test/env18-alice"
    target = "arn:aws:iam::123456789012:role/iamscope-test/env18-lambda-admin-exec"
    run_log = "\n".join(
        [
            "Resources deployed:",
            f"  alice_arn             : {source}",
            f"  lambda_admin_role_arn : {target}",
            "  lambda_function_arn   : arn:aws:lambda:us-east-1:123456789012:function:env18-passrole-probe",
            "  account_id            : 123456789012",
            "scenario validation: PASS",
            "benchmark semantic assertion: PASS",
        ]
    )
    (archive_dir / "run.log").write_text(run_log + "\n")
    (archive_dir / "scenario_validate.txt").write_text("Validation PASSED - scenario.json is structurally valid.\n")
    scenario_doc = {
        "nodes": [],
        "edges": [
            {
                "edge_id": "lambda-create-edge-1",
                "edge_type": "lambda:CreateFunction_permission",
                "src": {"provider_id": source},
                "dst": {"provider_id": "arn:aws:lambda:us-east-1:123456789012:function:env18-passrole-probe"},
                "features": {"has_conditions": False, "raw_conditions": {}},
            },
            {
                "edge_id": "passrole-edge-1",
                "edge_type": "iam:PassRole_permission",
                "src": {"provider_id": source},
                "dst": {"provider_id": target},
                "features": {"has_conditions": False, "raw_conditions": {}},
            },
            {
                "edge_id": "lambda-trust-edge-1",
                "edge_type": "sts:AssumeRole_trust",
                "src": {"provider_id": "lambda.amazonaws.com"},
                "dst": {"provider_id": target},
                "features": {"has_conditions": False, "raw_conditions": {}},
            },
        ],
        "constraints": [],
        "edge_constraints": [],
    }
    _write_json(collect_dir / "scenario.json", scenario_doc)
    finding = {
        "pattern_id": "passrole_lambda",
        "verdict": "validated" if include_validated else "inconclusive",
        "severity": "critical" if include_validated else "high",
        "source": {"provider_id": source},
        "target": {"provider_id": target},
        "blockers_observed": [],
        "required_checks": [
            {"name": "source_has_lambda_create_function", "state": "pass"},
            {"name": "source_has_passrole_to_target", "state": "pass"},
            {"name": "target_trusts_lambda_service", "state": "pass"},
        ],
    }
    _write_json(collect_dir / "findings.json", {"findings": [finding]})
    _write_json(collect_dir / "binding_metadata.json", {"bindings": []})
    _write_json(archive_dir / "expected_findings.json", {"environment": "env18_lambda_passrole_validated"})
    return archive_dir


def test_env18_evaluation_succeeds_with_validated_lambda_passrole(tmp_path: Path) -> None:
    archive_dir = _make_env18_archive(tmp_path, "iamscope-benchmark-env18-20260429T030000Z")
    out_dir = tmp_path / "env18-evaluation"
    result = evaluate_archive("env18_lambda_passrole_validated", archive_dir, out_dir, REPO_ROOT)
    assert result["success"] is True
    assert (out_dir / "run_manifest.json").exists()
    assert (out_dir / "scorer_result.json").exists()
    assert (out_dir / "gate_result.json").exists()
    assert (out_dir / "report.md").exists()


def test_env18_evaluation_fails_without_validated_passrole(tmp_path: Path) -> None:
    archive_dir = _make_env18_archive(
        tmp_path,
        "iamscope-benchmark-env18-20260429T030001Z",
        include_validated=False,
    )
    out_dir = tmp_path / "env18-not-validated"
    result = evaluate_archive("env18_lambda_passrole_validated", archive_dir, out_dir, REPO_ROOT)
    gate_result = load_json(out_dir / "gate_result.json")
    assert result["success"] is False
    assert gate_result["promotion_blocked"] is True
    assert any(defect["defect_class"] == "dishonest_degradation" for defect in gate_result["defects"])


def _make_env19_archive(tmp_path: Path, name: str, *, include_validated: bool = False) -> Path:
    archive_dir = tmp_path / name
    collect_dir = archive_dir / "collect"
    collect_dir.mkdir(parents=True)
    source = "arn:aws:iam::123456789012:user/iamscope-test/env19-alice"
    target = "arn:aws:iam::123456789012:role/iamscope-test/env19-lambda-admin-exec"
    run_log = "\n".join(
        [
            "Resources deployed:",
            f"  alice_arn             : {source}",
            f"  lambda_admin_role_arn : {target}",
            "  lambda_function_arn   : arn:aws:lambda:us-east-1:123456789012:function:env19-passrole-probe",
            "  account_id            : 123456789012",
            "scenario validation: PASS",
            "benchmark semantic assertion: PASS",
        ]
    )
    (archive_dir / "run.log").write_text(run_log + "\n")
    (archive_dir / "scenario_validate.txt").write_text("Validation PASSED - scenario.json is structurally valid.\n")
    scenario_doc = {
        "nodes": [],
        "edges": [
            {
                "edge_id": "lambda-create-edge-1",
                "edge_type": "lambda:CreateFunction_permission",
                "src": {"provider_id": source},
                "dst": {"provider_id": "arn:aws:lambda:us-east-1:123456789012:function:env19-passrole-probe"},
                "features": {"has_conditions": False, "raw_conditions": {}},
            },
            {
                "edge_id": "passrole-edge-1",
                "edge_type": "iam:PassRole_permission",
                "src": {"provider_id": source},
                "dst": {"provider_id": target},
                "features": {
                    "has_conditions": True,
                    "raw_conditions": {"StringEquals": {"iam:PassedToService": "ec2.amazonaws.com"}},
                },
            },
            {
                "edge_id": "lambda-trust-edge-1",
                "edge_type": "sts:AssumeRole_trust",
                "src": {"provider_id": "lambda.amazonaws.com"},
                "dst": {"provider_id": target},
                "features": {"has_conditions": False, "raw_conditions": {}},
            },
        ],
        "constraints": [],
        "edge_constraints": [],
    }
    _write_json(collect_dir / "scenario.json", scenario_doc)
    finding = {
        "pattern_id": "passrole_lambda",
        "verdict": "validated" if include_validated else "precondition_only",
        "severity": "critical" if include_validated else "medium",
        "source": {"provider_id": source},
        "target": {"provider_id": target},
        "blockers_observed": []
        if include_validated
        else [
            {
                "kind": "passed_to_service",
                "constraint_id": None,
                "edge_id": "passrole-edge-1",
            }
        ],
        "required_checks": [
            {"name": "source_has_lambda_create_function", "state": "pass"},
            {"name": "source_has_passrole_to_target", "state": "pass"},
            {"name": "target_trusts_lambda_service", "state": "pass"},
            {
                "name": "passrole_condition_scoped_to_lambda_or_absent",
                "state": "pass" if include_validated else "fail",
            },
        ],
    }
    _write_json(collect_dir / "findings.json", {"findings": [finding]})
    _write_json(collect_dir / "binding_metadata.json", {"bindings": []})
    _write_json(archive_dir / "expected_findings.json", {"environment": "env19_env18_passedtoservice_scoped_away"})
    return archive_dir


def test_env19_evaluation_succeeds_with_passedtoservice_scoped_away(tmp_path: Path) -> None:
    archive_dir = _make_env19_archive(tmp_path, "iamscope-benchmark-env19-20260429T040000Z")
    out_dir = tmp_path / "env19-evaluation"
    result = evaluate_archive("env19_passedtoservice_scoped_away_nonvalidated", archive_dir, out_dir, REPO_ROOT)
    assert result["success"] is True
    assert (out_dir / "run_manifest.json").exists()
    assert (out_dir / "scorer_result.json").exists()
    assert (out_dir / "gate_result.json").exists()
    assert (out_dir / "report.md").exists()


def test_env19_evaluation_fails_if_passrole_validates(tmp_path: Path) -> None:
    archive_dir = _make_env19_archive(
        tmp_path,
        "iamscope-benchmark-env19-20260429T040001Z",
        include_validated=True,
    )
    out_dir = tmp_path / "env19-false-positive"
    result = evaluate_archive("env19_passedtoservice_scoped_away_nonvalidated", archive_dir, out_dir, REPO_ROOT)
    gate_result = load_json(out_dir / "gate_result.json")
    assert result["success"] is False
    assert gate_result["promotion_blocked"] is True
    assert any(defect["defect_class"] == "false_admin_claim" for defect in gate_result["defects"])


def _make_env20_archive(
    tmp_path: Path,
    name: str,
    *,
    include_validated: bool = True,
    wildcard_ecs_evidence: bool = False,
) -> Path:
    archive_dir = tmp_path / name
    collect_dir = archive_dir / "collect"
    collect_dir.mkdir(parents=True)
    source = "arn:aws:iam::123456789012:user/iamscope-test/env20-alice"
    target = "arn:aws:iam::123456789012:role/iamscope-test/env20-ecs-admin-task"
    task_definition = "arn:aws:ecs:us-east-1:123456789012:task-definition/env20-passrole-probe:1"
    run_log = "\n".join(
        [
            "Resources deployed:",
            f"  alice_arn              : {source}",
            f"  ecs_admin_role_arn     : {target}",
            f"  ecs_task_definition_arn: {task_definition}",
            "  account_id             : 123456789012",
            "scenario validation: PASS",
            "benchmark semantic assertion: PASS",
        ]
    )
    (archive_dir / "run.log").write_text(run_log + "\n")
    (archive_dir / "scenario_validate.txt").write_text("Validation PASSED - scenario.json is structurally valid.\n")
    scenario_doc = {
        "nodes": [],
        "edges": [
            {
                "edge_id": "ecs-register-edge-1",
                "edge_type": "ecs:RegisterTaskDefinition_permission",
                "src": {"provider_id": source},
                "dst": {"provider_id": task_definition},
                "features": {
                    "has_conditions": False,
                    "raw_conditions": {},
                    "is_wildcard_resource": wildcard_ecs_evidence,
                },
            },
            {
                "edge_id": "ecs-run-edge-1",
                "edge_type": "ecs:RunTask_permission",
                "src": {"provider_id": source},
                "dst": {"provider_id": task_definition},
                "features": {
                    "has_conditions": False,
                    "raw_conditions": {},
                    "is_wildcard_resource": wildcard_ecs_evidence,
                },
            },
            {
                "edge_id": "passrole-edge-1",
                "edge_type": "iam:PassRole_permission",
                "src": {"provider_id": source},
                "dst": {"provider_id": target},
                "features": {"has_conditions": False, "raw_conditions": {}, "is_wildcard_resource": False},
            },
            {
                "edge_id": "ecs-trust-edge-1",
                "edge_type": "sts:AssumeRole_trust",
                "src": {"provider_id": "ecs-tasks.amazonaws.com"},
                "dst": {"provider_id": target},
                "features": {"has_conditions": False, "raw_conditions": {}},
            },
        ],
        "constraints": [],
        "edge_constraints": [],
    }
    _write_json(collect_dir / "scenario.json", scenario_doc)
    finding = {
        "pattern_id": "passrole_ecs",
        "verdict": "validated" if include_validated else "inconclusive",
        "severity": "critical" if include_validated else "high",
        "source": {"provider_id": source},
        "target": {"provider_id": target},
        "blockers_observed": [],
        "required_checks": [
            {"name": "source_has_ecs_create_and_run_permissions", "state": "pass"},
            {"name": "source_has_passrole_to_target", "state": "pass"},
            {"name": "target_trusts_ecs_tasks_service", "state": "pass"},
            {"name": "passrole_condition_scoped_to_ecs_or_absent", "state": "pass"},
        ],
    }
    _write_json(collect_dir / "findings.json", {"findings": [finding]})
    _write_json(collect_dir / "binding_metadata.json", {"bindings": []})
    _write_json(archive_dir / "expected_findings.json", {"environment": "env20_ecs_passrole_validated"})
    return archive_dir


def test_env20_evaluation_succeeds_with_validated_ecs_passrole(tmp_path: Path) -> None:
    archive_dir = _make_env20_archive(tmp_path, "iamscope-benchmark-env20-20260429T050000Z")
    out_dir = tmp_path / "env20-evaluation"
    result = evaluate_archive("env20_ecs_passrole_validated", archive_dir, out_dir, REPO_ROOT)
    assert result["success"] is True
    assert (out_dir / "run_manifest.json").exists()
    assert (out_dir / "scorer_result.json").exists()
    assert (out_dir / "gate_result.json").exists()
    assert (out_dir / "report.md").exists()


def test_env20_evaluation_fails_without_validated_passrole(tmp_path: Path) -> None:
    archive_dir = _make_env20_archive(
        tmp_path,
        "iamscope-benchmark-env20-20260429T050001Z",
        include_validated=False,
    )
    out_dir = tmp_path / "env20-not-validated"
    result = evaluate_archive("env20_ecs_passrole_validated", archive_dir, out_dir, REPO_ROOT)
    gate_result = load_json(out_dir / "gate_result.json")
    assert result["success"] is False
    assert gate_result["promotion_blocked"] is True
    assert any(defect["defect_class"] == "dishonest_degradation" for defect in gate_result["defects"])


def test_env20_evaluation_fails_with_wildcard_ecs_action_evidence(tmp_path: Path) -> None:
    archive_dir = _make_env20_archive(
        tmp_path,
        "iamscope-benchmark-env20-20260429T050002Z",
        wildcard_ecs_evidence=True,
    )
    out_dir = tmp_path / "env20-wildcard-ecs-evidence"
    result = evaluate_archive("env20_ecs_passrole_validated", archive_dir, out_dir, REPO_ROOT)
    gate_result = load_json(out_dir / "gate_result.json")
    assert result["success"] is False
    assert gate_result["promotion_blocked"] is True
    assert any(defect["defect_class"] == "semantic_mismatch" for defect in gate_result["defects"])


def _make_env21_archive(
    tmp_path: Path,
    name: str,
    *,
    include_validated: bool = False,
    include_condition: bool = True,
    condition_value: str = "ec2.amazonaws.com",
) -> Path:
    archive_dir = tmp_path / name
    collect_dir = archive_dir / "collect"
    collect_dir.mkdir(parents=True)
    source = "arn:aws:iam::123456789012:user/iamscope-test/env21-alice"
    target = "arn:aws:iam::123456789012:role/iamscope-test/env21-ecs-admin-task"
    task_definition = "arn:aws:ecs:us-east-1:123456789012:task-definition/env21-passrole-probe:1"
    run_log = "\n".join(
        [
            "Resources deployed:",
            f"  alice_arn              : {source}",
            f"  ecs_admin_role_arn     : {target}",
            f"  ecs_task_definition_arn: {task_definition}",
            "  account_id             : 123456789012",
            "scenario validation: PASS",
            "benchmark semantic assertion: PASS",
        ]
    )
    (archive_dir / "run.log").write_text(run_log + "\n")
    (archive_dir / "scenario_validate.txt").write_text("Validation PASSED - scenario.json is structurally valid.\n")
    passrole_conditions = {"StringEquals": {"iam:PassedToService": condition_value}} if include_condition else {}
    scenario_doc = {
        "nodes": [],
        "edges": [
            {
                "edge_id": "ecs-register-edge-1",
                "edge_type": "ecs:RegisterTaskDefinition_permission",
                "src": {"provider_id": source},
                "dst": {"provider_id": task_definition},
                "features": {
                    "has_conditions": False,
                    "raw_conditions": {},
                    "is_wildcard_resource": False,
                },
            },
            {
                "edge_id": "ecs-run-edge-1",
                "edge_type": "ecs:RunTask_permission",
                "src": {"provider_id": source},
                "dst": {"provider_id": task_definition},
                "features": {
                    "has_conditions": False,
                    "raw_conditions": {},
                    "is_wildcard_resource": False,
                },
            },
            {
                "edge_id": "passrole-edge-1",
                "edge_type": "iam:PassRole_permission",
                "src": {"provider_id": source},
                "dst": {"provider_id": target},
                "features": {
                    "has_conditions": include_condition,
                    "raw_conditions": passrole_conditions,
                    "is_wildcard_resource": False,
                },
            },
            {
                "edge_id": "ecs-trust-edge-1",
                "edge_type": "sts:AssumeRole_trust",
                "src": {"provider_id": "ecs-tasks.amazonaws.com"},
                "dst": {"provider_id": target},
                "features": {"has_conditions": False, "raw_conditions": {}},
            },
        ],
        "constraints": [],
        "edge_constraints": [],
    }
    _write_json(collect_dir / "scenario.json", scenario_doc)
    finding = {
        "pattern_id": "passrole_ecs",
        "verdict": "validated" if include_validated else "precondition_only",
        "severity": "critical" if include_validated else "medium",
        "source": {"provider_id": source},
        "target": {"provider_id": target},
        "blockers_observed": []
        if include_validated
        else [
            {
                "kind": "passed_to_service",
                "constraint_id": None,
                "edge_id": "passrole-edge-1",
            }
        ],
        "required_checks": [
            {"name": "source_has_ecs_create_and_run_permissions", "state": "pass"},
            {"name": "source_has_passrole_to_target", "state": "pass"},
            {"name": "target_trusts_ecs_tasks_service", "state": "pass"},
            {
                "name": "passrole_condition_scoped_to_ecs_or_absent",
                "state": "pass" if include_validated else "fail",
            },
        ],
    }
    _write_json(collect_dir / "findings.json", {"findings": [finding]})
    _write_json(collect_dir / "binding_metadata.json", {"bindings": []})
    _write_json(archive_dir / "expected_findings.json", {"environment": "env21_env20_passedtoservice_scoped_away"})
    return archive_dir


def test_env21_evaluation_succeeds_with_passedtoservice_scoped_away(tmp_path: Path) -> None:
    archive_dir = _make_env21_archive(tmp_path, "iamscope-benchmark-env21-20260429T060000Z")
    out_dir = tmp_path / "env21-evaluation"
    result = evaluate_archive("env21_ecs_passedtoservice_scoped_away_nonvalidated", archive_dir, out_dir, REPO_ROOT)
    assert result["success"] is True
    assert (out_dir / "run_manifest.json").exists()
    assert (out_dir / "scorer_result.json").exists()
    assert (out_dir / "gate_result.json").exists()
    assert (out_dir / "report.md").exists()


def test_env21_evaluation_fails_if_passrole_validates(tmp_path: Path) -> None:
    archive_dir = _make_env21_archive(
        tmp_path,
        "iamscope-benchmark-env21-20260429T060001Z",
        include_validated=True,
    )
    out_dir = tmp_path / "env21-false-positive"
    result = evaluate_archive("env21_ecs_passedtoservice_scoped_away_nonvalidated", archive_dir, out_dir, REPO_ROOT)
    gate_result = load_json(out_dir / "gate_result.json")
    assert result["success"] is False
    assert gate_result["promotion_blocked"] is True
    assert any(defect["defect_class"] == "false_admin_claim" for defect in gate_result["defects"])


def test_env21_evaluation_fails_without_passedtoservice_condition_evidence(tmp_path: Path) -> None:
    archive_dir = _make_env21_archive(
        tmp_path,
        "iamscope-benchmark-env21-20260429T060002Z",
        include_condition=False,
    )
    out_dir = tmp_path / "env21-missing-condition"
    result = evaluate_archive("env21_ecs_passedtoservice_scoped_away_nonvalidated", archive_dir, out_dir, REPO_ROOT)
    gate_result = load_json(out_dir / "gate_result.json")
    assert result["success"] is False
    assert gate_result["promotion_blocked"] is True
    assert any(defect["defect_class"] == "semantic_mismatch" for defect in gate_result["defects"])


def test_env21_evaluation_fails_with_wrong_passedtoservice_value(tmp_path: Path) -> None:
    archive_dir = _make_env21_archive(
        tmp_path,
        "iamscope-benchmark-env21-20260429T060003Z",
        condition_value="ecs-tasks.amazonaws.com",
    )
    out_dir = tmp_path / "env21-wrong-condition-value"
    result = evaluate_archive("env21_ecs_passedtoservice_scoped_away_nonvalidated", archive_dir, out_dir, REPO_ROOT)
    gate_result = load_json(out_dir / "gate_result.json")
    assert result["success"] is False
    assert gate_result["promotion_blocked"] is True
    assert any(defect["defect_class"] == "semantic_mismatch" for defect in gate_result["defects"])
