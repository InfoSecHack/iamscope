from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path
from typing import Any

from scripts.classify_real_pilot_findings import build_review_artifacts

REPO_ROOT = Path(__file__).resolve().parents[1]
SCRIPT = REPO_ROOT / "scripts" / "classify_real_pilot_findings.py"


def _account_id() -> str:
    return "1111" + "2222" + "3333"


def _iam_arn(resource: str) -> str:
    return f"arn:aws:iam::{_account_id()}:{resource}"


def _sts_arn(resource: str) -> str:
    return f"arn:aws:sts::{_account_id()}:{resource}"


def _scenario() -> dict[str, Any]:
    return {
        "nodes": [
            {"provider_id": _iam_arn("role/path/SourceWildcardTrustRole")},
            {"provider_id": _iam_arn("role/ProdDBAdminRole")},
        ],
        "edges": [
            {
                "id": "edge-trust-1",
                "src": _iam_arn("role/path/SourceWildcardTrustRole"),
                "dst": _iam_arn("role/TrustedTargetRole"),
                "action": "sts:AssumeRole",
            }
        ],
        "constraints": [{"id": "constraint-1"}],
        "edge_constraints": [{"id": "edge-constraint-1"}],
    }


def _findings() -> dict[str, Any]:
    return {
        "findings": [
            {
                "finding_id": "aaaabbbbcccc1111",
                "pattern_id": "cross_account_trust",
                "verdict": "validated",
                "severity": "high",
                "source": {"provider_id": _iam_arn("role/path/SourceWildcardTrustRole")},
                "target": {"provider_id": _iam_arn("role/TrustedTargetRole")},
                "title": f"{_iam_arn('role/path/SourceWildcardTrustRole')} trusts {_iam_arn('role/TrustedTargetRole')}",
                "evidence": {
                    "edge_refs": ["edge-trust-1"],
                    "trust_scope": "cross_account",
                    "naked_trust": True,
                    "wildcard_principal": True,
                    "has_external_id": True,
                    "has_conditions": True,
                    "principal": _sts_arn("assumed-role/ExternalReviewer/session"),
                },
                "collection_context": {
                    "scope": "partial_org",
                    "org_membership_status": "unknown",
                },
                "assumptions": [
                    {
                        "kind": "org_membership_status",
                        "detail": "source account membership is unknown in partial collection context",
                    }
                ],
                "required_checks": [{"name": "trust_policy_allows_source", "state": "pass"}],
            },
            {
                "finding_id": "ddddeeeeffff2222",
                "pattern_id": "admin_reachability",
                "verdict": "inconclusive",
                "severity": "critical",
                "source_principal_arn": _iam_arn("role/SourceAdminProbeRole"),
                "target_role_arn": _iam_arn("role/ProdDBAdminRole"),
                "title": f"{_iam_arn('role/SourceAdminProbeRole')} may reach AdministratorAccess target",
                "required_checks": [
                    {"name": "source_has_assume_role_permission", "state": "pass"},
                    {
                        "name": "at_least_one_reachable_chain_uses_clean_witnesses",
                        "state": "unknown",
                    },
                ],
                "evidence": {
                    "reachable_admins_count": 1,
                    "admin_policy_name": "AdministratorAccess",
                },
                "blockers_observed": [
                    {
                        "kind": "permission_boundary",
                        "reason": "reviewer should inspect boundary context",
                        "constraint_id": "constraint-1",
                    }
                ],
            },
            {
                "finding_id": "gggghhhhiiii3333",
                "pattern_id": "cross_account_trust",
                "verdict": "validated",
                "severity": "medium",
                "source_principal": "SpecificSourceRole",
                "target": "SpecificTargetRole",
                "title": "Specific role-to-role trust",
                "required_checks": [{"name": "trust_policy_allows_source", "state": "pass"}],
            },
        ]
    }


def _write_inputs(tmp_path: Path) -> tuple[Path, Path]:
    scenario = tmp_path / "scenario.json"
    findings = tmp_path / "findings.json"
    scenario.write_text(json.dumps(_scenario()), encoding="utf-8")
    findings.write_text(json.dumps(_findings()), encoding="utf-8")
    return scenario, findings


def _run_script(*args: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [sys.executable, str(SCRIPT), *args],
        cwd=REPO_ROOT,
        check=False,
        text=True,
        capture_output=True,
    )


def _load(path: Path) -> Any:
    return json.loads(path.read_text(encoding="utf-8"))


def _walk_keys(value: Any) -> list[str]:
    if isinstance(value, dict):
        keys: list[str] = []
        for key, item in value.items():
            keys.append(str(key))
            keys.extend(_walk_keys(item))
        return keys
    if isinstance(value, list):
        keys = []
        for item in value:
            keys.extend(_walk_keys(item))
        return keys
    return []


def test_script_refuses_output_inside_repo(tmp_path: Path) -> None:
    scenario, findings = _write_inputs(tmp_path)
    output = REPO_ROOT / "real-pilot-review-output"
    result = _run_script("--scenario", str(scenario), "--findings", str(findings), "--out", str(output))
    assert result.returncode == 1
    assert "refusing to write real-pilot review artifacts inside repository tree" in result.stderr
    assert not output.exists()


def test_no_label_run_emits_all_review_artifacts(tmp_path: Path) -> None:
    scenario, findings = _write_inputs(tmp_path)
    output = tmp_path / "review"
    result = _run_script("--scenario", str(scenario), "--findings", str(findings), "--out", str(output))
    assert result.returncode == 0, result.stderr
    assert (output / "review-table.md").exists()
    assert (output / "review-summary.json").exists()
    assert (output / "unlabeled-findings.json").exists()
    assert (output / "reviewer-label-template.json").exists()
    assert len(_load(output / "reviewer-label-template.json")["labels"]) == 3
    assert len(_load(output / "unlabeled-findings.json")["findings"]) == 3


def test_review_table_includes_capability_honesty_reminders(tmp_path: Path) -> None:
    scenario, findings = _write_inputs(tmp_path)
    output = tmp_path / "review"
    result = _run_script("--scenario", str(scenario), "--findings", str(findings), "--out", str(output))
    assert result.returncode == 0, result.stderr
    table = (output / "review-table.md").read_text(encoding="utf-8")
    assert "No findings does not mean safe" in table
    assert "Validated is not exploitability proof" in table
    assert "`collection_context` matters" in table
    assert "No composite score" in table
    assert "No pass/fail benchmark label" in table


def test_label_run_matches_by_unique_finding_id_prefix(tmp_path: Path) -> None:
    scenario, findings = _write_inputs(tmp_path)
    labels = tmp_path / "reviewer-labels.json"
    labels.write_text(
        json.dumps(
            {
                "pilot_id": "real-pilot-dev-001",
                "label_schema_version": 1,
                "labels": [
                    {
                        "finding_id_prefix": "aaaabbbbcccc",
                        "classification": "valid_path",
                        "reviewer_confidence": "high",
                        "owner_confirmed": False,
                        "notes": "Wildcard principal and ExternalId present.",
                        "recommended_followup": "Confirm whether trust is intentional.",
                        "sanitized_evidence_refs": ["ticket-123"],
                    }
                ],
            }
        ),
        encoding="utf-8",
    )
    output = tmp_path / "review"
    result = _run_script(
        "--scenario",
        str(scenario),
        "--findings",
        str(findings),
        "--labels",
        str(labels),
        "--out",
        str(output),
    )
    assert result.returncode == 0, result.stderr
    summary = _load(output / "review-summary.json")
    assert summary["counts"]["by_label_status"] == {"labeled": 1, "unlabeled": 2}
    assert summary["counts"]["by_reviewer_classification"]["valid_path"] == 1


def test_duplicate_or_ambiguous_finding_id_prefix_fails(tmp_path: Path) -> None:
    scenario, findings = _write_inputs(tmp_path)
    findings_payload = _findings()
    findings_payload["findings"][2]["finding_id"] = "aaaazzzzxxxx3333"
    findings.write_text(json.dumps(findings_payload), encoding="utf-8")
    labels = tmp_path / "reviewer-labels.json"
    labels.write_text(
        json.dumps(
            {
                "pilot_id": "real-pilot-dev-001",
                "label_schema_version": 1,
                "labels": [{"finding_id_prefix": "aaaa", "classification": "valid_path"}],
            }
        ),
        encoding="utf-8",
    )
    result = _run_script(
        "--scenario",
        str(scenario),
        "--findings",
        str(findings),
        "--labels",
        str(labels),
        "--out",
        str(tmp_path / "review"),
    )
    assert result.returncode == 1
    assert "matched" in result.stderr


def test_duplicate_label_for_same_finding_id_fails(tmp_path: Path) -> None:
    scenario, findings = _write_inputs(tmp_path)
    labels = tmp_path / "reviewer-labels.json"
    labels.write_text(
        json.dumps(
            {
                "pilot_id": "real-pilot-dev-001",
                "label_schema_version": 1,
                "labels": [
                    {"finding_id_prefix": "aaaabbbbcccc", "classification": "valid_path"},
                    {
                        "finding_id_prefix": "aaaabbbbcccc1111",
                        "classification": "needs_more_evidence",
                    },
                ],
            }
        ),
        encoding="utf-8",
    )
    result = _run_script(
        "--scenario",
        str(scenario),
        "--findings",
        str(findings),
        "--labels",
        str(labels),
        "--out",
        str(tmp_path / "review"),
    )
    assert result.returncode == 1
    assert "duplicate label" in result.stderr


def test_invalid_classification_category_fails(tmp_path: Path) -> None:
    scenario, findings = _write_inputs(tmp_path)
    labels = tmp_path / "reviewer-labels.json"
    labels.write_text(
        json.dumps(
            {
                "pilot_id": "real-pilot-dev-001",
                "label_schema_version": 1,
                "labels": [{"finding_id_prefix": "aaaabbbbcccc", "classification": "confirmed"}],
            }
        ),
        encoding="utf-8",
    )
    result = _run_script(
        "--scenario",
        str(scenario),
        "--findings",
        str(findings),
        "--labels",
        str(labels),
        "--out",
        str(tmp_path / "review"),
    )
    assert result.returncode == 1
    assert "invalid classification" in result.stderr


def test_raw_account_ids_and_arns_are_absent_from_outputs(tmp_path: Path) -> None:
    scenario, findings = _write_inputs(tmp_path)
    output = tmp_path / "review"
    result = _run_script("--scenario", str(scenario), "--findings", str(findings), "--out", str(output))
    assert result.returncode == 0, result.stderr
    combined = "\n".join(path.read_text(encoding="utf-8") for path in output.iterdir())
    assert _account_id() not in combined
    assert "arn:aws:iam::" not in combined
    assert "arn:aws:sts::" not in combined
    assert "SourceWildcardTrustRole" in combined
    assert "ProdDBAdminRole" in combined


def test_summary_counts_without_score_or_performance_metric_fields(tmp_path: Path) -> None:
    artifacts = build_review_artifacts(scenario_payload=_scenario(), findings_payload=_findings())
    summary = artifacts["summary"]
    assert summary["finding_count"] == 3
    assert summary["scenario_counts"] == {
        "nodes": 2,
        "edges": 1,
        "constraints": 1,
        "edge_constraints": 1,
    }
    assert summary["counts"]["by_pattern_id"] == {"admin_reachability": 1, "cross_account_trust": 2}
    assert summary["counts"]["by_iamscope_verdict"] == {"inconclusive": 1, "validated": 2}
    assert summary["counts"]["by_reviewer_classification"] == {"unlabeled": 3}
    assert summary["counts"]["by_severity"] == {"critical": 1, "high": 1, "medium": 1}
    assert summary["counts"]["by_label_status"] == {"unlabeled": 3}
    forbidden_field_names = {"score", "pass_fail", "accuracy", "precision", "recall"}
    assert forbidden_field_names.isdisjoint(set(_walk_keys(summary)))


def test_collection_context_assumptions_and_blockers_are_surfaced() -> None:
    artifacts = build_review_artifacts(scenario_payload=_scenario(), findings_payload=_findings())
    cross_account = artifacts["inventory"][0]
    assert "org_membership_status=unknown" in cross_account["collection_context_summary"]
    assert "scope=partial_org" in cross_account["collection_context_summary"]
    assert cross_account["assumptions"] == [
        "org_membership_status: source account membership is unknown in partial collection context"
    ]

    admin = [entry for entry in artifacts["inventory"] if entry["pattern_id"] == "admin_reachability"][0]
    assert admin["blockers_observed"] == ["permission_boundary: reviewer should inspect boundary context"]
    assert admin["required_check_states"]["at_least_one_reachable_chain_uses_clean_witnesses"] == "unknown"


def test_cross_account_trust_summary_preserves_reviewer_signal() -> None:
    artifacts = build_review_artifacts(scenario_payload=_scenario(), findings_payload=_findings())
    cross_account = artifacts["inventory"][0]
    summary = " ".join(cross_account["evidence_summary"])
    assert "trust_scope: cross_account" in summary
    assert "naked_trust: yes" in summary
    assert "wildcard_principal: yes" in summary
    assert "has_external_id: yes" in summary
    assert "has_conditions: yes" in summary


def test_referenced_edge_summary_preserves_sanitized_edge_context() -> None:
    artifacts = build_review_artifacts(scenario_payload=_scenario(), findings_payload=_findings())
    cross_account = artifacts["inventory"][0]
    assert cross_account["referenced_edges"] == [
        "edge-trust-1: SourceWildcardTrustRole -> TrustedTargetRole (sts:AssumeRole)"
    ]


def test_admin_reachability_summary_preserves_administratoraccess_signal() -> None:
    artifacts = build_review_artifacts(scenario_payload=_scenario(), findings_payload=_findings())
    admin = [entry for entry in artifacts["inventory"] if entry["pattern_id"] == "admin_reachability"][0]
    summary = " ".join(admin["evidence_summary"])
    assert "source_has_assume_role: pass" in summary
    assert "reachable_admins_count: 1" in summary
    assert "clean_witness_check: unknown" in summary
    assert "admin_witness_policy: AdministratorAccess" in summary


def test_template_contains_one_entry_per_finding(tmp_path: Path) -> None:
    artifacts = build_review_artifacts(scenario_payload=_scenario(), findings_payload=_findings())
    template = artifacts["template"]
    assert template["pilot_id"] == "real-pilot-dev-001"
    assert template["label_schema_version"] == 1
    assert len(template["labels"]) == 3
    assert {label["classification"] for label in template["labels"]} == {""}


def test_output_is_deterministic_across_repeated_runs(tmp_path: Path) -> None:
    scenario, findings = _write_inputs(tmp_path)
    output_one = tmp_path / "review-one"
    output_two = tmp_path / "review-two"

    first = _run_script("--scenario", str(scenario), "--findings", str(findings), "--out", str(output_one))
    second = _run_script("--scenario", str(scenario), "--findings", str(findings), "--out", str(output_two))
    assert first.returncode == 0, first.stderr
    assert second.returncode == 0, second.stderr

    for name in (
        "review-table.md",
        "review-summary.json",
        "unlabeled-findings.json",
        "reviewer-label-template.json",
    ):
        assert (output_one / name).read_text(encoding="utf-8") == (output_two / name).read_text(encoding="utf-8")
