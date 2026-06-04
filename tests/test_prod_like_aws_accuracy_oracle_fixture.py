from __future__ import annotations

import json
import re
from collections import Counter
from pathlib import Path
from typing import Any

REPO_ROOT = Path(__file__).resolve().parents[1]
FIXTURE_DIR = REPO_ROOT / "tests" / "fixtures" / "prod_like" / "aws_accuracy_oracle_v1"
FIXTURE_ID = "prod_like_aws_accuracy_oracle_v1"
REQUIRED_FILES = {
    "README.md",
    "oracle_rows.json",
    "scenario.json",
    "binding_metadata.json",
    "expected_findings.json",
    "expected_comparison.json",
}
REQUIRED_ROW_IDS = {
    "oracle-v-001",
    "oracle-v-002",
    "oracle-v-003",
    "oracle-v-004",
    "oracle-v-005",
    "oracle-v-006",
    "oracle-b-001",
    "oracle-b-002",
    "oracle-b-003",
    "oracle-b-004",
    "oracle-b-005",
    "oracle-p-001",
    "oracle-p-002",
    "oracle-p-003",
    "oracle-p-004",
    "oracle-i-001",
    "oracle-i-002",
    "oracle-i-003",
    "oracle-i-004",
    "oracle-i-005",
    "oracle-u-001",
    "oracle-u-002",
    "oracle-u-003",
    "oracle-u-004",
}
REQUIRED_ROW_FIELDS = {
    "oracle_row_id",
    "expected_category",
    "pattern",
    "source_principal_alias",
    "target_alias",
    "expected_iamscope_behavior",
    "evidence_required",
    "blocker_precondition_uncertainty_reason",
    "current_support_expectation",
    "reviewer_note",
    "comparison_status_policy",
}
ALLOWED_CATEGORIES = {"validated", "blocked", "precondition_only", "inconclusive", "unsupported"}
ALLOWED_SUPPORT = {"yes", "partial", "no", "unknown"}
EXPECTED_BREAKDOWN = {
    "validated": 6,
    "blocked": 5,
    "precondition_only": 4,
    "inconclusive": 5,
    "unsupported": 4,
}
NON_CLAIMS = {
    "not broad IAMScope correctness",
    "not production readiness",
    "not real production AWS",
    "not exploitability proof",
    "not downstream authorization proof",
    "not Lambda invocation behavior",
    "not generic Deny correctness",
    "not resource-policy Deny support except unsupported/static-only row labeling",
    "not SCP Deny support beyond selected benchmark behavior",
    "no composite benchmark score",
    "no pass/fail benchmark label",
}


def _load(name: str) -> dict[str, Any]:
    return json.loads((FIXTURE_DIR / name).read_text(encoding="utf-8"))


def _rows() -> list[dict[str, Any]]:
    return list(_load("oracle_rows.json")["oracle_rows"])


def _fixture_text() -> str:
    return "\n".join(path.read_text(encoding="utf-8") for path in FIXTURE_DIR.iterdir() if path.is_file())


def _metadata_payloads() -> list[dict[str, Any]]:
    return [
        _load("oracle_rows.json")["metadata"],
        _load("scenario.json")["metadata"],
        _load("binding_metadata.json")["metadata"],
        _load("expected_findings.json")["metadata"],
        _load("expected_comparison.json")["metadata"],
    ]


def test_required_fixture_files_exist() -> None:
    assert {path.name for path in FIXTURE_DIR.iterdir() if path.is_file()} == REQUIRED_FILES


def test_fixture_id_and_metadata_contract() -> None:
    for metadata in _metadata_payloads():
        assert metadata["fixture_id"] == FIXTURE_ID
        assert metadata["source_tool"] == "static_fixture_authoring"
        assert metadata["generation_mode"] == "local_prod_like_oracle_fixture"
        assert metadata["local_only"] is True
        assert metadata["live_aws_used"] is False
        assert metadata["aws_calls_made"] == 0
        assert metadata["generated_or_replayed_by_iamscope"] is False
        assert metadata["reasoners_run"] == []
        assert set(metadata["non_claims"]) == NON_CLAIMS


def test_oracle_rows_count_breakdown_and_ids() -> None:
    rows = _rows()
    row_ids = [row["oracle_row_id"] for row in rows]

    assert len(rows) == 24
    assert Counter(row["expected_category"] for row in rows) == EXPECTED_BREAKDOWN
    assert set(row_ids) == REQUIRED_ROW_IDS
    assert len(row_ids) == len(set(row_ids))
    assert _load("oracle_rows.json")["category_breakdown"] == EXPECTED_BREAKDOWN


def test_every_oracle_row_has_required_fields_and_allowed_values() -> None:
    for row in _rows():
        assert set(row) == REQUIRED_ROW_FIELDS
        assert row["expected_category"] in ALLOWED_CATEGORIES
        assert row["current_support_expectation"] in ALLOWED_SUPPORT
        assert str(row["evidence_required"]).strip()
        assert str(row["reviewer_note"]).strip()


def test_unsupported_rows_are_static_only_and_not_counted_as_mismatches() -> None:
    expected_findings = _load("expected_findings.json")
    comparison = _load("expected_comparison.json")
    unsupported_ids = {row["oracle_row_id"] for row in _rows() if row["expected_category"] == "unsupported"}

    assert {row["oracle_row_id"] for row in expected_findings["unsupported_static_only_rows"]} == unsupported_ids
    assert unsupported_ids.isdisjoint(
        {row["oracle_row_id"] for row in expected_findings["expected_supported_findings"]}
    )
    for row in expected_findings["unsupported_static_only_rows"]:
        assert row["comparison_status_policy"] == "unsupported_static_only_not_false_positive_or_false_negative"
        assert set(row["not_counted_as"]) == {
            "false_positive",
            "false_negative",
            "extra_finding",
            "missing_finding",
        }
    for row in comparison["comparison_rows"]:
        if row["oracle_row_id"] in unsupported_ids:
            assert row["match_status"] == "unsupported_behavior"
            assert set(row["not_counted_as"]) == {
                "false_positive",
                "false_negative",
                "extra_finding",
                "missing_finding",
            }


def test_expected_comparison_is_phase5_not_run_table_shape() -> None:
    comparison = _load("expected_comparison.json")

    assert comparison["metadata"]["phase5_status"] == "not_run_yet"
    assert len(comparison["comparison_rows"]) == 24
    for row in comparison["comparison_rows"]:
        assert {
            "oracle_row_id",
            "expected_category",
            "emitted_iamscope_category",
            "match_status",
            "evidence_used",
            "blocker_precondition_uncertainty_reason",
            "reviewer_note",
            "not_counted_as",
        } == set(row)
        assert row["emitted_iamscope_category"] == "not_run_yet"
        assert isinstance(row["evidence_used"], list)
        assert str(row["reviewer_note"]).strip()


def test_no_composite_score_or_pass_fail_label_fields() -> None:
    text = json.dumps(
        {
            name: _load(name)
            for name in (
                "oracle_rows.json",
                "scenario.json",
                "binding_metadata.json",
                "expected_findings.json",
                "expected_comparison.json",
            )
        }
    ).lower()

    assert "composite_score" not in text
    assert "benchmark_passed" not in text
    assert "pass_fail" not in text
    assert _load("expected_comparison.json")["comparison_method"]["score_policy"] == "no composite benchmark score"
    assert _load("expected_comparison.json")["comparison_method"]["benchmark_label_policy"] == (
        "no pass/fail benchmark label"
    )


def test_no_non_synthetic_account_ids_or_iam_arns() -> None:
    text = _fixture_text()
    account_ids = set(re.findall(r"\b[0-9]{12}\b", text))
    raw_arns = re.findall(r"arn:aws:iam::([0-9]{12})", text)

    assert account_ids <= {"000000000000"}
    assert set(raw_arns) <= {"000000000000"}
    assert "synthetic-account-a" in text
    assert "synthetic-account-b" in text


def test_no_live_or_terraform_artifacts_committed_in_fixture() -> None:
    forbidden_names = {
        "result.json",
        "terraform.tfstate",
        "terraform.tfstate.backup",
        ".terraform.lock.hcl",
        "terraform-outputs.json",
    }
    forbidden_suffixes = (".tfplan",)
    committed_names = {path.name for path in FIXTURE_DIR.rglob("*") if path.is_file()}

    assert forbidden_names.isdisjoint(committed_names)
    assert not any(path.name.endswith(forbidden_suffixes) for path in FIXTURE_DIR.rglob("*") if path.is_file())


def test_readme_includes_local_only_boundary_and_non_claims() -> None:
    readme = (FIXTURE_DIR / "README.md").read_text(encoding="utf-8")

    assert "no live AWS" in readme
    assert "no Terraform" in readme
    assert "no AWS credentials" in readme
    assert "generated/replayed by IAMScope: false" in readme
    assert "reasoners run: []" in readme
    for claim in NON_CLAIMS:
        assert claim in readme
