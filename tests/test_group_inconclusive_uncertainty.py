from __future__ import annotations

import json
import subprocess
from pathlib import Path

from scripts.group_inconclusive_uncertainty import group_inconclusive_uncertainty

REPO_ROOT = Path(__file__).resolve().parents[1]
HELPER = REPO_ROOT / "scripts" / "group_inconclusive_uncertainty.py"
FIXTURE_DIR = REPO_ROOT / "tests" / "fixtures" / "demo" / "path_overcounting_shared_uncertainty"
FINDINGS = FIXTURE_DIR / "findings.json"
EXPECTED_GROUPS = FIXTURE_DIR / "expected_uncertainty_groups.json"
EXPECTED_COUNTS = {
    "shared_passrole_target_resource_scope_unknown": 8,
    "shared_boundary_context_unresolved": 2,
    "session_policy_context_missing": 1,
}


def _run_helper(*args: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [str(HELPER), *args],
        cwd=REPO_ROOT,
        check=False,
        text=True,
        capture_output=True,
    )


def _load(path: Path) -> dict:
    return json.loads(path.read_text())


def test_groups_only_inconclusive_findings() -> None:
    findings = _load(FINDINGS)
    result = group_inconclusive_uncertainty(findings)
    inconclusive_ids = {
        finding["finding_id"] for finding in findings["findings"] if finding["verdict"] == "inconclusive"
    }
    grouped_ids = {finding_id for group in result["group_details"] for finding_id in group["finding_ids"]}
    assert grouped_ids == inconclusive_ids
    assert len(grouped_ids) == 11


def test_demo_fixture_group_counts_and_finding_ids() -> None:
    result = group_inconclusive_uncertainty(_load(FINDINGS))
    expected = _load(EXPECTED_GROUPS)
    expected_ids = {group["uncertainty_class"]: group["finding_ids"] for group in expected["groups"]}
    actual_ids = {group["uncertainty_class"]: group["finding_ids"] for group in result["group_details"]}
    assert result["groups"] == EXPECTED_COUNTS
    assert actual_ids == expected_ids
    assert result["top_uncertainty_class"] == "shared_passrole_target_resource_scope_unknown"
    assert result["top_uncertainty_count"] == 8


def test_expected_groups_enriches_reviewer_actions() -> None:
    expected = _load(EXPECTED_GROUPS)
    actions = {group["uncertainty_class"]: group["reviewer_action"] for group in expected["groups"]}
    result = group_inconclusive_uncertainty(_load(FINDINGS), reviewer_actions=actions)
    actual_actions = {group["uncertainty_class"]: group["reviewer_action"] for group in result["group_details"]}
    assert actual_actions == actions


def test_helper_does_not_mutate_input_findings() -> None:
    before = FINDINGS.read_text()
    group_inconclusive_uncertainty(_load(FINDINGS))
    assert FINDINGS.read_text() == before


def test_helper_prints_json_to_stdout() -> None:
    result = _run_helper("--findings", str(FINDINGS), "--expected-groups", str(EXPECTED_GROUPS))
    assert result.returncode == 0, result.stderr
    payload = json.loads(result.stdout)
    assert payload["groups"] == EXPECTED_COUNTS
    assert payload["non_claims"]["does_not_mutate_findings"] is True
    assert payload["non_claims"]["does_not_change_verdicts"] is True
    assert payload["non_claims"]["does_not_infer_exploitability"] is True
    assert payload["non_claims"]["does_not_claim_replay_equivalence"] is True
    assert payload["non_claims"]["requires_aws_credentials"] is False


def test_helper_writes_to_temp_output_path(tmp_path: Path) -> None:
    output = tmp_path / "uncertainty-groups.json"
    result = _run_helper(
        "--findings",
        str(FINDINGS),
        "--expected-groups",
        str(EXPECTED_GROUPS),
        "--out",
        str(output),
    )
    assert result.returncode == 0, result.stderr
    assert json.loads(output.read_text())["groups"] == EXPECTED_COUNTS


def test_helper_refuses_repository_output_path() -> None:
    output = REPO_ROOT / "uncertainty-groups.json"
    if output.exists():
        output.unlink()
    result = _run_helper("--findings", str(FINDINGS), "--out", str(output))
    assert result.returncode == 1
    assert "refusing to write uncertainty grouping output inside repository tree" in result.stderr
    assert not output.exists()
