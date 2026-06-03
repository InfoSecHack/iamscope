"""Tests for the narrow complex PassRole-to-Lambda replay subset probe."""

from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path

import pytest

from scripts.probe_complex_passrole_lambda_replay_subset import (
    FIXTURE_DIR,
    REPO_ROOT,
    build_probe_result,
    run_probe,
)

PROBE = REPO_ROOT / "scripts" / "probe_complex_passrole_lambda_replay_subset.py"
REQUIRED_FIXTURE_FILES = {
    "README.md",
    "scenario.json",
    "binding_metadata.json",
    "expected_rows.json",
}
GENERATED_OUTPUTS = {
    "replay-subset-summary.md",
    "replay-subset-manifest.json",
    "generated-findings.json",
}


def _fixture_text() -> str:
    return "\n".join(path.read_text(encoding="utf-8") for path in FIXTURE_DIR.iterdir() if path.is_file())


def test_fixture_files_exist() -> None:
    assert {path.name for path in FIXTURE_DIR.iterdir() if path.is_file()} == REQUIRED_FIXTURE_FILES


def test_fixture_uses_only_synthetic_account_and_no_raw_non_synthetic_arns() -> None:
    text = _fixture_text()

    assert "000000000000" in text
    assert "arn:aws:iam::000000000000" in text
    assert not [
        token
        for token in text.replace('"', " ").replace(":", " ").split()
        if token.isdigit() and len(token) == 12 and token != "000000000000"
    ]


def test_probe_refuses_repo_output_paths() -> None:
    with pytest.raises(ValueError, match="repository tree"):
        run_probe(REPO_ROOT / "replay-subset-output")


def test_probe_writes_summary_manifest_and_generated_findings(tmp_path: Path) -> None:
    manifest = run_probe(tmp_path)

    assert (tmp_path / "replay-subset-summary.md").is_file()
    assert (tmp_path / "replay-subset-manifest.json").is_file()
    assert (tmp_path / "generated-findings.json").is_file()
    assert json.loads((tmp_path / "replay-subset-manifest.json").read_text()) == manifest


def test_manifest_is_local_only_and_replays_narrow_subset(tmp_path: Path) -> None:
    manifest = run_probe(tmp_path)

    assert manifest["local_only"] is True
    assert manifest["live_aws_used"] is False
    assert manifest["aws_calls_made"] == 0
    assert manifest["fixture_id"] == "complex_replay_subset_passrole_lambda_001"
    assert manifest["replay_subset_status"] == "replayed_selected_passrole_lambda_subset"
    assert manifest["input_contract_status"] == "replay_ready"
    assert manifest["safe_replay_attempted"] is True
    assert manifest["reasoners_attempted"] == ["passrole_lambda"]
    assert manifest["reasoners_skipped"] == {}


def test_manifest_does_not_claim_full_complex_replay_equivalence(tmp_path: Path) -> None:
    manifest = run_probe(tmp_path)
    text = json.dumps(manifest)

    assert "no full complex benchmark replay-equivalence" in manifest["non_claims"]
    assert "no broad IAMScope correctness" in manifest["non_claims"]
    assert "full_complex_benchmark_replay_equivalence" not in text
    assert "composite_score" not in text
    assert "benchmark_passed" not in text


def test_row_accounting_matches_expected_subset(tmp_path: Path) -> None:
    manifest = run_probe(tmp_path)

    assert len(manifest["expected_rows"]) == 1
    assert len(manifest["generated_rows"]) == 1
    assert len(manifest["matched_rows"]) == 1
    assert manifest["matched_rows"][0]["pattern_id"] == "passrole_lambda"
    assert manifest["matched_rows"][0]["verdict"] == "validated"
    assert manifest["missing_rows"] == []
    assert manifest["extra_rows"] == []
    assert len(manifest["static_only_rows"]) == 1
    assert manifest["static_only_rows"][0]["expected_generation"] == "not_generated_missing_precondition"
    assert manifest["unsupported_rows"] == []


def test_static_only_rows_are_not_treated_as_generated_findings(tmp_path: Path) -> None:
    manifest = run_probe(tmp_path)
    generated_sources = {row["source"] for row in manifest["generated_rows"]}
    static_sources = {row["source"] for row in manifest["static_only_rows"]}

    assert generated_sources.isdisjoint(static_sources)
    assert "Missing-precondition/static-only rows are not treated as generated findings." in (
        tmp_path / "replay-subset-summary.md"
    ).read_text(encoding="utf-8")


def test_summary_states_required_boundaries(tmp_path: Path) -> None:
    run_probe(tmp_path)
    summary = (tmp_path / "replay-subset-summary.md").read_text(encoding="utf-8")

    assert "This is a narrow PassRole-to-Lambda replay subset." in summary
    assert "This does not prove replay-equivalence for the full complex synthetic benchmark." in summary
    assert "This does not prove broad IAMScope correctness." in summary
    assert "Missing-precondition/static-only rows are not treated as generated findings." in summary
    assert "No composite benchmark score or pass/fail benchmark label is produced." in summary


def test_probe_does_not_require_aws_credentials(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    for key in list(os.environ):
        if key.startswith("AWS_"):
            monkeypatch.delenv(key, raising=False)

    manifest = run_probe(tmp_path)

    assert manifest["live_aws_used"] is False
    assert manifest["aws_calls_made"] == 0


def test_no_generated_outputs_are_committed() -> None:
    committed = {path.name for path in FIXTURE_DIR.iterdir() if path.is_file()}
    assert GENERATED_OUTPUTS.isdisjoint(committed)


def test_cli_writes_expected_outputs(tmp_path: Path) -> None:
    result = subprocess.run(
        [sys.executable, str(PROBE), "--out", str(tmp_path)],
        cwd=REPO_ROOT,
        text=True,
        capture_output=True,
        check=False,
    )

    assert result.returncode == 0, result.stderr
    assert "Replay subset status: replayed_selected_passrole_lambda_subset" in result.stdout
    assert "Live AWS used: false" in result.stdout
    assert "AWS calls made: 0" in result.stdout
    assert (tmp_path / "replay-subset-summary.md").is_file()
    assert (tmp_path / "replay-subset-manifest.json").is_file()
    assert (tmp_path / "generated-findings.json").is_file()


def test_build_probe_result_without_out_does_not_attempt_replay() -> None:
    manifest, summary = build_probe_result()

    assert manifest["input_contract_status"] == "replay_ready"
    assert manifest["safe_replay_attempted"] is False
    assert manifest["replay_subset_status"] == "not_proven"
    assert "This is a narrow PassRole-to-Lambda replay subset." in summary
