from __future__ import annotations

import json
import shutil
import subprocess
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
RUNNER = REPO_ROOT / "scripts" / "run_path_overcounting_shared_uncertainty_demo.sh"
FIXTURE_DIR = REPO_ROOT / "tests" / "fixtures" / "demo" / "path_overcounting_shared_uncertainty"
DEFAULT_OUT = Path("/tmp/iamscope-path-overcounting-demo")
GENERATED_FILES = {
    "summary.md",
    "uncertainty-groups.json",
    "verdict-summary.json",
}


def _run_runner(*args: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [str(RUNNER), *args],
        cwd=REPO_ROOT,
        check=False,
        text=True,
        capture_output=True,
    )


def _assert_generated_files(output_dir: Path) -> None:
    assert {path.name for path in output_dir.iterdir() if path.is_file()} == GENERATED_FILES


def test_runner_defaults_output_under_tmp() -> None:
    shutil.rmtree(DEFAULT_OUT, ignore_errors=True)
    try:
        result = _run_runner()
        assert result.returncode == 0, result.stderr
        assert "Output: /tmp/iamscope-path-overcounting-demo" in result.stdout
        assert DEFAULT_OUT.is_dir()
        _assert_generated_files(DEFAULT_OUT)
    finally:
        shutil.rmtree(DEFAULT_OUT, ignore_errors=True)


def test_runner_writes_to_temp_output_directory(tmp_path: Path) -> None:
    output_dir = tmp_path / "demo-output"
    result = _run_runner("--out", str(output_dir))
    assert result.returncode == 0, result.stderr
    _assert_generated_files(output_dir)

    verdict_summary = json.loads((output_dir / "verdict-summary.json").read_text())
    assert verdict_summary["naive_candidate_count"] == 23
    assert verdict_summary["verdict_breakdown"] == {
        "validated": 3,
        "blocked": 5,
        "precondition_only": 4,
        "inconclusive": 11,
    }
    assert verdict_summary["replay_equivalence_status"] == "not_proven"
    assert verdict_summary["generated_or_replayed_by_iamscope"] is False
    assert verdict_summary["stronger_demo_claims_allowed"] is False
    assert verdict_summary["aws_calls_made"] == 0
    assert verdict_summary["live_aws_used"] is False


def test_runner_uncertainty_group_counts(tmp_path: Path) -> None:
    output_dir = tmp_path / "demo-output"
    result = _run_runner("--out", str(output_dir))
    assert result.returncode == 0, result.stderr

    groups = json.loads((output_dir / "uncertainty-groups.json").read_text())
    assert groups["groups"] == {
        "shared_passrole_target_resource_scope_unknown": 8,
        "shared_boundary_context_unresolved": 2,
        "session_policy_context_missing": 1,
    }
    assert groups["top_uncertainty_class"] == "shared_passrole_target_resource_scope_unknown"
    assert groups["top_uncertainty_count"] == 8


def test_runner_summary_preserves_safety_and_replay_boundary(tmp_path: Path) -> None:
    output_dir = tmp_path / "demo-output"
    result = _run_runner("--out", str(output_dir))
    assert result.returncode == 0, result.stderr

    summary = (output_dir / "summary.md").read_text()
    assert "IAMScope path-overcounting demo (local only)" in summary
    assert "Findings mode: frozen expected output" in summary
    assert "## Replay equivalence\n\nnot proven" in summary
    assert "Generated/replayed by IAMScope: false" in summary
    assert "Stronger demo claims allowed: false" in summary
    assert "AWS calls made: 0" in summary
    assert "Live AWS used: false" in summary
    assert "not live AWS validation" in summary
    assert "not replay-proven IAMScope reasoner output" in summary


def test_runner_refuses_repository_output_path() -> None:
    repo_output = REPO_ROOT / "path-overcounting-demo-output"
    shutil.rmtree(repo_output, ignore_errors=True)
    result = _run_runner("--out", str(repo_output))
    assert result.returncode == 2
    assert "refusing to write demo outputs inside the repository tree" in result.stderr
    assert not repo_output.exists()


def test_generated_outputs_are_not_committed_in_fixture_directory() -> None:
    assert GENERATED_FILES.isdisjoint({path.name for path in FIXTURE_DIR.iterdir() if path.is_file()})
