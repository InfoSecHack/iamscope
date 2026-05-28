from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path
from typing import Any

import pytest

from benchmarks.runtime.sts_probe_executor import (
    REQUIRED_OPERATOR_CONFIRMATION,
    build_executor_report_from_paths,
)
from benchmarks.runtime.sts_probe_executor import (
    render_markdown_report as render_sts_executor_markdown_report,
)
from benchmarks.runtime.sts_probe_plan import build_validation_from_paths
from benchmarks.scalability.baseline_compare import build_comparison_from_paths
from benchmarks.scalability.frozen_corpus_baseline_compare import (
    build_comparison_from_paths as build_frozen_corpus_comparison_from_paths,
)
from benchmarks.scalability.frozen_corpus_batch import build_report as build_frozen_corpus_report
from benchmarks.scalability.frozen_threshold_evaluator import (
    build_threshold_evaluation_from_paths as build_frozen_threshold_evaluation_from_paths,
)
from benchmarks.scalability.harness import (
    _candidate_paths,
    build_report,
    generate_fixture,
    render_markdown_report,
    run_fixture,
)
from benchmarks.scalability.threshold_config import load_threshold_config, validate_threshold_config
from benchmarks.scalability.threshold_evaluator import build_threshold_evaluation_from_paths

OLD_OPERATOR_CONFIRMATION = "I understand this will call sts:AssumeRole for test resources only"

FROZEN_CORPUS_SNAPSHOT = Path("benchmarks/snapshots/phase0-20260509-env27")
ARTIFACT_POLICY_REPO_PATHS = (
    Path("scalability-report.json"),
    Path("scalability-report.md"),
    Path("frozen-corpus-batch.json"),
    Path("frozen-corpus-batch.md"),
    Path("comparison.json"),
    Path("comparison.md"),
    Path("frozen-comparison.json"),
    Path("frozen-comparison.md"),
    Path("threshold-evaluation.json"),
    Path("threshold-evaluation.md"),
    Path("frozen-threshold-evaluation.json"),
    Path("frozen-threshold-evaluation.md"),
    Path("sts-probe-validation.json"),
    Path("sts-probe-validation.md"),
    Path("sts-probe-execution.json"),
    Path("sts-probe-execution.md"),
    Path("scenario.json"),
    Path("findings.json"),
    Path("binding_metadata.json"),
    Path("run.log"),
    Path("terraform.tfstate"),
    Path(".terraform"),
    Path("collect"),
    Path("benchmark-runs"),
    Path("benchmark_outputs"),
    Path("generated-benchmark-reports"),
)


def _repo_artifact_policy_snapshot() -> dict[str, bool]:
    return {str(path): (Path.cwd() / path).exists() for path in ARTIFACT_POLICY_REPO_PATHS}


def _assert_repo_artifact_policy_snapshot_unchanged(before: dict[str, bool]) -> None:
    assert _repo_artifact_policy_snapshot() == before


def _subprocess_env_without_bytecode() -> dict[str, str]:
    env = os.environ.copy()
    env["PYTHONDONTWRITEBYTECODE"] = "1"
    return env


def _subprocess_env_without_aws_credentials() -> dict[str, str]:
    env = _subprocess_env_without_bytecode()
    for key in list(env):
        if key.startswith("AWS_"):
            env.pop(key)
    return env


def _valid_threshold_config() -> dict[str, Any]:
    return {
        "schema_version": "0.1",
        "config_type": "iamscope_threshold_config",
        "mode": "report_only",
        "report_type": "synthetic_scalability_baseline_comparison",
        "caveats": ["advisory_only", "no_composite_score"],
        "thresholds": [
            {
                "target_type": "fixture",
                "target_name": "constraint_heavy",
                "metric": "constraint_evaluations",
                "comparison_type": "max_absolute_delta",
                "delta_limit": 0,
                "rationale": "Constraint-evaluation count should remain deterministic.",
                "caveat": "A change is a review signal, not automatically a bug.",
            },
            {
                "target_type": "fixture",
                "target_name": "small",
                "metric": "deterministic_output_stability.fixture_digest",
                "comparison_type": "equals",
                "expected": "unchanged",
                "rationale": "Small fixture topology should remain stable unless intentionally changed.",
                "caveat": "Digest equality is a stability signal, not proof of correctness.",
            },
            {
                "target_type": "fixture",
                "target_name": "medium",
                "metric": "paths_validated",
                "comparison_type": "may_be_unavailable",
                "expected": "not_collected",
                "rationale": "The current minimal harness exposes this metric as not_collected.",
                "caveat": "Unavailable is distinct from zero.",
            },
        ],
    }


def _synthetic_comparison_fixture_files(tmp_path: Path) -> tuple[Path, Path, Path]:
    baseline = build_report(["small", "medium"])
    current = json.loads(json.dumps(baseline))
    current_medium = next(item for item in current["fixtures"] if item["fixture_name"] == "medium")
    current_medium["metrics"]["candidate_paths_considered"] += 7
    current_medium["metrics"]["constraint_evaluations"] += 42
    current_medium["metrics"]["deterministic_output_stability"]["stable_metric_digest"] = "changed-digest"

    baseline_path = tmp_path / "baseline.json"
    current_path = tmp_path / "current.json"
    comparison_path = tmp_path / "comparison.json"
    baseline_path.write_text(json.dumps(baseline))
    current_path.write_text(json.dumps(current))
    comparison_path.write_text(json.dumps(build_comparison_from_paths(baseline_path, current_path)))
    return baseline_path, current_path, comparison_path


def _threshold_evaluator_config() -> dict[str, Any]:
    return {
        "schema_version": "0.1",
        "config_type": "iamscope_threshold_config",
        "mode": "report_only",
        "report_type": "synthetic_scalability_baseline_comparison",
        "caveats": ["report_only", "no_composite_score"],
        "thresholds": [
            {
                "target_type": "fixture",
                "target_name": "medium",
                "metric": "candidate_paths_considered",
                "comparison_type": "max_absolute_delta",
                "delta_limit": 10,
                "rationale": "Small candidate-path movement is expected in this synthetic test input.",
                "caveat": "Threshold satisfaction is not proof of correctness.",
            },
            {
                "target_type": "fixture",
                "target_name": "medium",
                "metric": "candidate_paths_considered",
                "comparison_type": "max_relative_delta",
                "delta_limit": 0.01,
                "rationale": "Exercise breached relative-delta reporting without gating.",
                "caveat": "A breach is a review signal, not pass/fail behavior.",
            },
            {
                "target_type": "fixture",
                "target_name": "medium",
                "metric": "deterministic_output_stability.stable_metric_digest",
                "comparison_type": "changed_or_unchanged",
                "expected": "changed",
                "rationale": "Digest changes should be highlighted for review.",
                "caveat": "Digest changes require review but do not prove a bug.",
            },
            {
                "target_type": "fixture",
                "target_name": "medium",
                "metric": "paths_validated",
                "comparison_type": "must_be_available",
                "rationale": "Unavailable metrics should remain unavailable, not zero.",
                "caveat": "Unavailable is not zero and is not a pass/fail outcome.",
            },
            {
                "target_type": "fixture",
                "target_name": "missing_fixture",
                "metric": "constraint_evaluations",
                "comparison_type": "max_absolute_delta",
                "delta_limit": 0,
                "rationale": "Missing targets should be non-gating review signals.",
                "caveat": "Missing targets are not interpreted as benchmark failure.",
            },
            {
                "target_type": "fixture",
                "target_name": "small",
                "metric": "wall_clock_runtime_ms",
                "comparison_type": "max_absolute_delta",
                "delta_limit": 1000000,
                "rationale": "Runtime movement should keep machine context caveats.",
                "caveat": "Runtime is machine/context-sensitive and not correctness evidence.",
                "runtime_context_note": "Machine context must be reviewed before interpreting runtime deltas.",
            },
            {
                "target_type": "fixture",
                "target_name": "medium",
                "metric": "failure_mode_classification",
                "comparison_type": "equals",
                "expected": "none",
                "rationale": "Failure mode classification should remain explicit.",
                "caveat": "Classification equality is not proof of broad correctness.",
            },
            {
                "target_type": "fixture",
                "target_name": "medium",
                "metric": "paths_rejected",
                "comparison_type": "may_be_unavailable",
                "rationale": "The current harness may leave rejection counts unavailable.",
                "caveat": "Unavailable remains distinct from zero.",
            },
        ],
    }


def _frozen_corpus_comparison_fixture_files(tmp_path: Path) -> tuple[Path, Path, Path, str, str, str]:
    baseline = build_frozen_corpus_report(FROZEN_CORPUS_SNAPSHOT)
    current = json.loads(json.dumps(baseline))
    matched_case = next(
        case for case in current["cases"] if case["case_id"] == "env27_multihop_trust_scoped_away_nonvalidated"
    )
    matched_case["environment"] = "env27-threshold-review"
    removed_case = current["cases"].pop(0)
    added_case = json.loads(json.dumps(matched_case))
    added_case["case_id"] = "synthetic_added_case_for_threshold_evaluation"
    added_case["run_id"] = "synthetic-threshold-added-run"
    current["cases"].append(added_case)
    current["batch_summary"]["cases"] += 1
    current["batch_summary"]["failures"] += 2
    current["unavailable_metrics"][0]["reason"] = "not_collected: changed threshold evaluation reason"

    baseline_path = tmp_path / "frozen-baseline.json"
    current_path = tmp_path / "frozen-current.json"
    comparison_path = tmp_path / "frozen-comparison.json"
    baseline_path.write_text(json.dumps(baseline))
    current_path.write_text(json.dumps(current))
    comparison_path.write_text(json.dumps(build_frozen_corpus_comparison_from_paths(baseline_path, current_path)))
    return (
        baseline_path,
        current_path,
        comparison_path,
        str(matched_case["case_id"]),
        str(added_case["case_id"]),
        str(removed_case["case_id"]),
    )


def _frozen_threshold_evaluator_config(
    matched_case_id: str, added_case_id: str, removed_case_id: str
) -> dict[str, Any]:
    return {
        "schema_version": "0.1",
        "config_type": "iamscope_threshold_config",
        "mode": "report_only",
        "report_type": "frozen_corpus_baseline_comparison",
        "caveats": ["offline_report_only", "no_composite_score"],
        "thresholds": [
            {
                "target_type": "batch",
                "target_name": "frozen_corpus",
                "metric": "failures",
                "comparison_type": "max_absolute_delta",
                "delta_limit": 3,
                "rationale": "Small synthetic failure-count movement is tolerated for this test input.",
                "caveat": "Threshold satisfaction is not proof of correctness.",
            },
            {
                "target_type": "batch",
                "target_name": "frozen_corpus",
                "metric": "cases",
                "comparison_type": "max_relative_delta",
                "delta_limit": 0.001,
                "rationale": "Exercise breached relative-delta reporting without gates.",
                "caveat": "A breach is changed offline report behavior requiring review.",
            },
            {
                "target_type": "batch",
                "target_name": "frozen_corpus",
                "metric": "live_aws_used",
                "comparison_type": "equals",
                "expected": False,
                "rationale": "Frozen-corpus threshold evaluation should remain offline.",
                "caveat": "Offline consistency is not new live AWS evidence.",
            },
            {
                "target_type": "batch",
                "target_name": "frozen_corpus",
                "metric": "candidate_paths_considered",
                "comparison_type": "must_be_available",
                "rationale": "Unavailable frozen-corpus metrics should remain unavailable, not zero.",
                "caveat": "Unavailable is not zero and is not a pass/fail outcome.",
            },
            {
                "target_type": "case",
                "target_name": matched_case_id,
                "metric": "environment",
                "comparison_type": "changed_or_unchanged",
                "expected": "changed",
                "rationale": "Case field changes should be visible for review.",
                "caveat": "Changed offline report behavior is not automatically a bug.",
            },
            {
                "target_type": "case",
                "target_name": added_case_id,
                "metric": "presence",
                "comparison_type": "equals",
                "expected": "added",
                "rationale": "Case additions are explicit targets only when configured.",
                "caveat": "Case additions require human interpretation.",
            },
            {
                "target_type": "case",
                "target_name": removed_case_id,
                "metric": "presence",
                "comparison_type": "equals",
                "expected": "removed",
                "rationale": "Case removals are explicit targets only when configured.",
                "caveat": "Case removals require human interpretation.",
            },
            {
                "target_type": "case",
                "target_name": "missing_case_for_threshold_evaluation",
                "metric": "presence",
                "comparison_type": "equals",
                "expected": "matched",
                "rationale": "Missing cases should be non-gating review signals.",
                "caveat": "Missing cases are not interpreted as benchmark failure.",
            },
            {
                "target_type": "case",
                "target_name": matched_case_id,
                "metric": "score_passed",
                "comparison_type": "may_be_unavailable",
                "rationale": "Available case fields may remain available.",
                "caveat": "Availability is not proof of broad correctness.",
            },
        ],
    }


def _valid_sts_probe_plan() -> dict[str, Any]:
    return {
        "schema_version": "0.1",
        "plan_type": "sts_assume_role_probe_plan",
        "mode": "dry_run",
        "probes": [
            {
                "probe_id": "sts-assume-role-test-admin",
                "source_principal_arn": "arn:aws:iam::123456789012:role/iamscope-test-source",
                "target_role_arn": "arn:aws:iam::123456789012:role/iamscope-test-target",
                "aws_profile": "iamscope-test",
                "expected_account_id": "123456789012",
                "session_name_prefix": "iamscope-test",
                "duration_seconds": 900,
                "expected_outcome": "assumed",
                "evidence_boundary": "Dry-run validation only; not runtime proof.",
                "safety_notes": "Uses test identities, test roles, and a test account only.",
            }
        ],
    }


class _FakeStsClient:
    def __init__(self, response: dict[str, Any] | None = None, error: Exception | None = None) -> None:
        self.response = response or {}
        self.error = error
        self.calls: list[dict[str, Any]] = []

    def assume_role(self, **kwargs: Any) -> dict[str, Any]:
        self.calls.append(kwargs)
        if self.error is not None:
            raise self.error
        return self.response


class _FakeAwsError(Exception):
    def __init__(self, code: str) -> None:
        self.response = {"Error": {"Code": code}}
        super().__init__(code)


def _contains_key(value: Any, key: str) -> bool:
    if isinstance(value, dict):
        return key in value or any(_contains_key(child, key) for child in value.values())
    if isinstance(value, list):
        return any(_contains_key(child, key) for child in value)
    return False


def _stable_fixture_digest(result: dict[str, Any]) -> str:
    return str(result["metrics"]["deterministic_output_stability"]["fixture_digest"])


def test_small_fixture_generation_is_deterministic() -> None:
    first = generate_fixture("small")
    second = generate_fixture("small")

    assert first == second
    assert first["seed"] == 20260509
    assert first["config"]["fixture_class"] == "small_regression_fixture"
    assert len(first["nodes"]) == 5
    assert len(first["permission_edges"]) == 2
    assert len(first["trust_edges"]) == 2


def test_medium_fixture_generation_is_deterministic() -> None:
    first = generate_fixture("medium")
    second = generate_fixture("medium")

    assert first == second
    assert first["seed"] == 20260509
    assert first["config"]["fixture_class"] == "medium_synthetic_org_graph"
    assert len(first["nodes"]) == 34
    assert len(first["permission_edges"]) == 34
    assert len(first["trust_edges"]) == 34
    assert len(first["resource_policy_edges"]) == 4
    assert len(first["constraints"]) == 6


def test_constraint_heavy_fixture_generation_is_deterministic() -> None:
    first = generate_fixture("constraint_heavy")
    second = generate_fixture("constraint_heavy")

    assert first == second
    assert first["seed"] == 20260509
    assert first["config"]["fixture_class"] == "constraint_heavy_synthetic_fixture"
    assert first["config"]["account_count"] == 2
    assert first["config"]["principals_per_account"] == 5
    assert first["config"]["roles_per_account"] == 12
    assert first["config"]["path_depth"] == 3
    assert first["config"]["branching_factor"] == 2
    assert len(first["nodes"]) == 42
    assert len(first["permission_edges"]) == 42
    assert len(first["trust_edges"]) == 42
    assert len(first["resource_policy_edges"]) == 6
    assert len(first["constraints"]) == 32


def test_dense_trust_fixture_generation_is_deterministic() -> None:
    first = generate_fixture("dense_trust")
    second = generate_fixture("dense_trust")

    assert first == second
    assert first["seed"] == 20260509
    assert first["config"]["fixture_class"] == "dense_trust_synthetic_fixture"
    assert first["config"]["account_count"] == 2
    assert first["config"]["principals_per_account"] == 4
    assert first["config"]["roles_per_account"] == 12
    assert first["config"]["path_depth"] == 3
    assert first["config"]["branching_factor"] == 3
    assert first["config"]["extra_trust_edges_per_principal"] == 4
    assert len(first["nodes"]) == 38
    assert len(first["permission_edges"]) == 64
    assert len(first["trust_edges"]) == 88
    assert len(first["resource_policy_edges"]) == 4
    assert len(first["constraints"]) == 4


def test_multihop_stress_fixture_generation_is_deterministic() -> None:
    first = generate_fixture("multihop_stress")
    second = generate_fixture("multihop_stress")

    assert first == second
    assert first["seed"] == 20260509
    assert first["config"]["fixture_class"] == "multihop_stress_synthetic_fixture"
    assert first["config"]["account_count"] == 2
    assert first["config"]["principals_per_account"] == 3
    assert first["config"]["roles_per_account"] == 18
    assert first["config"]["path_depth"] == 6
    assert first["config"]["branching_factor"] == 2
    assert len(first["nodes"]) == 48
    assert len(first["permission_edges"]) == 34
    assert len(first["trust_edges"]) == 34
    assert len(first["resource_policy_edges"]) == 4
    assert len(first["constraints"]) == 4


def test_negative_no_valid_path_fixture_generation_is_deterministic() -> None:
    first = generate_fixture("negative_no_valid_path")
    second = generate_fixture("negative_no_valid_path")

    assert first == second
    assert first["seed"] == 20260509
    assert first["config"]["fixture_class"] == "negative_no_valid_path_synthetic_fixture"
    assert first["config"]["account_count"] == 2
    assert first["config"]["principals_per_account"] == 4
    assert first["config"]["roles_per_account"] == 12
    assert first["config"]["path_depth"] == 4
    assert first["config"]["branching_factor"] == 2
    assert first["config"]["disjoint_path_roles"] is True
    assert first["config"]["omit_terminal_assume_role_pair"] is True
    assert first["config"]["expected_valid_synthetic_paths"] == 0
    assert len(first["nodes"]) == 38
    assert len(first["permission_edges"]) == 34
    assert len(first["trust_edges"]) == 34
    assert len(first["resource_policy_edges"]) == 4
    assert len(first["constraints"]) == 4


def test_metric_output_schema_is_stable_without_composite_score() -> None:
    report = build_report(
        ["small", "medium", "constraint_heavy", "dense_trust", "multihop_stress", "negative_no_valid_path"]
    )

    assert report["report_type"] == "synthetic_scalability_benchmark"
    assert report["schema_version"] == "0.1"
    assert report["fixture_names"] == [
        "small",
        "medium",
        "constraint_heavy",
        "dense_trust",
        "multihop_stress",
        "negative_no_valid_path",
    ]
    assert "composite_score" not in json.dumps(report)

    for fixture_result in report["fixtures"]:
        metrics = fixture_result["metrics"]
        assert set(metrics) == {
            "artifact_load_time_ms",
            "candidate_paths_considered",
            "constraint_evaluations",
            "deterministic_output_stability",
            "failure_mode_classification",
            "paths_rejected",
            "paths_validated",
            "peak_memory_bytes",
            "report_generation_time_ms",
            "wall_clock_runtime_ms",
        }
        assert metrics["wall_clock_runtime_ms"] >= 0
        assert metrics["paths_validated"] == "not_collected"
        assert metrics["paths_rejected"] == "not_collected"
        assert metrics["failure_mode_classification"] == "none"
        assert "fixture_digest" in metrics["deterministic_output_stability"]
        assert "stable_metric_digest" in metrics["deterministic_output_stability"]


def test_fixture_metric_digests_are_deterministic() -> None:
    first_small = run_fixture("small")
    second_small = run_fixture("small")
    first_medium = run_fixture("medium")
    second_medium = run_fixture("medium")
    first_constraint_heavy = run_fixture("constraint_heavy")
    second_constraint_heavy = run_fixture("constraint_heavy")
    first_dense_trust = run_fixture("dense_trust")
    second_dense_trust = run_fixture("dense_trust")
    first_multihop_stress = run_fixture("multihop_stress")
    second_multihop_stress = run_fixture("multihop_stress")
    first_negative = run_fixture("negative_no_valid_path")
    second_negative = run_fixture("negative_no_valid_path")

    assert _stable_fixture_digest(first_small) == _stable_fixture_digest(second_small)
    assert _stable_fixture_digest(first_medium) == _stable_fixture_digest(second_medium)
    assert _stable_fixture_digest(first_constraint_heavy) == _stable_fixture_digest(second_constraint_heavy)
    assert _stable_fixture_digest(first_dense_trust) == _stable_fixture_digest(second_dense_trust)
    assert _stable_fixture_digest(first_multihop_stress) == _stable_fixture_digest(second_multihop_stress)
    assert _stable_fixture_digest(first_negative) == _stable_fixture_digest(second_negative)
    assert first_small["metrics"]["candidate_paths_considered"] == second_small["metrics"]["candidate_paths_considered"]
    assert (
        first_medium["metrics"]["candidate_paths_considered"] == second_medium["metrics"]["candidate_paths_considered"]
    )
    assert (
        first_constraint_heavy["metrics"]["candidate_paths_considered"]
        == second_constraint_heavy["metrics"]["candidate_paths_considered"]
    )
    assert (
        first_dense_trust["metrics"]["candidate_paths_considered"]
        == second_dense_trust["metrics"]["candidate_paths_considered"]
    )
    assert (
        first_multihop_stress["metrics"]["candidate_paths_considered"]
        == second_multihop_stress["metrics"]["candidate_paths_considered"]
    )
    assert (
        first_negative["metrics"]["candidate_paths_considered"]
        == second_negative["metrics"]["candidate_paths_considered"]
    )


def test_constraint_heavy_has_more_constraint_pressure_than_medium() -> None:
    medium = run_fixture("medium")
    constraint_heavy = run_fixture("constraint_heavy")

    assert constraint_heavy["metrics"]["candidate_paths_considered"] == 60
    assert constraint_heavy["metrics"]["constraint_evaluations"] == 1920
    assert constraint_heavy["metrics"]["constraint_evaluations"] > medium["metrics"]["constraint_evaluations"]


def test_dense_trust_has_more_trust_edges_without_becoming_constraint_heavy() -> None:
    medium_fixture = generate_fixture("medium")
    dense_trust_fixture = generate_fixture("dense_trust")
    constraint_heavy = run_fixture("constraint_heavy")
    dense_trust = run_fixture("dense_trust")

    assert len(dense_trust_fixture["trust_edges"]) == 88
    assert len(medium_fixture["trust_edges"]) == 34
    assert len(dense_trust_fixture["trust_edges"]) > len(medium_fixture["trust_edges"]) * 2
    assert dense_trust["metrics"]["candidate_paths_considered"] == 136
    assert dense_trust["metrics"]["constraint_evaluations"] == 544
    assert dense_trust["metrics"]["constraint_evaluations"] < constraint_heavy["metrics"]["constraint_evaluations"]


def test_multihop_stress_has_deeper_paths_without_becoming_dense_or_constraint_heavy() -> None:
    medium = run_fixture("medium")
    dense_trust_fixture = generate_fixture("dense_trust")
    constraint_heavy = run_fixture("constraint_heavy")
    multihop_fixture = generate_fixture("multihop_stress")
    multihop = run_fixture("multihop_stress")

    assert multihop["fixture_size"]["path_depth"] == 6
    assert medium["fixture_size"]["path_depth"] == 3
    assert multihop["fixture_size"]["path_depth"] > medium["fixture_size"]["path_depth"]
    assert len(multihop_fixture["trust_edges"]) == 34
    assert len(dense_trust_fixture["trust_edges"]) == 88
    assert len(multihop_fixture["trust_edges"]) < len(dense_trust_fixture["trust_edges"])
    assert multihop["metrics"]["candidate_paths_considered"] == 72
    assert multihop["metrics"]["constraint_evaluations"] == 288
    assert multihop["metrics"]["constraint_evaluations"] < constraint_heavy["metrics"]["constraint_evaluations"]


def test_negative_no_valid_path_has_search_work_without_full_depth_valid_paths() -> None:
    fixture = generate_fixture("negative_no_valid_path")
    result = run_fixture("negative_no_valid_path")
    candidate_paths = _candidate_paths(fixture)
    full_depth_paths = [path for path in candidate_paths if len(path) == fixture["config"]["path_depth"]]

    assert result["metrics"]["candidate_paths_considered"] == 48
    assert result["metrics"]["constraint_evaluations"] == 192
    assert len(candidate_paths) == 48
    assert full_depth_paths == []
    assert max(len(path) for path in candidate_paths) == 3
    assert result["synthetic_path_expectation"] == {
        "expected_valid_synthetic_paths": 0,
        "representation": "full_depth_candidate_paths",
    }
    assert len(fixture["nodes"]) > 0
    assert len(fixture["permission_edges"]) > 0
    assert len(fixture["trust_edges"]) > 0


def test_benchmark_command_runs_both_fixtures_without_semantic_claims(tmp_path: Path) -> None:
    json_out = tmp_path / "scalability-report.json"

    completed = subprocess.run(
        [
            sys.executable,
            "-m",
            "benchmarks.scalability.harness",
            "--fixture",
            "small",
            "--fixture",
            "medium",
            "--fixture",
            "constraint_heavy",
            "--fixture",
            "dense_trust",
            "--fixture",
            "multihop_stress",
            "--fixture",
            "negative_no_valid_path",
            "--json-out",
            str(json_out),
        ],
        check=True,
        text=True,
        capture_output=True,
    )

    payload = json.loads(json_out.read_text())
    serialized = json.dumps(payload, sort_keys=True)
    assert "scalability_report_json=" in completed.stdout
    assert payload["fixture_names"] == [
        "small",
        "medium",
        "constraint_heavy",
        "dense_trust",
        "multihop_stress",
        "negative_no_valid_path",
    ]
    assert payload["fixture_count"] == 6
    assert any(item["fixture_name"] == "constraint_heavy" for item in payload["fixtures"])
    assert any(item["fixture_name"] == "dense_trust" for item in payload["fixtures"])
    assert any(item["fixture_name"] == "multihop_stress" for item in payload["fixtures"])
    assert any(item["fixture_name"] == "negative_no_valid_path" for item in payload["fixtures"])
    assert "admin_reachability" not in serialized
    assert "assume_role_chain" not in serialized
    assert "cross_account_trust" not in serialized
    assert "production_ready" not in serialized
    assert "does not prove" in serialized
    assert "composite_score" not in serialized


def test_report_output_is_artifact_hygiene_friendly() -> None:
    report = build_report(["small"])
    serialized = json.dumps(report, sort_keys=True)

    assert "scenario.json" not in serialized
    assert "findings.json" not in serialized
    assert "binding_metadata.json" not in serialized
    assert "run.log" not in serialized
    assert "terraform.tfstate" not in serialized
    assert ".terraform" not in serialized


def test_markdown_report_generation_is_stable_for_fixed_input() -> None:
    report = build_report(
        ["small", "medium", "constraint_heavy", "dense_trust", "multihop_stress", "negative_no_valid_path"]
    )

    first = render_markdown_report(report)
    second = render_markdown_report(report)

    assert first == second
    assert "# IAMScope Synthetic Scalability Report" in first
    assert "| small | small_regression_fixture | 20260509 |" in first
    assert "| medium | medium_synthetic_org_graph | 20260509 |" in first
    assert "| constraint_heavy | constraint_heavy_synthetic_fixture | 20260509 |" in first
    assert "| dense_trust | dense_trust_synthetic_fixture | 20260509 |" in first
    assert "| multihop_stress | multihop_stress_synthetic_fixture | 20260509 |" in first
    assert "| negative_no_valid_path | negative_no_valid_path_synthetic_fixture | 20260509 |" in first
    assert "No composite score" in first
    assert "Synthetic-only" in first
    assert "Does not prove real-world scalability or correctness" in first
    assert "composite_score" not in first
    assert "overall_score" not in first
    assert "pass_rate" not in first


def test_benchmark_command_can_write_json_and_markdown(tmp_path: Path) -> None:
    json_out = tmp_path / "scalability-report.json"
    markdown_out = tmp_path / "scalability-report.md"

    completed = subprocess.run(
        [
            sys.executable,
            "-m",
            "benchmarks.scalability.harness",
            "--fixture",
            "small",
            "--fixture",
            "medium",
            "--fixture",
            "constraint_heavy",
            "--fixture",
            "dense_trust",
            "--fixture",
            "multihop_stress",
            "--fixture",
            "negative_no_valid_path",
            "--json-out",
            str(json_out),
            "--markdown-out",
            str(markdown_out),
        ],
        check=True,
        text=True,
        capture_output=True,
    )

    payload = json.loads(json_out.read_text())
    markdown = markdown_out.read_text()
    assert payload["fixture_names"] == [
        "small",
        "medium",
        "constraint_heavy",
        "dense_trust",
        "multihop_stress",
        "negative_no_valid_path",
    ]
    assert "scalability_report_json=" in completed.stdout
    assert "scalability_report_markdown=" in completed.stdout
    assert "| small |" in markdown
    assert "| medium |" in markdown
    assert "| constraint_heavy |" in markdown
    assert "| dense_trust |" in markdown
    assert "| multihop_stress |" in markdown
    assert "| negative_no_valid_path |" in markdown
    assert "No composite score" in markdown
    assert "Does not prove real-world scalability or correctness" in markdown
    assert "composite_score" not in markdown
    assert "overall_score" not in markdown


def test_frozen_corpus_batch_report_reads_safe_snapshot_artifacts() -> None:
    report = build_frozen_corpus_report(FROZEN_CORPUS_SNAPSHOT)
    serialized = json.dumps(report, sort_keys=True)

    assert report["report_type"] == "frozen_corpus_batch_report"
    assert report["snapshot_path"] == str(FROZEN_CORPUS_SNAPSHOT)
    assert report["offline_only"] is True
    assert report["live_aws_used"] is False
    assert report["case_count"] == 24
    assert report["batch_summary"]["total_cases_evaluated"] == 24
    assert report["batch_summary"]["passes"] == 24
    assert report["batch_summary"]["failures"] == 0
    assert "composite_score" not in report
    assert "composite_score" not in serialized
    assert any(case["case_id"] == "env27_multihop_trust_scoped_away_nonvalidated" for case in report["cases"])
    assert all(case["safe_snapshot_artifacts"]["run_manifest_json"] for case in report["cases"])
    assert all(case["safe_snapshot_artifacts"]["scorer_result_json"] for case in report["cases"])
    assert all(case["safe_snapshot_artifacts"]["gate_result_json"] for case in report["cases"])
    assert all(case["safe_snapshot_artifacts"]["report_md"] for case in report["cases"])
    assert any(item["metric"] == "candidate_paths_considered" for item in report["unavailable_metrics"])
    assert "not_collected" in json.dumps(report["unavailable_metrics"], sort_keys=True)


def test_frozen_corpus_batch_command_writes_json_and_markdown_without_repo_artifacts(tmp_path: Path) -> None:
    json_out = tmp_path / "frozen-corpus-batch.json"
    markdown_out = tmp_path / "frozen-corpus-batch.md"

    completed = subprocess.run(
        [
            sys.executable,
            "-m",
            "benchmarks.scalability.frozen_corpus_batch",
            "--snapshot",
            str(FROZEN_CORPUS_SNAPSHOT),
            "--json-out",
            str(json_out),
            "--markdown-out",
            str(markdown_out),
        ],
        check=True,
        text=True,
        capture_output=True,
    )

    payload = json.loads(json_out.read_text())
    markdown = markdown_out.read_text()
    assert "frozen_corpus_batch_report_json=" in completed.stdout
    assert "frozen_corpus_batch_report_markdown=" in completed.stdout
    assert payload["offline_only"] is True
    assert payload["live_aws_used"] is False
    assert "composite_score" not in json.dumps(payload, sort_keys=True)
    assert "# IAMScope Frozen Corpus Batch Report" in markdown
    assert "Offline only" in markdown
    assert "No live AWS" in markdown
    assert "No composite score" in markdown
    assert "Does not prove real-world scalability or correctness" in markdown
    assert "Does not replace live semantic benchmark interpretation" in markdown
    assert "composite_score" not in markdown
    assert not (Path.cwd() / "frozen-corpus-batch.json").exists()
    assert not (Path.cwd() / "frozen-corpus-batch.md").exists()


def test_frozen_corpus_batch_command_fails_for_invalid_snapshot(tmp_path: Path) -> None:
    missing_snapshot = tmp_path / "missing-snapshot"

    completed = subprocess.run(
        [
            sys.executable,
            "-m",
            "benchmarks.scalability.frozen_corpus_batch",
            "--snapshot",
            str(missing_snapshot),
        ],
        check=False,
        text=True,
        capture_output=True,
    )

    assert completed.returncode != 0
    assert "snapshot path does not exist" in completed.stderr


def test_synthetic_baseline_comparator_reports_deltas_without_scores(tmp_path: Path) -> None:
    baseline = build_report(["small", "medium"])
    current = json.loads(json.dumps(baseline))
    current_medium = next(item for item in current["fixtures"] if item["fixture_name"] == "medium")
    current_medium["metrics"]["candidate_paths_considered"] += 7
    current_medium["metrics"]["constraint_evaluations"] += 42
    current_medium["metrics"]["deterministic_output_stability"]["stable_metric_digest"] = "changed-digest"

    baseline_path = tmp_path / "baseline.json"
    current_path = tmp_path / "current.json"
    baseline_path.write_text(json.dumps(baseline))
    current_path.write_text(json.dumps(current))

    comparison = build_comparison_from_paths(baseline_path, current_path)
    serialized = json.dumps(comparison, sort_keys=True)
    medium = next(item for item in comparison["fixture_comparisons"] if item["fixture_name"] == "medium")
    by_metric = {item["metric"]: item for item in medium["metric_comparisons"]}

    assert comparison["report_type"] == "synthetic_scalability_baseline_comparison"
    assert comparison["report_only"] is True
    assert comparison["thresholds_used"] is False
    assert "composite_score" not in comparison
    assert "composite_score" not in serialized
    assert comparison["fixture_count"] == 2
    assert medium["classification"] == "changed"
    assert by_metric["candidate_paths_considered"]["classification"] == "changed"
    assert by_metric["candidate_paths_considered"]["delta"] == 7
    assert by_metric["constraint_evaluations"]["delta"] == 42
    assert by_metric["deterministic_output_stability.stable_metric_digest"]["classification"] == "changed"
    assert by_metric["paths_validated"]["classification"] == "unavailable"
    assert "delta" not in by_metric["paths_validated"]
    assert by_metric["paths_validated"]["baseline_value"] == "not_collected"
    assert by_metric["paths_validated"]["current_value"] == "not_collected"


def test_synthetic_baseline_comparator_command_writes_json_and_markdown(tmp_path: Path) -> None:
    baseline = build_report(["small", "medium"])
    current = json.loads(json.dumps(baseline))
    current_small = next(item for item in current["fixtures"] if item["fixture_name"] == "small")
    current_small["metrics"]["deterministic_output_stability"]["fixture_digest"] = "changed-fixture-digest"
    baseline_path = tmp_path / "baseline.json"
    current_path = tmp_path / "current.json"
    json_out = tmp_path / "comparison.json"
    markdown_out = tmp_path / "comparison.md"
    baseline_path.write_text(json.dumps(baseline))
    current_path.write_text(json.dumps(current))

    completed = subprocess.run(
        [
            "bash",
            "scripts/compare_scalability_baseline.sh",
            "--baseline",
            str(baseline_path),
            "--current",
            str(current_path),
            "--json-out",
            str(json_out),
            "--markdown-out",
            str(markdown_out),
        ],
        check=True,
        text=True,
        capture_output=True,
    )

    payload = json.loads(json_out.read_text())
    markdown = markdown_out.read_text()
    assert "scalability_baseline_comparison_json=" in completed.stdout
    assert "scalability_baseline_comparison_markdown=" in completed.stdout
    assert payload["report_only"] is True
    assert payload["thresholds_used"] is False
    assert "composite_score" not in json.dumps(payload, sort_keys=True)
    assert "Report-only" in markdown
    assert "No thresholds" in markdown
    assert "No composite score" in markdown
    assert "Does not prove real-world scalability or correctness" in markdown
    assert "| small | changed | deterministic_output_stability.fixture_digest |" in markdown
    assert "composite_score" not in markdown
    assert "pass_rate" not in markdown


def test_synthetic_baseline_comparator_fails_for_invalid_input(tmp_path: Path) -> None:
    missing = tmp_path / "missing.json"
    current_path = tmp_path / "current.json"
    current_path.write_text(json.dumps(build_report(["small"])))

    completed = subprocess.run(
        [
            sys.executable,
            "-m",
            "benchmarks.scalability.baseline_compare",
            "--baseline",
            str(missing),
            "--current",
            str(current_path),
        ],
        check=False,
        text=True,
        capture_output=True,
    )

    assert completed.returncode != 0
    assert "baseline input path does not exist" in completed.stderr


def test_frozen_corpus_baseline_comparator_reports_case_and_batch_deltas(tmp_path: Path) -> None:
    baseline = build_frozen_corpus_report(FROZEN_CORPUS_SNAPSHOT)
    current = json.loads(json.dumps(baseline))
    matched_case = next(
        case for case in current["cases"] if case["case_id"] == "env27_multihop_trust_scoped_away_nonvalidated"
    )
    matched_case["environment"] = "env27-review-copy"
    removed_case = current["cases"].pop(0)
    added_case = json.loads(json.dumps(matched_case))
    added_case["case_id"] = "synthetic_added_case_for_comparison"
    added_case["run_id"] = "synthetic-added-run"
    current["cases"].append(added_case)
    current["batch_summary"]["cases"] += 1
    current["batch_summary"]["failures"] += 2
    current["unavailable_metrics"][0]["reason"] = "not_collected: changed reason for regression test"

    baseline_path = tmp_path / "frozen-baseline.json"
    current_path = tmp_path / "frozen-current.json"
    baseline_path.write_text(json.dumps(baseline))
    current_path.write_text(json.dumps(current))

    comparison = build_frozen_corpus_comparison_from_paths(baseline_path, current_path)
    serialized = json.dumps(comparison, sort_keys=True)
    by_case = {case["case_id"]: case for case in comparison["case_comparisons"]}
    by_batch_metric = {item["metric"]: item for item in comparison["batch_summary_comparisons"]}
    unavailable_by_metric = {item["metric"]: item for item in comparison["unavailable_metric_comparisons"]}

    assert comparison["report_type"] == "frozen_corpus_baseline_comparison"
    assert comparison["report_only"] is True
    assert comparison["thresholds_used"] is False
    assert comparison["live_aws_used"] is False
    assert "composite_score" not in comparison
    assert "composite_score" not in serialized
    assert by_batch_metric["cases"]["classification"] == "changed"
    assert by_batch_metric["cases"]["delta"] == 1
    assert by_batch_metric["failures"]["delta"] == 2
    assert by_case["env27_multihop_trust_scoped_away_nonvalidated"]["presence"] == "matched"
    assert by_case["env27_multihop_trust_scoped_away_nonvalidated"]["classification"] == "changed"
    assert "environment" in by_case["env27_multihop_trust_scoped_away_nonvalidated"]["changed_fields"]
    assert by_case[removed_case["case_id"]]["presence"] == "removed"
    assert by_case["synthetic_added_case_for_comparison"]["presence"] == "added"
    assert "synthetic_added_case_for_comparison" in comparison["case_presence_summary"]["added"]
    assert removed_case["case_id"] in comparison["case_presence_summary"]["removed"]
    assert unavailable_by_metric["wall_clock_runtime_ms"]["classification"] == "changed"
    assert "delta" not in unavailable_by_metric["wall_clock_runtime_ms"]


def test_frozen_corpus_baseline_comparator_command_writes_json_and_markdown(tmp_path: Path) -> None:
    baseline = build_frozen_corpus_report(FROZEN_CORPUS_SNAPSHOT)
    current = json.loads(json.dumps(baseline))
    current["batch_summary"]["human_review_required_count"] += 1
    baseline_path = tmp_path / "frozen-baseline.json"
    current_path = tmp_path / "frozen-current.json"
    json_out = tmp_path / "frozen-comparison.json"
    markdown_out = tmp_path / "frozen-comparison.md"
    baseline_path.write_text(json.dumps(baseline))
    current_path.write_text(json.dumps(current))

    completed = subprocess.run(
        [
            "bash",
            "scripts/compare_frozen_corpus_baseline.sh",
            "--baseline",
            str(baseline_path),
            "--current",
            str(current_path),
            "--json-out",
            str(json_out),
            "--markdown-out",
            str(markdown_out),
        ],
        check=True,
        text=True,
        capture_output=True,
    )

    payload = json.loads(json_out.read_text())
    markdown = markdown_out.read_text()
    assert "frozen_corpus_baseline_comparison_json=" in completed.stdout
    assert "frozen_corpus_baseline_comparison_markdown=" in completed.stdout
    assert payload["report_only"] is True
    assert payload["thresholds_used"] is False
    assert payload["live_aws_used"] is False
    assert "composite_score" not in json.dumps(payload, sort_keys=True)
    assert "# IAMScope Frozen Corpus Baseline Comparison" in markdown
    assert "Offline-only" in markdown
    assert "Report-only" in markdown
    assert "No thresholds" in markdown
    assert "No composite score" in markdown
    assert "No new live AWS evidence" in markdown
    assert "Does not prove real-world scalability or correctness" in markdown
    assert "composite_score" not in markdown
    assert "pass_rate" not in markdown


def test_frozen_corpus_baseline_comparator_fails_for_invalid_input(tmp_path: Path) -> None:
    missing = tmp_path / "missing.json"
    current_path = tmp_path / "current.json"
    current_path.write_text(json.dumps(build_frozen_corpus_report(FROZEN_CORPUS_SNAPSHOT)))

    completed = subprocess.run(
        [
            sys.executable,
            "-m",
            "benchmarks.scalability.frozen_corpus_baseline_compare",
            "--baseline",
            str(missing),
            "--current",
            str(current_path),
        ],
        check=False,
        text=True,
        capture_output=True,
    )

    assert completed.returncode != 0
    assert "baseline input path does not exist" in completed.stderr


def test_reporting_scripts_write_only_to_caller_provided_paths(tmp_path: Path) -> None:
    synthetic_baseline = tmp_path / "synthetic-baseline.json"
    synthetic_current = tmp_path / "synthetic-current.json"
    frozen_baseline = tmp_path / "frozen-baseline.json"
    frozen_current = tmp_path / "frozen-current.json"
    threshold_config = tmp_path / "threshold-config.json"
    frozen_threshold_config = tmp_path / "frozen-threshold-config.json"
    _, _, synthetic_comparison = _synthetic_comparison_fixture_files(tmp_path)
    _, _, frozen_comparison, matched_case_id, added_case_id, removed_case_id = _frozen_corpus_comparison_fixture_files(
        tmp_path
    )
    synthetic_baseline.write_text(json.dumps(build_report(["small"])))
    synthetic_current.write_text(json.dumps(build_report(["small"])))
    frozen_baseline.write_text(json.dumps(build_frozen_corpus_report(FROZEN_CORPUS_SNAPSHOT)))
    frozen_current.write_text(json.dumps(build_frozen_corpus_report(FROZEN_CORPUS_SNAPSHOT)))
    threshold_config.write_text(json.dumps(_threshold_evaluator_config()))
    frozen_threshold_config.write_text(
        json.dumps(_frozen_threshold_evaluator_config(matched_case_id, added_case_id, removed_case_id))
    )

    commands = [
        (
            [
                "bash",
                "scripts/run_scalability_benchmark.sh",
                "--fixture",
                "small",
                "--json-out",
                str(tmp_path / "scalability.json"),
                "--markdown-out",
                str(tmp_path / "scalability.md"),
            ],
            (tmp_path / "scalability.json", tmp_path / "scalability.md"),
        ),
        (
            [
                "bash",
                "scripts/run_frozen_corpus_batch_report.sh",
                "--snapshot",
                str(FROZEN_CORPUS_SNAPSHOT),
                "--json-out",
                str(tmp_path / "frozen-batch.json"),
                "--markdown-out",
                str(tmp_path / "frozen-batch.md"),
            ],
            (tmp_path / "frozen-batch.json", tmp_path / "frozen-batch.md"),
        ),
        (
            [
                "bash",
                "scripts/compare_scalability_baseline.sh",
                "--baseline",
                str(synthetic_baseline),
                "--current",
                str(synthetic_current),
                "--json-out",
                str(tmp_path / "synthetic-comparison.json"),
                "--markdown-out",
                str(tmp_path / "synthetic-comparison.md"),
            ],
            (tmp_path / "synthetic-comparison.json", tmp_path / "synthetic-comparison.md"),
        ),
        (
            [
                "bash",
                "scripts/compare_frozen_corpus_baseline.sh",
                "--baseline",
                str(frozen_baseline),
                "--current",
                str(frozen_current),
                "--json-out",
                str(tmp_path / "frozen-comparison.json"),
                "--markdown-out",
                str(tmp_path / "frozen-comparison.md"),
            ],
            (tmp_path / "frozen-comparison.json", tmp_path / "frozen-comparison.md"),
        ),
        (
            [
                "bash",
                "scripts/evaluate_synthetic_thresholds.sh",
                "--threshold-config",
                str(threshold_config),
                "--comparison",
                str(synthetic_comparison),
                "--json-out",
                str(tmp_path / "threshold-evaluation.json"),
                "--markdown-out",
                str(tmp_path / "threshold-evaluation.md"),
            ],
            (tmp_path / "threshold-evaluation.json", tmp_path / "threshold-evaluation.md"),
        ),
        (
            [
                "bash",
                "scripts/evaluate_frozen_corpus_thresholds.sh",
                "--threshold-config",
                str(frozen_threshold_config),
                "--comparison",
                str(frozen_comparison),
                "--json-out",
                str(tmp_path / "frozen-threshold-evaluation.json"),
                "--markdown-out",
                str(tmp_path / "frozen-threshold-evaluation.md"),
            ],
            (tmp_path / "frozen-threshold-evaluation.json", tmp_path / "frozen-threshold-evaluation.md"),
        ),
    ]

    before = _repo_artifact_policy_snapshot()
    for command, outputs in commands:
        subprocess.run(
            command,
            check=True,
            text=True,
            capture_output=True,
            env=_subprocess_env_without_bytecode(),
        )
        assert all(path.exists() for path in outputs)
        _assert_repo_artifact_policy_snapshot_unchanged(before)


def test_reporting_scripts_without_output_paths_do_not_create_repo_outputs(tmp_path: Path) -> None:
    synthetic_baseline = tmp_path / "synthetic-baseline.json"
    synthetic_current = tmp_path / "synthetic-current.json"
    frozen_baseline = tmp_path / "frozen-baseline.json"
    frozen_current = tmp_path / "frozen-current.json"
    threshold_config = tmp_path / "threshold-config.json"
    frozen_threshold_config = tmp_path / "frozen-threshold-config.json"
    _, _, synthetic_comparison = _synthetic_comparison_fixture_files(tmp_path)
    _, _, frozen_comparison, matched_case_id, added_case_id, removed_case_id = _frozen_corpus_comparison_fixture_files(
        tmp_path
    )
    synthetic_baseline.write_text(json.dumps(build_report(["small"])))
    synthetic_current.write_text(json.dumps(build_report(["small"])))
    frozen_baseline.write_text(json.dumps(build_frozen_corpus_report(FROZEN_CORPUS_SNAPSHOT)))
    frozen_current.write_text(json.dumps(build_frozen_corpus_report(FROZEN_CORPUS_SNAPSHOT)))
    threshold_config.write_text(json.dumps(_threshold_evaluator_config()))
    frozen_threshold_config.write_text(
        json.dumps(_frozen_threshold_evaluator_config(matched_case_id, added_case_id, removed_case_id))
    )

    commands = [
        ["bash", "scripts/run_scalability_benchmark.sh", "--fixture", "small"],
        ["bash", "scripts/run_frozen_corpus_batch_report.sh", "--snapshot", str(FROZEN_CORPUS_SNAPSHOT)],
        [
            "bash",
            "scripts/compare_scalability_baseline.sh",
            "--baseline",
            str(synthetic_baseline),
            "--current",
            str(synthetic_current),
        ],
        [
            "bash",
            "scripts/compare_frozen_corpus_baseline.sh",
            "--baseline",
            str(frozen_baseline),
            "--current",
            str(frozen_current),
        ],
        [
            "bash",
            "scripts/evaluate_synthetic_thresholds.sh",
            "--threshold-config",
            str(threshold_config),
            "--comparison",
            str(synthetic_comparison),
        ],
        [
            "bash",
            "scripts/evaluate_frozen_corpus_thresholds.sh",
            "--threshold-config",
            str(frozen_threshold_config),
            "--comparison",
            str(frozen_comparison),
        ],
    ]

    before = _repo_artifact_policy_snapshot()
    for command in commands:
        completed = subprocess.run(
            command,
            check=True,
            text=True,
            capture_output=True,
            env=_subprocess_env_without_bytecode(),
        )
        assert '"report_type"' in completed.stdout
        _assert_repo_artifact_policy_snapshot_unchanged(before)


def test_threshold_config_parser_accepts_explicit_report_only_config(tmp_path: Path) -> None:
    config = _valid_threshold_config()
    config_path = tmp_path / "threshold-config.json"
    config_path.write_text(json.dumps(config))

    parsed = load_threshold_config(config_path)

    assert parsed == config
    assert parsed["mode"] == "report_only"
    assert parsed["thresholds"][2]["expected"] == "not_collected"
    assert parsed["thresholds"][0]["delta_limit"] == 0
    assert not _contains_key(parsed, "composite_score")


def test_threshold_config_parser_preserves_unavailable_missing_zero_and_not_collected() -> None:
    config = _valid_threshold_config()
    config["thresholds"].extend(
        [
            {
                "target_type": "fixture",
                "target_name": "small",
                "metric": "synthetic_zero_metric",
                "comparison_type": "equals",
                "expected": 0,
                "rationale": "Zero remains distinct from unavailable states.",
                "caveat": "Zero is a concrete value.",
            },
            {
                "target_type": "fixture",
                "target_name": "small",
                "metric": "synthetic_missing_metric",
                "comparison_type": "equals",
                "expected": "missing",
                "rationale": "Missing remains distinct from zero.",
                "caveat": "Missing is not zero.",
            },
            {
                "target_type": "fixture",
                "target_name": "small",
                "metric": "synthetic_unavailable_metric",
                "comparison_type": "equals",
                "expected": "unavailable",
                "rationale": "Unavailable remains distinct from zero.",
                "caveat": "Unavailable is not zero.",
            },
        ]
    )

    parsed = validate_threshold_config(config)
    expected_values = [entry.get("expected") for entry in parsed["thresholds"]]

    assert 0 in expected_values
    assert "missing" in expected_values
    assert "unavailable" in expected_values
    assert "not_collected" in expected_values


@pytest.mark.parametrize(
    ("field", "value", "message"),
    [
        ("schema_version", "9.9", "unsupported threshold config schema_version"),
        ("mode", "hard_gate", "unsupported threshold config mode"),
        ("mode", "fail_build", "unsupported threshold config mode"),
        ("mode", "production_ready", "unsupported threshold config mode"),
        ("report_type", "raw_artifact_report", "unsupported threshold config report_type"),
    ],
)
def test_threshold_config_parser_rejects_unsupported_top_level_values(field: str, value: str, message: str) -> None:
    config = _valid_threshold_config()
    config[field] = value

    with pytest.raises(ValueError, match=message):
        validate_threshold_config(config)


@pytest.mark.parametrize(
    "comparison_type",
    [
        "composite_score",
        "overall_score",
        "grade",
        "ranking",
        "pass_rate",
        "production_readiness",
        "broad_pass_fail",
        "severity",
    ],
)
def test_threshold_config_parser_rejects_forbidden_fields_at_any_level(comparison_type: str) -> None:
    config = _valid_threshold_config()
    config["thresholds"][0][comparison_type] = "forbidden"

    with pytest.raises(ValueError, match="forbidden threshold config field"):
        validate_threshold_config(config)


@pytest.mark.parametrize(
    ("location", "field"),
    [
        ("top_level", "default_thresholds"),
        ("entry", "hidden_threshold"),
    ],
)
def test_threshold_config_parser_rejects_unknown_or_hidden_default_fields(location: str, field: str) -> None:
    config = _valid_threshold_config()
    if location == "top_level":
        config[field] = []
    else:
        config["thresholds"][0][field] = True

    with pytest.raises(ValueError, match="unknown field"):
        validate_threshold_config(config)


def test_threshold_config_parser_rejects_malformed_json(tmp_path: Path) -> None:
    config_path = tmp_path / "threshold-config.json"
    config_path.write_text("{not-json")

    with pytest.raises(ValueError, match="threshold config is malformed JSON"):
        load_threshold_config(config_path)


@pytest.mark.parametrize(
    ("field", "message"),
    [
        ("thresholds", "missing required field"),
        ("report_type", "missing required field"),
    ],
)
def test_threshold_config_parser_rejects_missing_top_level_fields(field: str, message: str) -> None:
    config = _valid_threshold_config()
    config.pop(field)

    with pytest.raises(ValueError, match=message):
        validate_threshold_config(config)


def test_threshold_config_parser_rejects_malformed_threshold_entries() -> None:
    config = _valid_threshold_config()
    config["thresholds"][0].pop("rationale")

    with pytest.raises(ValueError, match="missing required field"):
        validate_threshold_config(config)


@pytest.mark.parametrize(
    ("comparison_type", "field", "message"),
    [
        ("max_absolute_delta", "delta_limit", "requires delta_limit"),
        ("max_relative_delta", "delta_limit", "requires delta_limit"),
        ("equals", "expected", "requires expected"),
        ("changed_or_unchanged", "expected", "requires expected 'changed' or 'unchanged'"),
    ],
)
def test_threshold_config_parser_rejects_missing_required_comparison_values(
    comparison_type: str, field: str, message: str
) -> None:
    config = _valid_threshold_config()
    entry = config["thresholds"][0]
    entry["comparison_type"] = comparison_type
    entry.pop(field, None)

    with pytest.raises(ValueError, match=message):
        validate_threshold_config(config)


def test_threshold_config_parser_requires_runtime_context_for_runtime_metrics() -> None:
    config = _valid_threshold_config()
    config["thresholds"][0] = {
        "target_type": "fixture",
        "target_name": "small",
        "metric": "wall_clock_runtime_ms",
        "comparison_type": "max_absolute_delta",
        "delta_limit": 10,
        "rationale": "Runtime changes should be visible.",
        "caveat": "Runtime changes are advisory only.",
    }

    with pytest.raises(ValueError, match="runtime metric requires machine/context caveat"):
        validate_threshold_config(config)

    config["thresholds"][0]["runtime_context_note"] = "Machine and CI context must be recorded."
    assert validate_threshold_config(config) == config


def test_threshold_config_parser_does_not_execute_thresholds_or_emit_pass_fail() -> None:
    parsed = validate_threshold_config(_valid_threshold_config())
    serialized = json.dumps(parsed, sort_keys=True)

    assert "pass_fail" not in serialized
    assert "pass_rate" not in serialized
    assert "thresholds_used" not in serialized
    assert not _contains_key(parsed, "composite_score")


def test_synthetic_threshold_evaluator_reports_non_gating_classifications(tmp_path: Path) -> None:
    _, _, comparison_path = _synthetic_comparison_fixture_files(tmp_path)
    config_path = tmp_path / "threshold-config.json"
    config_path.write_text(json.dumps(_threshold_evaluator_config()))

    evaluation = build_threshold_evaluation_from_paths(config_path, comparison_path)
    serialized = json.dumps(evaluation, sort_keys=True)
    by_metric_and_type = {(item["metric"], item["comparison_type"]): item for item in evaluation["threshold_results"]}

    assert evaluation["report_type"] == "synthetic_threshold_evaluation"
    assert evaluation["report_only"] is True
    assert evaluation["thresholds_used"] is True
    assert evaluation["evaluation_mode"] == "report_only"
    assert "composite_score" not in evaluation
    assert "overall_score" not in evaluation
    assert "pass_rate" not in evaluation
    assert "composite_score" not in serialized
    assert "overall_score" not in serialized
    assert "pass_rate" not in serialized
    assert not _contains_key(evaluation, "composite_score")
    assert not _contains_key(evaluation, "overall_score")
    assert not _contains_key(evaluation, "pass_rate")
    assert not _contains_key(evaluation, "severity")
    assert by_metric_and_type[("candidate_paths_considered", "max_absolute_delta")]["result_classification"] == (
        "satisfied"
    )
    assert by_metric_and_type[("candidate_paths_considered", "max_relative_delta")]["result_classification"] == (
        "breached"
    )
    assert by_metric_and_type[("paths_validated", "must_be_available")]["result_classification"] == "unavailable"
    assert by_metric_and_type[("constraint_evaluations", "max_absolute_delta")]["result_classification"] == (
        "not_applicable"
    )
    assert by_metric_and_type[("wall_clock_runtime_ms", "max_absolute_delta")]["runtime_caveat"] == (
        "Machine context must be reviewed before interpreting runtime deltas."
    )
    assert by_metric_and_type[("paths_validated", "must_be_available")]["current_value"] == "not_collected"
    assert by_metric_and_type[("paths_validated", "must_be_available")]["observed_value"] == "not_collected"
    assert by_metric_and_type[("failure_mode_classification", "equals")]["result_classification"] == "satisfied"
    assert by_metric_and_type[("paths_rejected", "may_be_unavailable")]["result_classification"] == "satisfied"


def test_synthetic_threshold_evaluator_command_writes_json_and_markdown(tmp_path: Path) -> None:
    _, _, comparison_path = _synthetic_comparison_fixture_files(tmp_path)
    config_path = tmp_path / "threshold-config.json"
    json_out = tmp_path / "threshold-evaluation.json"
    markdown_out = tmp_path / "threshold-evaluation.md"
    config_path.write_text(json.dumps(_threshold_evaluator_config()))

    completed = subprocess.run(
        [
            "bash",
            "scripts/evaluate_synthetic_thresholds.sh",
            "--threshold-config",
            str(config_path),
            "--comparison",
            str(comparison_path),
            "--json-out",
            str(json_out),
            "--markdown-out",
            str(markdown_out),
        ],
        check=True,
        text=True,
        capture_output=True,
    )

    payload = json.loads(json_out.read_text())
    markdown = markdown_out.read_text()
    assert "synthetic_threshold_evaluation_json=" in completed.stdout
    assert "synthetic_threshold_evaluation_markdown=" in completed.stdout
    assert payload["report_only"] is True
    assert payload["thresholds_used"] is True
    assert "composite_score" not in json.dumps(payload, sort_keys=True)
    assert "# IAMScope Synthetic Threshold Evaluation" in markdown
    assert "Report-only" in markdown
    assert "No CI gating" in markdown
    assert "No pass/fail" in markdown
    assert "No composite score" in markdown
    assert "Does not prove real-world scalability or correctness" in markdown
    assert "| fixture:medium | candidate_paths_considered | max_absolute_delta | satisfied |" in markdown
    assert "composite_score" not in markdown
    assert "pass_rate" not in markdown


def test_synthetic_threshold_evaluator_fails_closed_for_invalid_config(tmp_path: Path) -> None:
    _, _, comparison_path = _synthetic_comparison_fixture_files(tmp_path)
    config = _threshold_evaluator_config()
    config["thresholds"][0].pop("rationale")
    config_path = tmp_path / "threshold-config.json"
    config_path.write_text(json.dumps(config))

    completed = subprocess.run(
        [
            sys.executable,
            "-m",
            "benchmarks.scalability.threshold_evaluator",
            "--threshold-config",
            str(config_path),
            "--comparison",
            str(comparison_path),
        ],
        check=False,
        text=True,
        capture_output=True,
    )

    assert completed.returncode != 0
    assert "missing required field" in completed.stderr


def test_synthetic_threshold_evaluator_rejects_frozen_corpus_report_type(tmp_path: Path) -> None:
    _, _, comparison_path = _synthetic_comparison_fixture_files(tmp_path)
    config = _threshold_evaluator_config()
    config["report_type"] = "frozen_corpus_baseline_comparison"
    config["thresholds"] = [
        {
            "target_type": "batch",
            "target_name": "frozen_corpus",
            "metric": "case_count",
            "comparison_type": "must_be_available",
            "rationale": "Frozen-corpus threshold execution is out of scope for this slice.",
            "caveat": "No frozen-corpus threshold execution yet.",
        }
    ]
    config_path = tmp_path / "threshold-config.json"
    config_path.write_text(json.dumps(config))

    completed = subprocess.run(
        [
            sys.executable,
            "-m",
            "benchmarks.scalability.threshold_evaluator",
            "--threshold-config",
            str(config_path),
            "--comparison",
            str(comparison_path),
        ],
        check=False,
        text=True,
        capture_output=True,
    )

    assert completed.returncode != 0
    assert "threshold config report_type must be" in completed.stderr


def test_frozen_threshold_evaluator_reports_offline_non_gating_classifications(tmp_path: Path) -> None:
    _, _, comparison_path, matched_case_id, added_case_id, removed_case_id = _frozen_corpus_comparison_fixture_files(
        tmp_path
    )
    config_path = tmp_path / "frozen-threshold-config.json"
    config_path.write_text(
        json.dumps(_frozen_threshold_evaluator_config(matched_case_id, added_case_id, removed_case_id))
    )

    evaluation = build_frozen_threshold_evaluation_from_paths(config_path, comparison_path)
    serialized = json.dumps(evaluation, sort_keys=True)
    by_metric_and_type = {
        (item["target_name"], item["metric"], item["comparison_type"]): item for item in evaluation["threshold_results"]
    }

    assert evaluation["report_type"] == "frozen_corpus_threshold_evaluation"
    assert evaluation["offline_only"] is True
    assert evaluation["report_only"] is True
    assert evaluation["thresholds_used"] is True
    assert evaluation["live_aws_used"] is False
    assert evaluation["evaluation_mode"] == "report_only"
    assert "composite_score" not in evaluation
    assert "overall_score" not in evaluation
    assert "pass_rate" not in evaluation
    assert "composite_score" not in serialized
    assert "overall_score" not in serialized
    assert "pass_rate" not in serialized
    assert not _contains_key(evaluation, "composite_score")
    assert not _contains_key(evaluation, "overall_score")
    assert not _contains_key(evaluation, "pass_rate")
    assert not _contains_key(evaluation, "severity")
    assert by_metric_and_type[("frozen_corpus", "failures", "max_absolute_delta")]["result_classification"] == (
        "satisfied"
    )
    assert by_metric_and_type[("frozen_corpus", "cases", "max_relative_delta")]["result_classification"] == "breached"
    assert by_metric_and_type[("frozen_corpus", "live_aws_used", "equals")]["result_classification"] == "satisfied"
    assert (
        by_metric_and_type[("frozen_corpus", "candidate_paths_considered", "must_be_available")][
            "result_classification"
        ]
        == "unavailable"
    )
    assert (
        by_metric_and_type[(matched_case_id, "environment", "changed_or_unchanged")]["result_classification"]
        == "satisfied"
    )
    assert by_metric_and_type[(added_case_id, "presence", "equals")]["observed_value"] == "added"
    assert by_metric_and_type[(added_case_id, "presence", "equals")]["result_classification"] == "satisfied"
    assert by_metric_and_type[(removed_case_id, "presence", "equals")]["observed_value"] == "removed"
    assert by_metric_and_type[(removed_case_id, "presence", "equals")]["result_classification"] == "satisfied"
    assert (
        by_metric_and_type[("missing_case_for_threshold_evaluation", "presence", "equals")]["result_classification"]
        == "not_applicable"
    )
    assert (
        by_metric_and_type[(matched_case_id, "score_passed", "may_be_unavailable")]["result_classification"]
        == "satisfied"
    )
    unavailable_item = by_metric_and_type[("frozen_corpus", "candidate_paths_considered", "must_be_available")]
    assert isinstance(unavailable_item["current_value"], str)
    assert unavailable_item["current_value"].startswith("not_collected")
    assert unavailable_item["observed_value"].startswith("not_collected")


def test_frozen_threshold_evaluator_command_writes_json_and_markdown(tmp_path: Path) -> None:
    _, _, comparison_path, matched_case_id, added_case_id, removed_case_id = _frozen_corpus_comparison_fixture_files(
        tmp_path
    )
    config_path = tmp_path / "frozen-threshold-config.json"
    json_out = tmp_path / "frozen-threshold-evaluation.json"
    markdown_out = tmp_path / "frozen-threshold-evaluation.md"
    config_path.write_text(
        json.dumps(_frozen_threshold_evaluator_config(matched_case_id, added_case_id, removed_case_id))
    )

    completed = subprocess.run(
        [
            "bash",
            "scripts/evaluate_frozen_corpus_thresholds.sh",
            "--threshold-config",
            str(config_path),
            "--comparison",
            str(comparison_path),
            "--json-out",
            str(json_out),
            "--markdown-out",
            str(markdown_out),
        ],
        check=True,
        text=True,
        capture_output=True,
    )

    payload = json.loads(json_out.read_text())
    markdown = markdown_out.read_text()
    assert "frozen_corpus_threshold_evaluation_json=" in completed.stdout
    assert "frozen_corpus_threshold_evaluation_markdown=" in completed.stdout
    assert payload["offline_only"] is True
    assert payload["report_only"] is True
    assert payload["thresholds_used"] is True
    assert payload["live_aws_used"] is False
    assert "composite_score" not in json.dumps(payload, sort_keys=True)
    assert "# IAMScope Frozen-Corpus Threshold Evaluation" in markdown
    assert "Offline-only" in markdown
    assert "Report-only" in markdown
    assert "No CI gating" in markdown
    assert "No pass/fail" in markdown
    assert "No composite score" in markdown
    assert "No new live AWS evidence" in markdown
    assert "Does not prove real-world scalability or correctness" in markdown
    assert "| batch:frozen_corpus | failures | max_absolute_delta | satisfied |" in markdown
    assert "composite_score" not in markdown
    assert "pass_rate" not in markdown


def test_frozen_threshold_evaluator_fails_closed_for_invalid_config(tmp_path: Path) -> None:
    _, _, comparison_path, matched_case_id, added_case_id, removed_case_id = _frozen_corpus_comparison_fixture_files(
        tmp_path
    )
    config = _frozen_threshold_evaluator_config(matched_case_id, added_case_id, removed_case_id)
    config["thresholds"][0].pop("rationale")
    config_path = tmp_path / "frozen-threshold-config.json"
    config_path.write_text(json.dumps(config))

    completed = subprocess.run(
        [
            sys.executable,
            "-m",
            "benchmarks.scalability.frozen_threshold_evaluator",
            "--threshold-config",
            str(config_path),
            "--comparison",
            str(comparison_path),
        ],
        check=False,
        text=True,
        capture_output=True,
    )

    assert completed.returncode != 0
    assert "missing required field" in completed.stderr


def test_frozen_threshold_evaluator_rejects_synthetic_report_type(tmp_path: Path) -> None:
    _, _, comparison_path, matched_case_id, added_case_id, removed_case_id = _frozen_corpus_comparison_fixture_files(
        tmp_path
    )
    config = _frozen_threshold_evaluator_config(matched_case_id, added_case_id, removed_case_id)
    config["report_type"] = "synthetic_scalability_baseline_comparison"
    config["thresholds"] = [
        {
            "target_type": "fixture",
            "target_name": "medium",
            "metric": "candidate_paths_considered",
            "comparison_type": "must_be_available",
            "rationale": "Synthetic threshold execution is out of scope for this evaluator.",
            "caveat": "Frozen-corpus evaluator accepts frozen-corpus comparison JSON only.",
        }
    ]
    config_path = tmp_path / "frozen-threshold-config.json"
    config_path.write_text(json.dumps(config))

    completed = subprocess.run(
        [
            sys.executable,
            "-m",
            "benchmarks.scalability.frozen_threshold_evaluator",
            "--threshold-config",
            str(config_path),
            "--comparison",
            str(comparison_path),
        ],
        check=False,
        text=True,
        capture_output=True,
    )

    assert completed.returncode != 0
    assert "threshold config report_type must be" in completed.stderr


def test_sts_probe_plan_validator_accepts_valid_dry_run_plan_without_credentials(tmp_path: Path) -> None:
    plan_path = tmp_path / "sts-probe-plan.json"
    plan_path.write_text(json.dumps(_valid_sts_probe_plan()))

    report = build_validation_from_paths(plan_path)
    serialized = json.dumps(report, sort_keys=True)

    assert report["report_type"] == "sts_probe_plan_validation"
    assert report["dry_run_only"] is True
    assert report["live_aws_used"] is False
    assert report["aws_calls_made"] is False
    assert report["plan_path"] == str(plan_path)
    assert report["validation_results"][0]["result_classification"] == "valid"
    assert "composite_score" not in serialized
    assert "benchmark_passed" not in serialized
    assert "exploited" not in serialized
    assert "vulnerable" not in serialized


def test_sts_probe_plan_validator_rejects_invalid_top_level_mode(tmp_path: Path) -> None:
    plan = _valid_sts_probe_plan()
    plan["mode"] = "live"
    plan_path = tmp_path / "sts-probe-plan.json"
    plan_path.write_text(json.dumps(plan))

    completed = subprocess.run(
        [
            sys.executable,
            "-m",
            "benchmarks.runtime.sts_probe_plan",
            "--plan",
            str(plan_path),
        ],
        check=False,
        text=True,
        capture_output=True,
    )

    assert completed.returncode != 0
    assert "unsupported STS probe plan mode" in completed.stderr


def test_sts_probe_plan_validator_reports_safety_and_malformed_probe_issues(tmp_path: Path) -> None:
    plan = _valid_sts_probe_plan()
    valid_probe = plan["probes"][0]
    missing_profile = dict(valid_probe)
    missing_profile["probe_id"] = "missing-profile"
    missing_profile.pop("aws_profile")
    mismatched_account = dict(valid_probe)
    mismatched_account["probe_id"] = "mismatched-account"
    mismatched_account["target_role_arn"] = "arn:aws:iam::210987654321:role/iamscope-test-target"
    wildcard_role = dict(valid_probe)
    wildcard_role["probe_id"] = "wildcard-role"
    wildcard_role["target_role_arn"] = "arn:aws:iam::123456789012:role/*"
    excessive_duration = dict(valid_probe)
    excessive_duration["probe_id"] = "excessive-duration"
    excessive_duration["duration_seconds"] = 3600
    missing_boundaries = dict(valid_probe)
    missing_boundaries["probe_id"] = "missing-boundaries"
    missing_boundaries["evidence_boundary"] = ""
    missing_boundaries["safety_notes"] = ""
    duplicate_probe = dict(valid_probe)
    duplicate_probe["target_role_arn"] = "arn:aws:iam::123456789012:role/iamscope-test-target-2"
    plan["probes"] = [
        valid_probe,
        missing_profile,
        mismatched_account,
        wildcard_role,
        excessive_duration,
        missing_boundaries,
        duplicate_probe,
    ]
    plan_path = tmp_path / "sts-probe-plan.json"
    plan_path.write_text(json.dumps(plan))

    report = build_validation_from_paths(plan_path)
    by_id = {item["probe_id"]: item for item in report["validation_results"]}
    first_result = report["validation_results"][0]

    assert first_result["probe_id"] == "sts-assume-role-test-admin"
    assert first_result["result_classification"] == "valid"
    assert by_id["missing-profile"]["result_classification"] == "invalid"
    assert any("aws_profile" in reason for reason in by_id["missing-profile"]["reasons"])
    assert by_id["mismatched-account"]["result_classification"] == "skipped_safety_guard"
    assert "target role account does not match expected_account_id" in by_id["mismatched-account"]["reasons"]
    assert by_id["wildcard-role"]["result_classification"] == "malformed_probe"
    assert "target_role_arn must not contain wildcards" in by_id["wildcard-role"]["reasons"]
    assert by_id["excessive-duration"]["result_classification"] == "invalid"
    assert any("duration_seconds" in reason for reason in by_id["excessive-duration"]["reasons"])
    assert by_id["missing-boundaries"]["result_classification"] == "invalid"
    assert "evidence_boundary must be non-empty" in by_id["missing-boundaries"]["reasons"]
    assert "safety_notes must be non-empty" in by_id["missing-boundaries"]["reasons"]
    duplicate_results = [item for item in report["validation_results"] if "duplicate probe_id" in item["reasons"]]
    assert len(duplicate_results) == 1
    assert duplicate_results[0]["result_classification"] == "invalid"


def test_sts_probe_plan_validator_command_writes_json_and_markdown_without_repo_artifacts(tmp_path: Path) -> None:
    plan_path = tmp_path / "sts-probe-plan.json"
    json_out = tmp_path / "sts-probe-validation.json"
    markdown_out = tmp_path / "sts-probe-validation.md"
    plan_path.write_text(json.dumps(_valid_sts_probe_plan()))
    before = _repo_artifact_policy_snapshot()

    completed = subprocess.run(
        [
            "bash",
            "scripts/validate_sts_probe_plan.sh",
            "--plan",
            str(plan_path),
            "--json-out",
            str(json_out),
            "--markdown-out",
            str(markdown_out),
        ],
        check=True,
        text=True,
        capture_output=True,
        env=_subprocess_env_without_bytecode(),
    )

    payload = json.loads(json_out.read_text())
    markdown = markdown_out.read_text()
    serialized = json.dumps(payload, sort_keys=True)
    assert "sts_probe_plan_validation_json=" in completed.stdout
    assert "sts_probe_plan_validation_markdown=" in completed.stdout
    assert payload["dry_run_only"] is True
    assert payload["live_aws_used"] is False
    assert payload["aws_calls_made"] is False
    assert "composite_score" not in serialized
    assert "benchmark_passed" not in serialized
    assert "exploited" not in serialized
    assert "vulnerable" not in serialized
    assert "# IAMScope STS Probe Plan Validation" in markdown
    assert "Dry-run only" in markdown
    assert "No AWS calls" in markdown
    assert "No runtime proof" in markdown
    assert "No production-readiness" in markdown
    assert "No composite score" in markdown
    assert "composite_score" not in markdown
    _assert_repo_artifact_policy_snapshot_unchanged(before)


def test_sts_probe_plan_validator_stdout_does_not_create_repo_outputs(tmp_path: Path) -> None:
    plan_path = tmp_path / "sts-probe-plan.json"
    plan_path.write_text(json.dumps(_valid_sts_probe_plan()))
    before = _repo_artifact_policy_snapshot()

    completed = subprocess.run(
        [
            "bash",
            "scripts/validate_sts_probe_plan.sh",
            "--plan",
            str(plan_path),
        ],
        check=True,
        text=True,
        capture_output=True,
        env=_subprocess_env_without_bytecode(),
    )

    payload = json.loads(completed.stdout)
    assert payload["report_type"] == "sts_probe_plan_validation"
    assert payload["dry_run_only"] is True
    assert payload["live_aws_used"] is False
    assert payload["aws_calls_made"] is False
    _assert_repo_artifact_policy_snapshot_unchanged(before)


def test_sts_probe_executor_simulate_mode_writes_outputs_without_credentials(tmp_path: Path) -> None:
    plan_path = tmp_path / "sts-probe-plan.json"
    json_out = tmp_path / "sts-probe-execution.json"
    markdown_out = tmp_path / "sts-probe-execution.md"
    plan_path.write_text(json.dumps(_valid_sts_probe_plan()))
    before = _repo_artifact_policy_snapshot()

    completed = subprocess.run(
        [
            "bash",
            "scripts/run_sts_probe_executor.sh",
            "--plan",
            str(plan_path),
            "--json-out",
            str(json_out),
            "--markdown-out",
            str(markdown_out),
            "--mode",
            "simulate",
        ],
        check=True,
        text=True,
        capture_output=True,
        env=_subprocess_env_without_aws_credentials(),
    )

    payload = json.loads(json_out.read_text())
    markdown = markdown_out.read_text()
    serialized = json.dumps(payload, sort_keys=True)
    assert "sts_probe_executor_simulation_json=" in completed.stdout
    assert "sts_probe_executor_simulation_markdown=" in completed.stdout
    assert payload["report_type"] == "sts_probe_executor_simulation"
    assert payload["mode"] == "simulate"
    assert payload["live_aws_used"] is False
    assert payload["aws_calls_made"] is False
    assert payload["sts_assume_role_called"] is False
    assert payload["credentials_obtained"] is False
    assert payload["execution_results"][0]["result_classification"] == "simulated_not_executed"
    assert "composite_score" not in serialized
    assert "benchmark_passed" not in serialized
    assert "exploited" not in serialized
    assert "vulnerable" not in serialized
    assert "pwned" not in serialized
    assert "production_ready" not in serialized
    assert "# IAMScope STS Probe Executor" in markdown
    assert "No AWS calls" in markdown
    assert "STS AssumeRole called: `false`" in markdown
    assert "No downstream AWS actions" in markdown
    assert "No production-readiness" in markdown
    assert "No broad exploitability" in markdown
    assert "No composite score" in markdown
    assert "composite_score" not in markdown
    _assert_repo_artifact_policy_snapshot_unchanged(before)


@pytest.mark.parametrize("mode", ["live", "execute", "assume_role", "unknown"])
def test_sts_probe_executor_rejects_live_and_unknown_modes(tmp_path: Path, mode: str) -> None:
    plan_path = tmp_path / "sts-probe-plan.json"
    plan_path.write_text(json.dumps(_valid_sts_probe_plan()))

    completed = subprocess.run(
        [
            sys.executable,
            "-m",
            "benchmarks.runtime.sts_probe_executor",
            "--plan",
            str(plan_path),
            "--mode",
            mode,
        ],
        check=False,
        text=True,
        capture_output=True,
        env=_subprocess_env_without_aws_credentials(),
    )

    assert completed.returncode != 0
    assert "unsupported STS executor mode" in completed.stderr


def test_sts_probe_executor_live_probe_requires_allow_live_mode_before_sts_call(tmp_path: Path) -> None:
    plan_path = tmp_path / "sts-probe-plan.json"
    plan_path.write_text(json.dumps(_valid_sts_probe_plan()))
    fake_sts = _FakeStsClient()

    report = build_executor_report_from_paths(
        plan_path,
        mode="live_probe",
        operator_confirmation=REQUIRED_OPERATOR_CONFIRMATION,
        output_paths_supplied=True,
        sts_client=fake_sts,
    )

    assert fake_sts.calls == []
    assert report["live_aws_used"] is False
    assert report["aws_calls_made"] is False
    assert report["execution_results"][0]["result_classification"] == "configuration_error"
    assert "allow_live_mode must be explicitly enabled" in report["execution_results"][0]["reasons"]


def test_sts_probe_executor_live_probe_requires_operator_confirmation_before_sts_call(tmp_path: Path) -> None:
    plan_path = tmp_path / "sts-probe-plan.json"
    plan_path.write_text(json.dumps(_valid_sts_probe_plan()))
    fake_sts = _FakeStsClient()

    report = build_executor_report_from_paths(
        plan_path,
        mode="live_probe",
        allow_live_mode=True,
        output_paths_supplied=True,
        sts_client=fake_sts,
    )

    assert fake_sts.calls == []
    assert report["execution_results"][0]["result_classification"] == "configuration_error"
    assert any("operator confirmation" in reason for reason in report["execution_results"][0]["reasons"])


def test_sts_probe_executor_live_probe_rejects_old_operator_confirmation_before_sts_call(tmp_path: Path) -> None:
    plan_path = tmp_path / "sts-probe-plan.json"
    plan_path.write_text(json.dumps(_valid_sts_probe_plan()))
    fake_sts = _FakeStsClient()

    report = build_executor_report_from_paths(
        plan_path,
        mode="live_probe",
        allow_live_mode=True,
        operator_confirmation=OLD_OPERATOR_CONFIRMATION,
        output_paths_supplied=True,
        sts_client=fake_sts,
    )

    assert fake_sts.calls == []
    assert report["live_aws_used"] is False
    assert report["aws_calls_made"] is False
    assert report["sts_assume_role_called"] is False
    assert report["execution_results"][0]["result_classification"] == "configuration_error"
    assert any("operator confirmation" in reason for reason in report["execution_results"][0]["reasons"])


def test_sts_probe_executor_live_probe_requires_output_paths_before_sts_call(tmp_path: Path) -> None:
    plan_path = tmp_path / "sts-probe-plan.json"
    plan_path.write_text(json.dumps(_valid_sts_probe_plan()))
    fake_sts = _FakeStsClient()

    report = build_executor_report_from_paths(
        plan_path,
        mode="live_probe",
        allow_live_mode=True,
        operator_confirmation=REQUIRED_OPERATOR_CONFIRMATION,
        sts_client=fake_sts,
    )

    assert fake_sts.calls == []
    assert report["execution_results"][0]["result_classification"] == "configuration_error"
    assert (
        "json_out and markdown_out must both be supplied for live_probe mode"
        in report["execution_results"][0]["reasons"]
    )


def test_sts_probe_executor_live_probe_refuses_failed_validator_before_sts_call(tmp_path: Path) -> None:
    plan = _valid_sts_probe_plan()
    plan["probes"][0].pop("aws_profile")
    plan_path = tmp_path / "sts-probe-plan.json"
    plan_path.write_text(json.dumps(plan))
    fake_sts = _FakeStsClient()

    report = build_executor_report_from_paths(
        plan_path,
        mode="live_probe",
        allow_live_mode=True,
        operator_confirmation=REQUIRED_OPERATOR_CONFIRMATION,
        output_paths_supplied=True,
        sts_client=fake_sts,
    )

    assert fake_sts.calls == []
    assert report["execution_results"][0]["result_classification"] == "configuration_error"
    assert any("aws_profile" in reason for reason in report["execution_results"][0]["reasons"])
    assert (
        "dry-run validation must be valid for every probe before live_probe mode"
        in report["execution_results"][0]["reasons"]
    )


def test_sts_probe_executor_live_probe_refuses_mismatched_account_before_sts_call(tmp_path: Path) -> None:
    plan = _valid_sts_probe_plan()
    plan["probes"][0]["target_role_arn"] = "arn:aws:iam::210987654321:role/iamscope-test-target"
    plan_path = tmp_path / "sts-probe-plan.json"
    plan_path.write_text(json.dumps(plan))
    fake_sts = _FakeStsClient()

    report = build_executor_report_from_paths(
        plan_path,
        mode="live_probe",
        allow_live_mode=True,
        operator_confirmation=REQUIRED_OPERATOR_CONFIRMATION,
        output_paths_supplied=True,
        sts_client=fake_sts,
    )

    assert fake_sts.calls == []
    assert report["execution_results"][0]["result_classification"] in {
        "configuration_error",
        "skipped_safety_guard",
    }
    assert "target role account does not match expected_account_id" in report["execution_results"][0]["reasons"]


def test_sts_probe_executor_live_probe_refuses_downstream_actions_and_debug_before_sts_call(tmp_path: Path) -> None:
    plan = _valid_sts_probe_plan()
    plan["downstream_actions"] = ["s3:ListBucket"]
    plan["raw_debug_logging"] = True
    plan_path = tmp_path / "sts-probe-plan.json"
    plan_path.write_text(json.dumps(plan))
    fake_sts = _FakeStsClient()

    report = build_executor_report_from_paths(
        plan_path,
        mode="live_probe",
        allow_live_mode=True,
        operator_confirmation=REQUIRED_OPERATOR_CONFIRMATION,
        output_paths_supplied=True,
        sts_client=fake_sts,
    )

    assert fake_sts.calls == []
    assert report["execution_results"][0]["result_classification"] == "configuration_error"
    assert any("unknown field" in reason for reason in report["execution_results"][0]["reasons"])


def test_sts_probe_executor_live_probe_refuses_production_marker_before_sts_call(tmp_path: Path) -> None:
    plan = _valid_sts_probe_plan()
    plan["probes"][0]["target_role_arn"] = "arn:aws:iam::123456789012:role/prod-admin"
    plan_path = tmp_path / "sts-probe-plan.json"
    plan_path.write_text(json.dumps(plan))
    fake_sts = _FakeStsClient()

    report = build_executor_report_from_paths(
        plan_path,
        mode="live_probe",
        allow_live_mode=True,
        operator_confirmation=REQUIRED_OPERATOR_CONFIRMATION,
        output_paths_supplied=True,
        sts_client=fake_sts,
    )

    assert fake_sts.calls == []
    assert report["execution_results"][0]["result_classification"] in {
        "configuration_error",
        "skipped_safety_guard",
    }
    assert (
        "target_role_arn contains production-like markers without a test marker"
        in report["execution_results"][0]["reasons"]
    )


def test_sts_probe_executor_live_probe_refuses_multiple_probes_before_sts_call(tmp_path: Path) -> None:
    plan = _valid_sts_probe_plan()
    second_probe = dict(plan["probes"][0])
    second_probe["probe_id"] = "second-test-probe"
    second_probe["target_role_arn"] = "arn:aws:iam::123456789012:role/iamscope-test-target-2"
    plan["probes"].append(second_probe)
    plan_path = tmp_path / "sts-probe-plan.json"
    plan_path.write_text(json.dumps(plan))
    fake_sts = _FakeStsClient()

    report = build_executor_report_from_paths(
        plan_path,
        mode="live_probe",
        allow_live_mode=True,
        operator_confirmation=REQUIRED_OPERATOR_CONFIRMATION,
        output_paths_supplied=True,
        sts_client=fake_sts,
    )

    assert fake_sts.calls == []
    assert all(result["result_classification"] == "configuration_error" for result in report["execution_results"])
    assert all(
        "live_probe mode supports exactly 1 probe per invocation" in result["reasons"]
        for result in report["execution_results"]
    )


def test_sts_probe_executor_invalid_plan_emits_safe_refusal_result(tmp_path: Path) -> None:
    plan = _valid_sts_probe_plan()
    plan["probes"][0].pop("aws_profile")
    plan_path = tmp_path / "sts-probe-plan.json"
    plan_path.write_text(json.dumps(plan))

    report = build_executor_report_from_paths(plan_path, mode="simulate")
    serialized = json.dumps(report, sort_keys=True)

    assert report["live_aws_used"] is False
    assert report["aws_calls_made"] is False
    assert report["sts_assume_role_called"] is False
    assert report["credentials_obtained"] is False
    assert report["execution_results"][0]["result_classification"] == "configuration_error"
    assert any("aws_profile" in reason for reason in report["execution_results"][0]["reasons"])
    assert "composite_score" not in serialized
    assert "benchmark_passed" not in serialized
    assert "exploited" not in serialized
    assert "vulnerable" not in serialized


def test_sts_probe_executor_validate_only_mode_does_not_execute(tmp_path: Path) -> None:
    plan_path = tmp_path / "sts-probe-plan.json"
    plan_path.write_text(json.dumps(_valid_sts_probe_plan()))

    report = build_executor_report_from_paths(plan_path, mode="validate_only")

    assert report["mode"] == "validate_only"
    assert report["live_aws_used"] is False
    assert report["aws_calls_made"] is False
    assert report["sts_assume_role_called"] is False
    assert report["credentials_obtained"] is False
    assert report["execution_results"][0]["result_classification"] == "skipped_safety_guard"


def test_sts_probe_executor_module_has_no_static_boto3_import() -> None:
    source = Path("benchmarks/runtime/sts_probe_executor.py").read_text()

    assert "import boto3" not in source
    assert "import botocore" not in source


def test_sts_probe_executor_mocked_live_success_classifies_assumed_without_credentials(tmp_path: Path) -> None:
    plan_path = tmp_path / "sts-probe-plan.json"
    plan_path.write_text(json.dumps(_valid_sts_probe_plan()))
    fake_sts = _FakeStsClient(
        response={
            "Credentials": {
                "AccessKeyId": "ASIAEXAMPLE",
                "SecretAccessKey": "secret",
                "SessionToken": "token",
            },
            "AssumedRoleUser": {"Arn": "arn:aws:sts::123456789012:assumed-role/iamscope-test-target/iamscope-test"},
        }
    )

    report = build_executor_report_from_paths(
        plan_path,
        mode="live_probe",
        allow_live_mode=True,
        operator_confirmation=REQUIRED_OPERATOR_CONFIRMATION,
        output_paths_supplied=True,
        sts_client=fake_sts,
    )
    serialized = json.dumps(report, sort_keys=True)

    assert len(fake_sts.calls) == 1
    assert fake_sts.calls[0]["RoleArn"] == "arn:aws:iam::123456789012:role/iamscope-test-target"
    assert report["live_aws_used"] is True
    assert report["aws_calls_made"] is True
    assert report["sts_assume_role_called"] is True
    assert report["credentials_obtained"] is True
    assert report["execution_results"][0]["result_classification"] == "assumed"
    assert report["execution_results"][0]["credentials_obtained"] is True
    assert "AccessKeyId" not in serialized
    assert "SecretAccessKey" not in serialized
    assert "SessionToken" not in serialized
    assert "ASIAEXAMPLE" not in serialized
    assert "composite_score" not in serialized
    assert "benchmark_passed" not in serialized


def test_sts_probe_executor_mocked_access_denied_classifies_denied(tmp_path: Path) -> None:
    plan_path = tmp_path / "sts-probe-plan.json"
    plan_path.write_text(json.dumps(_valid_sts_probe_plan()))
    fake_sts = _FakeStsClient(error=_FakeAwsError("AccessDenied"))

    report = build_executor_report_from_paths(
        plan_path,
        mode="live_probe",
        allow_live_mode=True,
        operator_confirmation=REQUIRED_OPERATOR_CONFIRMATION,
        output_paths_supplied=True,
        sts_client=fake_sts,
    )

    assert len(fake_sts.calls) == 1
    assert report["live_aws_used"] is True
    assert report["aws_calls_made"] is True
    assert report["sts_assume_role_called"] is True
    assert report["credentials_obtained"] is False
    assert report["execution_results"][0]["result_classification"] == "denied"
    assert report["execution_results"][0]["safe_error_category"] == "access_denied"


def test_sts_probe_executor_mocked_unexpected_response_classifies_inconclusive(tmp_path: Path) -> None:
    plan_path = tmp_path / "sts-probe-plan.json"
    plan_path.write_text(json.dumps(_valid_sts_probe_plan()))
    fake_sts = _FakeStsClient(response={"ResponseMetadata": {"RequestId": "safe-request-id"}})

    report = build_executor_report_from_paths(
        plan_path,
        mode="live_probe",
        allow_live_mode=True,
        operator_confirmation=REQUIRED_OPERATOR_CONFIRMATION,
        output_paths_supplied=True,
        sts_client=fake_sts,
    )

    assert len(fake_sts.calls) == 1
    assert report["execution_results"][0]["result_classification"] == "inconclusive"
    assert report["credentials_obtained"] is False


def test_sts_probe_executor_mocked_unexpected_account_classifies_unexpected_account(tmp_path: Path) -> None:
    plan_path = tmp_path / "sts-probe-plan.json"
    plan_path.write_text(json.dumps(_valid_sts_probe_plan()))
    fake_sts = _FakeStsClient(
        response={
            "Credentials": {
                "AccessKeyId": "ASIAEXAMPLE",
                "SecretAccessKey": "secret",
                "SessionToken": "token",
            },
            "AssumedRoleUser": {"Arn": "arn:aws:sts::210987654321:assumed-role/iamscope-test-target/iamscope-test"},
        }
    )

    report = build_executor_report_from_paths(
        plan_path,
        mode="live_probe",
        allow_live_mode=True,
        operator_confirmation=REQUIRED_OPERATOR_CONFIRMATION,
        output_paths_supplied=True,
        sts_client=fake_sts,
    )

    assert len(fake_sts.calls) == 1
    assert report["execution_results"][0]["result_classification"] == "unexpected_account"
    assert report["credentials_obtained"] is True


def test_sts_probe_executor_markdown_omits_credentials_for_mocked_live_success(tmp_path: Path) -> None:
    plan_path = tmp_path / "sts-probe-plan.json"
    plan_path.write_text(json.dumps(_valid_sts_probe_plan()))
    fake_sts = _FakeStsClient(
        response={
            "Credentials": {
                "AccessKeyId": "ASIAEXAMPLE",
                "SecretAccessKey": "secret",
                "SessionToken": "token",
            },
            "AssumedRoleUser": {"Arn": "arn:aws:sts::123456789012:assumed-role/iamscope-test-target/iamscope-test"},
        }
    )

    report = build_executor_report_from_paths(
        plan_path,
        mode="live_probe",
        allow_live_mode=True,
        operator_confirmation=REQUIRED_OPERATOR_CONFIRMATION,
        output_paths_supplied=True,
        sts_client=fake_sts,
    )
    markdown = render_sts_executor_markdown_report(report)

    assert "No downstream AWS actions" in markdown
    assert "No production-readiness" in markdown
    assert "No broad exploitability" in markdown
    assert "AccessKeyId" not in markdown
    assert "SecretAccessKey" not in markdown
    assert "SessionToken" not in markdown
    assert "ASIAEXAMPLE" not in markdown


def test_sts_probe_executor_stdout_does_not_create_repo_outputs(tmp_path: Path) -> None:
    plan_path = tmp_path / "sts-probe-plan.json"
    plan_path.write_text(json.dumps(_valid_sts_probe_plan()))
    before = _repo_artifact_policy_snapshot()

    completed = subprocess.run(
        [
            "bash",
            "scripts/run_sts_probe_executor.sh",
            "--plan",
            str(plan_path),
            "--mode",
            "simulate",
        ],
        check=True,
        text=True,
        capture_output=True,
        env=_subprocess_env_without_aws_credentials(),
    )

    payload = json.loads(completed.stdout)
    assert payload["report_type"] == "sts_probe_executor_simulation"
    assert payload["live_aws_used"] is False
    assert payload["aws_calls_made"] is False
    assert payload["sts_assume_role_called"] is False
    assert payload["credentials_obtained"] is False
    _assert_repo_artifact_policy_snapshot_unchanged(before)
