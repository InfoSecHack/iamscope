from __future__ import annotations

import json
import re
from collections import Counter
from pathlib import Path
from typing import Any

FIXTURE_DIR = Path("tests/fixtures/demo/path_overcounting_shared_uncertainty")
REQUIRED_FILES = {
    "scenario.json",
    "binding_metadata.json",
    "findings.json",
    "naive_candidates.json",
    "expected_uncertainty_groups.json",
}
EXPECTED_VERDICTS = {
    "validated": 3,
    "blocked": 5,
    "precondition_only": 4,
    "inconclusive": 11,
}
EXPECTED_UNCERTAINTY_GROUPS = {
    "shared_passrole_target_resource_scope_unknown": 8,
    "shared_boundary_context_unresolved": 2,
    "session_policy_context_missing": 1,
}
GENERATED_OUTPUT_NAMES = {
    "report.md",
    "verdict-summary.json",
    "uncertainty-groups.json",
    "uncertainty-groups.md",
    "why-inconclusive.txt",
}
FORBIDDEN_MARKERS = [
    "AccessKeyId",
    "SecretAccessKey",
    "SessionToken",
    "raw_aws_log",
    "raw_error",
    "/home/ericc",
    "/mnt/c/Users/ericc",
    "Claude",
    "ChatGPT",
    "Anthropic",
    "OpenAI",
    "Toyota Financial",
    "Red Team Lead",
    "personal AWS Free Tier",
    "gmail.com",
    "aol.com",
]


def _load(name: str) -> dict[str, Any]:
    return json.loads((FIXTURE_DIR / name).read_text())


def test_fixture_files_exist() -> None:
    assert FIXTURE_DIR.is_dir()
    assert {path.name for path in FIXTURE_DIR.iterdir() if path.is_file()} == REQUIRED_FILES


def test_naive_candidate_count_is_exact() -> None:
    naive = _load("naive_candidates.json")
    assert len(naive["candidate_paths"]) == 23
    assert naive["is_iamscope_output"] is False
    assert naive["reachability_evidence"] is False


def test_verdict_counts_are_exact() -> None:
    findings = _load("findings.json")["findings"]
    assert Counter(finding["verdict"] for finding in findings) == EXPECTED_VERDICTS
    assert _load("findings.json")["metadata"]["verdict_breakdown"] == EXPECTED_VERDICTS


def test_uncertainty_group_counts_are_exact() -> None:
    groups = _load("expected_uncertainty_groups.json")["groups"]
    assert {group["uncertainty_class"]: group["count"] for group in groups} == EXPECTED_UNCERTAINTY_GROUPS
    assert {group["uncertainty_class"]: len(group["finding_ids"]) for group in groups} == EXPECTED_UNCERTAINTY_GROUPS


def test_uncertainty_groups_reference_inconclusive_findings() -> None:
    findings = _load("findings.json")["findings"]
    inconclusive_ids = {finding["finding_id"] for finding in findings if finding["verdict"] == "inconclusive"}
    referenced_ids = {
        finding_id
        for group in _load("expected_uncertainty_groups.json")["groups"]
        for finding_id in group["finding_ids"]
    }
    assert referenced_ids == inconclusive_ids


def test_primary_uncertainty_class_is_passrole_like() -> None:
    findings = _load("findings.json")["findings"]
    naive_by_id = {
        candidate["candidate_id"]: candidate for candidate in _load("naive_candidates.json")["candidate_paths"]
    }
    primary_findings = [
        finding
        for finding in findings
        if finding.get("uncertainty_class") == "shared_passrole_target_resource_scope_unknown"
    ]
    assert len(primary_findings) == 8

    for finding in primary_findings:
        candidate = naive_by_id[finding["naive_candidate_id"]]
        assert "passrole" in finding["pattern_id"].lower() or "iam:PassRole" in candidate["action_or_precondition"]


def test_each_naive_candidate_maps_once() -> None:
    finding_ids = {finding["finding_id"] for finding in _load("findings.json")["findings"]}
    for candidate in _load("naive_candidates.json")["candidate_paths"]:
        mapping = candidate["maps_to"]
        has_finding = bool(mapping.get("finding_id"))
        has_non_finding_reason = bool(mapping.get("non_finding_reason"))
        assert has_finding != has_non_finding_reason
        if has_finding:
            assert mapping["finding_id"] in finding_ids


def test_findings_are_labeled_as_frozen_expected_output() -> None:
    findings = _load("findings.json")
    metadata = _load("binding_metadata.json")["findings_generation"]
    assert findings["generation_mode"] == "frozen_expected_output"
    assert findings["source_tool"] == "static_fixture_authoring"
    assert findings["source_tool"] != "iamscope"
    assert findings["replay_equivalence_follow_up_required"] is True
    assert findings["metadata"]["reasoners_run"] == []
    assert findings["metadata"]["generated_or_replayed_by_iamscope"] is False
    assert metadata["mode"] == "frozen_expected_output"
    assert metadata["replay_equivalence_follow_up_required"] is True
    assert metadata["live_aws_used"] is False
    assert metadata["aws_calls_made"] is False


def test_replay_equivalence_gap_is_documented() -> None:
    findings = _load("findings.json")
    metadata = _load("binding_metadata.json")["findings_generation"]
    assert findings["replay_equivalence_status"] == "not_proven"
    assert findings["metadata"]["replay_equivalence_status"] == "not_proven"
    assert findings["metadata"]["stronger_demo_claims_allowed"] is False
    assert metadata["replay_equivalence_status"] == "not_proven"
    assert metadata["existing_replay_failure_category"] == "fixture_shape_not_replay_compatible"
    assert metadata["stronger_demo_claims_allowed"] is False
    assert "run_reasoners_on_frozen_artifacts" in metadata["replay_equivalence_gap"]
    assert "edge-constraint binding list" in metadata["replay_equivalence_gap"]


def test_generated_outputs_are_not_committed_in_fixture_dir() -> None:
    committed_names = {path.name for path in FIXTURE_DIR.iterdir() if path.is_file()}
    assert committed_names.isdisjoint(GENERATED_OUTPUT_NAMES)


def test_fixture_has_no_obvious_live_or_provenance_markers() -> None:
    combined = "\n".join(path.read_text() for path in sorted(FIXTURE_DIR.glob("*.json")))
    for marker in FORBIDDEN_MARKERS:
        assert marker not in combined

    account_ids = set(re.findall(r"(?<![0-9])[0-9]{12}(?![0-9])", combined))
    assert account_ids <= {"000000000000"}
