from __future__ import annotations

import json
import re
from collections import Counter
from pathlib import Path
from typing import Any

FIXTURE_DIR = Path("tests/fixtures/demo/complex_shared_uncertainty_iam_benchmark")
FIXTURE_ID = "complex_shared_uncertainty_iam_benchmark_001"
SYNTHETIC_ACCOUNT = "000000000000"
REQUIRED_FILES = {
    "README.md",
    "scenario.json",
    "binding_metadata.json",
    "findings.json",
    "naive_candidates.json",
    "expected_uncertainty_groups.json",
}
EXPECTED_VERDICTS = {
    "validated": 4,
    "blocked": 5,
    "precondition_only": 3,
    "inconclusive": 6,
}
EXPECTED_UNCERTAINTY_GROUPS = {
    "shared_passrole_target_resource_scope_unknown": 3,
    "shared_cross_account_trust_condition_unknown": 2,
    "shared_boundary_or_session_policy_context_missing": 1,
}
REQUIRED_PATTERN_CATEGORIES = {
    "PassRole-to-Lambda",
    "PassRole-to-ECS",
    "AssumeRole chain",
    "Cross-account trust-shaped path",
    "permission boundary blocked path",
    "SCP blocked path",
    "identity-Deny suppressed path",
    "missing iam:PassRole precondition",
    "missing target trust precondition",
    "shared unknown resource scope",
}
EXPECTED_PRINCIPALS = {
    "AnalystUser",
    "CICDRole",
    "DeveloperRole",
    "ReadOnlyAuditRole",
    "BreakGlassCandidateRole",
}
EXPECTED_TARGET_ROLES = {
    "LambdaExecutionAdminLikeRole",
    "LambdaExecutionScopedRole",
    "ECSExecutionAdminLikeRole",
    "CrossAccountOpsRole",
    "BoundaryConstrainedRole",
    "UnknownResourceScopeRole",
}
EXPECTED_SERVICE_PRINCIPALS = {
    "lambda.amazonaws.com",
    "ecs-tasks.amazonaws.com",
}
REQUIRED_NON_CLAIMS = {
    "no_live_aws",
    "no_broad_iamscope_correctness",
    "no_broad_passrole_correctness",
    "no_generic_deny_correctness",
    "no_resource_policy_deny_support",
    "no_scp_deny_support_beyond_selected_synthetic_fixture_behavior",
    "no_exploitability_proof",
    "no_downstream_authorization_proof",
    "no_lambda_invocation_behavior",
    "no_production_readiness",
    "no_correctness_for_real_aws_environments",
    "no_correctness_for_other_principals_roles_accounts_regions_conditions_boundaries_scps_resource_policies_or_findings",
    "no_composite_benchmark_score",
    "no_pass_fail_benchmark_label",
}
GENERATED_ARTIFACT_NAMES = {
    "result.json",
    "terraform.tfstate",
    "terraform.tfstate.backup",
    ".terraform.lock.hcl",
    "terraform-outputs.json",
}
FORBIDDEN_PROVENANCE_MARKERS = [
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


def _combined_fixture_text() -> str:
    return "\n".join(path.read_text() for path in sorted(FIXTURE_DIR.iterdir()) if path.is_file())


def test_required_fixture_files_exist() -> None:
    assert FIXTURE_DIR.is_dir()
    assert {path.name for path in FIXTURE_DIR.iterdir() if path.is_file()} == REQUIRED_FILES


def test_fixture_id_is_consistent() -> None:
    for name in REQUIRED_FILES - {"README.md"}:
        assert _load(name)["fixture_id"] == FIXTURE_ID
    assert FIXTURE_ID in (FIXTURE_DIR / "README.md").read_text()


def test_only_synthetic_account_ids_and_arns_are_present() -> None:
    combined = _combined_fixture_text()
    account_ids = set(re.findall(r"(?<![0-9])[0-9]{12}(?![0-9])", combined))
    raw_arn_accounts = set(re.findall(r"arn:aws:iam::([0-9]{12})", combined))

    assert account_ids <= {SYNTHETIC_ACCOUNT}
    assert raw_arn_accounts <= {SYNTHETIC_ACCOUNT}


def test_local_only_safety_metadata_is_pinned() -> None:
    for name in ["scenario.json", "binding_metadata.json", "findings.json"]:
        payload = _load(name)
        assert payload["aws_calls_made"] == 0
        assert payload["live_aws_used"] is False


def test_synthetic_graph_shape_matches_design() -> None:
    scenario = _load("scenario.json")

    assert set(scenario["principals"]) == EXPECTED_PRINCIPALS
    assert set(scenario["target_roles"]) == EXPECTED_TARGET_ROLES
    assert set(scenario["service_principals"]) == EXPECTED_SERVICE_PRINCIPALS


def test_findings_are_frozen_synthetic_oracle_not_iamscope_replay() -> None:
    findings = _load("findings.json")
    binding = _load("binding_metadata.json")

    assert findings["source_tool"] == "static_fixture_authoring"
    assert findings["generation_mode"] == "frozen_synthetic_oracle"
    assert findings["generated_or_replayed_by_iamscope"] is False
    assert findings["reasoners_run"] == []
    assert findings["metadata"]["source_tool"] == "static_fixture_authoring"
    assert findings["metadata"]["generation_mode"] == "frozen_synthetic_oracle"
    assert findings["metadata"]["generated_or_replayed_by_iamscope"] is False
    assert findings["metadata"]["reasoners_run"] == []
    assert binding["findings_generation"]["mode"] == "frozen_synthetic_oracle"
    assert binding["findings_generation"]["generated_or_replayed_by_iamscope"] is False
    assert binding["findings_generation"]["reasoners_run"] == []


def test_naive_candidate_count_is_exact() -> None:
    naive = _load("naive_candidates.json")
    assert naive["candidate_count"] == 42
    assert len(naive["candidate_paths"]) == 42
    assert naive["is_iamscope_output"] is False
    assert naive["reachability_evidence"] is False


def test_naive_candidates_have_required_shape_and_mapping() -> None:
    finding_ids = {finding["finding_id"] for finding in _load("findings.json")["findings"]}
    required = {
        "candidate_id",
        "source_principal",
        "pattern",
        "target",
        "candidate_interpretation",
        "expected_oracle_status",
        "reason",
    }
    for candidate in _load("naive_candidates.json")["candidate_paths"]:
        assert required <= set(candidate)
        mapping = candidate["maps_to"]
        has_finding = bool(mapping.get("finding_id"))
        has_non_finding_reason = bool(mapping.get("non_finding_reason"))
        assert has_finding != has_non_finding_reason
        if has_finding:
            assert mapping["finding_id"] in finding_ids


def test_finding_count_and_verdict_breakdown_are_exact() -> None:
    findings_doc = _load("findings.json")
    findings = findings_doc["findings"]
    assert len(findings) == 18
    assert Counter(finding["verdict"] for finding in findings) == EXPECTED_VERDICTS
    assert findings_doc["verdict_breakdown"] == EXPECTED_VERDICTS
    assert findings_doc["metadata"]["verdict_breakdown"] == EXPECTED_VERDICTS


def test_uncertainty_group_counts_are_exact_and_reference_findings() -> None:
    findings = _load("findings.json")["findings"]
    finding_ids = {finding["finding_id"] for finding in findings}
    inconclusive_ids = {finding["finding_id"] for finding in findings if finding["verdict"] == "inconclusive"}
    groups = _load("expected_uncertainty_groups.json")["groups"]
    referenced_ids = {finding_id for group in groups for finding_id in group["finding_ids"]}

    assert {group["uncertainty_class"]: group["count"] for group in groups} == EXPECTED_UNCERTAINTY_GROUPS
    assert {group["uncertainty_class"]: len(group["finding_ids"]) for group in groups} == EXPECTED_UNCERTAINTY_GROUPS
    assert referenced_ids <= finding_ids
    assert referenced_ids == inconclusive_ids


def test_required_pattern_categories_are_present() -> None:
    scenario = _load("scenario.json")
    candidate_patterns = {candidate["pattern"] for candidate in _load("naive_candidates.json")["candidate_paths"]}
    finding_patterns = {finding["pattern_id"] for finding in _load("findings.json")["findings"]}

    assert set(scenario["pattern_coverage"]) == REQUIRED_PATTERN_CATEGORIES
    assert {"passrole_lambda", "passrole_ecs", "assume_role_chain", "cross_account_trust"} <= finding_patterns
    assert {
        "permission_boundary_blocked_path",
        "scp_blocked_path",
        "identity_deny_suppressed_path",
        "missing_iam_passrole_precondition",
        "missing_target_trust_precondition",
        "shared_unknown_resource_scope",
    } <= candidate_patterns


def test_each_finding_has_evidence_boundary_and_non_claims() -> None:
    required_finding_fields = {
        "finding_id",
        "source_principal",
        "target",
        "pattern_id",
        "verdict",
        "classification",
        "severity",
        "required_checks",
        "evidence_boundary",
        "non_claims",
    }
    for finding in _load("findings.json")["findings"]:
        assert required_finding_fields <= set(finding)
        assert finding["required_checks"]
        boundary = finding["evidence_boundary"]
        assert boundary["local_only"] is True
        assert boundary["synthetic_fixture"] is True
        assert boundary["frozen_synthetic_oracle"] is True
        assert boundary["live_aws_used"] is False
        assert boundary["aws_calls_made"] == 0
        assert boundary["applies_only_to_fixture_id"] == FIXTURE_ID
        assert set(finding["non_claims"]) == REQUIRED_NON_CLAIMS
        assert all(finding["non_claims"].values())


def test_top_level_non_claims_are_preserved() -> None:
    for name in ["scenario.json", "binding_metadata.json", "findings.json", "naive_candidates.json"]:
        non_claims = _load(name)["non_claims"]
        assert set(non_claims) == REQUIRED_NON_CLAIMS
        assert all(non_claims.values())

    readme = (FIXTURE_DIR / "README.md").read_text()
    for phrase in [
        "no live AWS",
        "no broad IAMScope correctness",
        "no exploitability proof",
        "no production readiness",
        "no composite benchmark score",
        "no pass/fail benchmark label",
    ]:
        assert phrase in readme


def test_fixture_has_no_positive_live_or_score_claims() -> None:
    combined = _combined_fixture_text().lower()
    forbidden_positive_claims = [
        "live aws validation succeeded",
        "proves exploitability",
        "production ready",
        "broad iamscope correctness evidence",
        "composite_score",
        "benchmark_passed",
        "pass/fail score",
    ]
    for marker in forbidden_positive_claims:
        assert marker not in combined


def test_no_generated_artifacts_or_provenance_markers_are_committed() -> None:
    committed_names = {path.name for path in FIXTURE_DIR.iterdir() if path.is_file()}
    assert committed_names.isdisjoint(GENERATED_ARTIFACT_NAMES)
    assert not any(path.suffix == ".tfplan" for path in FIXTURE_DIR.iterdir())

    combined = _combined_fixture_text()
    for marker in FORBIDDEN_PROVENANCE_MARKERS:
        assert marker not in combined
