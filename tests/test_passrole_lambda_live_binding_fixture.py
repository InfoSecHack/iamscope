from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any

from iamscope.models import Edge, Node, NodeRef
from iamscope.reasoner import FactGraph, PassRoleLambdaReasoner, Verdict

REPO_ROOT = Path(__file__).resolve().parents[1]
FIXTURE_DIR = REPO_ROOT / "tests" / "fixtures" / "live_binding" / "passrole_lambda_selected_finding"
DENIED_FIXTURE_DIR = REPO_ROOT / "tests" / "fixtures" / "live_binding" / "passrole_lambda_denied_missing_passrole"
SCENARIO = FIXTURE_DIR / "scenario.json"
EXPECTED = FIXTURE_DIR / "expected_finding.json"
README = FIXTURE_DIR / "README.md"
DENIED_SCENARIO = DENIED_FIXTURE_DIR / "scenario.json"
DENIED_EXPECTED = DENIED_FIXTURE_DIR / "expected_no_selected_finding.json"
DENIED_README = DENIED_FIXTURE_DIR / "README.md"
ALLOWED_SYNTHETIC_ACCOUNT = "000000000000"
FORBIDDEN_GENERATED_NAMES = {
    "result.json",
    "terraform.tfstate",
    "terraform.tfstate.backup",
    ".terraform.lock.hcl",
    "terraform.tfvars",
    "terraform-outputs.json",
}


def _load_json(path: Path) -> dict[str, Any]:
    return json.loads(path.read_text())


def _node_ref(payload: dict[str, Any]) -> NodeRef:
    return NodeRef(
        provider=payload["provider"],
        node_type=payload["node_type"],
        provider_id=payload["provider_id"],
        region=payload["region"],
    )


def _fact_graph_from_scenario(payload: dict[str, Any]) -> FactGraph:
    nodes = tuple(
        Node(
            provider=node["provider"],
            node_type=node["node_type"],
            provider_id=node["provider_id"],
            region=node["region"],
            properties=node.get("properties", {}),
        )
        for node in payload["nodes"]
    )
    edges = tuple(
        Edge(
            edge_type=edge["edge_type"],
            src=_node_ref(edge["src"]),
            dst=_node_ref(edge["dst"]),
            region=edge["region"],
            features=edge.get("features", {}),
        )
        for edge in payload["edges"]
    )
    return FactGraph(
        nodes=nodes,
        edges=edges,
        constraints=(),
        edge_constraints=(),
        scenario_hash=payload["scenario_hash"],
        edge_budget_exhausted=False,
    )


def test_selected_passrole_finding_is_generated_by_existing_reasoner() -> None:
    scenario = _load_json(SCENARIO)
    expected = _load_json(EXPECTED)["selected_finding"]

    findings = PassRoleLambdaReasoner().run(_fact_graph_from_scenario(scenario))

    assert len(findings) == 1
    finding = findings[0]
    assert finding.finding_id == expected["finding_id"]
    assert finding.finding_key == expected["finding_key"]
    assert finding.pattern_id == "passrole_lambda"
    assert finding.verdict is Verdict.VALIDATED
    assert finding.verdict.value == expected["expected_verdict"]
    assert finding.severity == expected["severity"]
    assert finding.severity == "high"
    assert "admin-equivalent" not in finding.title.lower()
    assert "exploit" not in finding.title.lower()
    assert "downstream" not in finding.title.lower()
    assert finding.source.provider_id == expected["source_principal_arn"]
    assert finding.target.provider_id == expected["target_role_arn"]
    assert {check.name: check.state.value for check in finding.required_checks} == expected["required_check_states"]
    assert all(check.state.value == "pass" for check in finding.required_checks)


def test_fixture_is_passrole_lambda_specific_and_sanitized() -> None:
    scenario = _load_json(SCENARIO)
    selected = _load_json(EXPECTED)["selected_finding"]

    assert scenario["generation_mode"] == "local_reasoner_fixture"
    assert scenario["live_aws_used"] is False
    assert scenario["aws_calls_made"] == 0
    assert selected["pattern_id"] == "passrole_lambda"
    assert selected["source_principal_arn"].startswith(f"arn:aws:iam::{ALLOWED_SYNTHETIC_ACCOUNT}:")
    assert selected["target_role_arn"].startswith(f"arn:aws:iam::{ALLOWED_SYNTHETIC_ACCOUNT}:")
    assert selected["expected_classification"] == "selected_local_createfunction_passrole_finding"
    assert selected["live_behavior_alignment"] == "service-mediated CreateFunction plus PassRole plus Lambda trust only"
    assert scenario["scope_boundary"] == {
        "represents_admin_equivalent_execution_role": False,
        "represents_downstream_authorization": False,
        "represents_exploitability": False,
        "represents_lambda_invocation": False,
        "represents_service_mediated_create_function": True,
    }
    assert any(edge["edge_type"] == "lambda:CreateFunction_permission" for edge in scenario["edges"])
    assert any(edge["edge_type"] == "iam:PassRole_permission" for edge in scenario["edges"])
    assert any(edge["edge_type"] == "sts:AssumeRole_trust" for edge in scenario["edges"])
    assert not any(edge["edge_type"] == "iam:*_permission" for edge in scenario["edges"])


def test_fixture_contains_no_raw_live_ids_or_generated_artifacts() -> None:
    text = "\n".join(path.read_text() for path in FIXTURE_DIR.iterdir() if path.is_file())
    account_ids = set(re.findall(r"\b\d{12}\b", text))

    assert account_ids <= {ALLOWED_SYNTHETIC_ACCOUNT}
    selected = _load_json(EXPECTED)["selected_finding"]

    assert "<redacted" not in text.lower()
    assert "AdministratorAccess" not in text
    assert "iam:*_permission" not in text
    assert "admin-equivalent" not in selected["title"].lower()
    assert "downstream" not in selected["title"].lower()
    assert "exploit" not in selected["title"].lower()
    assert "/tmp/iamscope-live-passrole-lambda-validation/result.json" not in text
    assert FORBIDDEN_GENERATED_NAMES.isdisjoint({path.name for path in FIXTURE_DIR.iterdir()})
    assert not any(path.suffix == ".tfplan" for path in FIXTURE_DIR.iterdir())


def test_fixture_documents_boundary_and_next_slice() -> None:
    expected = _load_json(EXPECTED)
    readme = README.read_text()

    assert expected["binding_status"] == "ready_for_next_checkpoint_comparison"
    assert (
        expected["next_slice"] == "Recommended next slice: bind selected IAMScope PassRole finding to live AWS result."
    )
    assert expected["non_claims"] == {
        "no_live_aws": True,
        "no_lambda_invocation_behavior": True,
        "no_admin_equivalent_execution_role_claim": True,
        "no_broad_iamscope_correctness": True,
        "no_broad_passrole_correctness": True,
        "no_exploitability_proof": True,
        "no_downstream_authorization_proof": True,
        "no_production_readiness": True,
        "no_composite_benchmark_score": True,
        "no_pass_fail_benchmark_label": True,
    }
    assert "does not run live AWS" in readme
    assert "does not include an admin-equivalent execution role edge" in readme
    assert "does not claim Lambda invocation behavior" in readme
    assert "does not claim broad IAMScope correctness" in readme


def test_denied_missing_passrole_fixture_emits_no_selected_validated_finding() -> None:
    scenario = _load_json(DENIED_SCENARIO)
    expected = _load_json(DENIED_EXPECTED)["local_expectation"]
    selected_path = _load_json(DENIED_EXPECTED)["selected_path"]

    findings = PassRoleLambdaReasoner().run(_fact_graph_from_scenario(scenario))

    selected_findings = [
        finding
        for finding in findings
        if finding.pattern_id == "passrole_lambda"
        and finding.source.provider_id == selected_path["source_principal_arn"]
        and finding.target.provider_id == selected_path["target_role_arn"]
    ]
    selected_validated = [finding for finding in selected_findings if finding.verdict is Verdict.VALIDATED]

    assert expected["expected_reasoner"] == "PassRoleLambdaReasoner"
    assert expected["expected_selected_validated_finding_emitted"] is False
    assert expected["expected_selected_passrole_lambda_finding_count"] == 0
    assert expected["missing_required_evidence"] == "source_has_passrole_to_target"
    assert selected_findings == []
    assert selected_validated == []


def test_denied_missing_passrole_fixture_shape_is_specific() -> None:
    scenario = _load_json(DENIED_SCENARIO)
    selected_path = scenario["selected_path"]
    source = selected_path["source_principal_arn"]
    target = selected_path["target_role_arn"]

    assert scenario["generation_mode"] == "local_reasoner_fixture"
    assert scenario["live_aws_used"] is False
    assert scenario["aws_calls_made"] == 0
    assert scenario["account_id"] == ALLOWED_SYNTHETIC_ACCOUNT
    assert source.startswith(f"arn:aws:iam::{ALLOWED_SYNTHETIC_ACCOUNT}:role/")
    assert target.startswith(f"arn:aws:iam::{ALLOWED_SYNTHETIC_ACCOUNT}:role/")
    assert scenario["scope_boundary"] == {
        "represents_admin_equivalent_execution_role": False,
        "represents_downstream_authorization": False,
        "represents_exploitability": False,
        "represents_lambda_invocation": False,
        "represents_missing_passrole_denial": True,
        "represents_service_mediated_create_function": True,
    }

    assert any(
        edge["edge_type"] == "lambda:CreateFunction_permission"
        and edge["src"]["provider_id"] == source
        and edge["dst"]["provider_id"] == target
        for edge in scenario["edges"]
    )
    assert not any(
        edge["edge_type"] == "iam:PassRole_permission"
        and edge["src"]["provider_id"] == source
        and edge["dst"]["provider_id"] == target
        for edge in scenario["edges"]
    )
    assert not any(edge["edge_type"] == "iam:PassRole_permission" for edge in scenario["edges"])
    assert any(
        edge["edge_type"] == "sts:AssumeRole_trust"
        and edge["src"]["provider_id"] == "lambda.amazonaws.com"
        and edge["dst"]["provider_id"] == target
        for edge in scenario["edges"]
    )
    assert not any(edge["edge_type"] == "iam:*_permission" for edge in scenario["edges"])


def test_denied_fixture_contains_no_raw_live_ids_or_generated_artifacts() -> None:
    text = "\n".join(path.read_text() for path in DENIED_FIXTURE_DIR.iterdir() if path.is_file())
    account_ids = set(re.findall(r"\b\d{12}\b", text))
    expected = _load_json(DENIED_EXPECTED)

    assert account_ids <= {ALLOWED_SYNTHETIC_ACCOUNT}
    assert "AdministratorAccess" not in text
    assert "iam:*_permission" not in text
    assert "admin-equivalent" not in expected["local_expectation"]["reason"].lower()
    assert "downstream" not in expected["local_expectation"]["reason"].lower()
    assert "exploit" not in expected["local_expectation"]["reason"].lower()
    assert "/tmp/iamscope-live-passrole-lambda-validation-denied/result.json" not in text
    assert FORBIDDEN_GENERATED_NAMES.isdisjoint({path.name for path in DENIED_FIXTURE_DIR.iterdir()})
    assert not any(path.suffix == ".tfplan" for path in DENIED_FIXTURE_DIR.iterdir())


def test_denied_fixture_documents_boundary_and_non_claims() -> None:
    expected = _load_json(DENIED_EXPECTED)
    readme = DENIED_README.read_text()

    assert expected["binding_status"] == "ready_for_denied_checkpoint_comparison"
    assert expected["local_expectation"]["expected_verdict"] == "no_selected_validated_finding"
    assert expected["non_claims"] == {
        "no_live_aws": True,
        "no_lambda_invocation_behavior": True,
        "no_admin_equivalent_execution_role_claim": True,
        "no_broad_iamscope_correctness": True,
        "no_broad_passrole_correctness": True,
        "no_generic_deny_correctness": True,
        "no_exploitability_proof": True,
        "no_downstream_authorization_proof": True,
        "no_production_readiness": True,
        "no_composite_benchmark_score": True,
        "no_pass_fail_benchmark_label": True,
    }
    assert "does not run live AWS" in readme
    assert "source_has_passrole_to_target" in readme
    assert "emits no selected validated `passrole_lambda` finding" in readme
    assert "does not claim Lambda invocation behavior" in readme
    assert "broad IAMScope correctness" in readme
