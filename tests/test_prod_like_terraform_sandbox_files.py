from __future__ import annotations

import re
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
SANDBOX_DIR = REPO_ROOT / "tests" / "live" / "aws" / "prod_like_accuracy_sandbox"
TERRAFORM_DIR = SANDBOX_DIR / "terraform"
README = SANDBOX_DIR / "README.md"
REQUIRED_FILES = {
    "main.tf",
    "variables.tf",
    "outputs.tf",
    ".gitignore",
}
REQUIRED_GITIGNORE = {
    ".terraform/",
    ".terraform.lock.hcl",
    "terraform.tfstate",
    "terraform.tfstate.backup",
    "*.tfplan",
    "terraform-outputs.json",
    "result.json",
    "*.log",
}
REQUIRED_ROW_IDS = {
    *(f"oracle-v-{index:03d}" for index in range(1, 7)),
    *(f"oracle-b-{index:03d}" for index in range(1, 6)),
    *(f"oracle-p-{index:03d}" for index in range(1, 5)),
    *(f"oracle-i-{index:03d}" for index in range(1, 6)),
    *(f"oracle-u-{index:03d}" for index in range(1, 5)),
}
UNSUPPORTED_ROW_IDS = {
    "oracle-u-001",
    "oracle-u-002",
    "oracle-u-003",
    "oracle-u-004",
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


def _terraform_text() -> str:
    return "\n".join((TERRAFORM_DIR / name).read_text(encoding="utf-8") for name in REQUIRED_FILES)


def _all_sandbox_text() -> str:
    return README.read_text(encoding="utf-8") + "\n" + _terraform_text()


def test_required_terraform_files_and_readme_exist() -> None:
    assert README.is_file()
    assert {path.name for path in TERRAFORM_DIR.iterdir() if path.is_file()} == REQUIRED_FILES


def test_gitignore_excludes_local_terraform_and_live_artifacts() -> None:
    patterns = {
        line.strip() for line in (TERRAFORM_DIR / ".gitignore").read_text(encoding="utf-8").splitlines() if line.strip()
    }
    assert patterns >= REQUIRED_GITIGNORE


def test_terraform_contains_account_ack_and_prefix_guards() -> None:
    text = _terraform_text()

    assert 'variable "aws_profile"' in text
    assert 'variable "aws_region"' in text
    assert 'variable "expected_account_id"' in text
    assert 'variable "resource_prefix"' in text
    assert 'variable "live_ack"' in text
    assert 'data "aws_caller_identity" "current"' in text
    assert 'resource "terraform_data" "safety_guards"' in text
    assert "data.aws_caller_identity.current.account_id == var.expected_account_id" in text
    assert 'var.live_ack == "I_UNDERSTAND_THIS_IS_A_DEDICATED_IAMSCOPE_SANDBOX"' in text
    assert 'startswith(var.resource_prefix, "iamscope-prodlike-v1-")' in text


def test_provider_and_tags_are_bounded_to_aws_provider() -> None:
    text = _terraform_text()

    assert 'source  = "hashicorp/aws"' in text
    assert 'provider "aws"' in text
    assert 'Project   = "IAMScope"' in text
    assert 'Purpose   = "ProdLikeAccuracySandbox"' in text
    assert 'Owner     = "TestOnly"' in text
    assert 'ManagedBy = "Terraform"' in text


def test_terraform_contains_meaningful_iam_policy_relationships() -> None:
    text = _terraform_text()

    assert 'resource "aws_iam_user_policy" "source_relationships"' in text
    assert 'resource "aws_iam_role_policy" "assume_chain_continuation"' in text
    assert 'resource "aws_iam_user_policy_attachment" "identity_deny"' in text
    assert 'resource "aws_iam_user_policy_attachment" "guardrail_simulation"' in text
    assert "permissions_boundary =" in text
    assert '"lambda.amazonaws.com"' in text
    assert '"ecs-tasks.amazonaws.com"' in text


def test_terraform_maps_oracle_rows_to_iam_policy_themes() -> None:
    text = _terraform_text()

    required_terms = {
        "OracleV001PassRoleToScopedLambdaRole",
        "OracleV002EcsTaskRunShape",
        "OracleV003DirectAssumeRole",
        "OracleV004ContinuationAssumeRoleShape",
        "OracleV005CrossAccountShapedConditionSatisfied",
        "OracleV006ServiceMediatedPolicyShape",
        "OracleB001BoundaryBlockedPassRoleLambdaShape",
        "OracleB002BoundaryBlockedChainContinuationShape",
        "OracleB003ScpLikeGuardrailPassRoleShape",
        "OracleB004DenyAssumeRole",
        "OracleB005DenyServiceMediatedPermission",
        "OracleP001ServiceAction",
        "OracleP002PassRoleToRoleWithoutServiceTrust",
        "OracleP003PassRoleWithoutServiceAction",
        "oracle-p-004",
        "OracleI001WildcardResourceScopeUnknown",
        "OracleI002UnresolvedConditionKey",
        "OracleI003SessionBoundaryContextMissing",
        "OracleI004ScpLikeScopeUnknownShape",
        "OracleI005CrossAccountTrustConditionUnknown",
    }
    for term in required_terms:
        assert term in text

    assert "lambda:CreateFunction" in text
    assert "iam:PassRole" in text
    assert "ecs:RegisterTaskDefinition" in text
    assert "ecs:RunTask" in text
    assert "sts:AssumeRole" in text
    assert "Condition" in text
    assert 'effect    = "Deny"' in text


def test_oracle_i001_source_is_split_from_boundary_session_source() -> None:
    text = _terraform_text()

    assert 'uncertainty_resource_probe = "uncertainty-resource-probe"' in text
    assert 'uncertainty_boundary_probe = "uncertainty-boundary-probe"' in text
    assert 'uncertainty_boundary_probe = "session_context"' in text
    assert 'uncertainty_resource_probe = "session_context"' not in text

    i001_start = text.index("oracle-i-001 = {")
    i001_block = text[i001_start : i001_start + 350]
    assert 'source_principal    = "uncertainty_resource_probe"' in i001_block

    i002_start = text.index("oracle-i-002 = {")
    i002_block = text[i002_start : i002_start + 350]
    assert 'source_principal    = "uncertainty_boundary_probe"' in i002_block

    i003_start = text.index("oracle-i-003 = {")
    i003_block = text[i003_start : i003_start + 350]
    assert 'source_principal    = "uncertainty_boundary_probe"' in i003_block


def test_no_raw_non_synthetic_account_ids_or_iam_arns() -> None:
    text = _all_sandbox_text()
    account_ids = set(re.findall(r"\b[0-9]{12}\b", text))
    raw_iam_arn_accounts = set(re.findall(r"arn:aws:iam::([0-9]{12})", text))

    assert account_ids <= {"000000000000"}
    assert raw_iam_arn_accounts <= {"000000000000"}


def test_terraform_files_avoid_work_identifiers() -> None:
    text = _terraform_text().lower()

    assert "work account" not in text
    assert "corporate" not in text
    assert "company" not in text
    assert "employee" not in text


def test_all_oracle_rows_are_mapped() -> None:
    text = _terraform_text()

    for row_id in REQUIRED_ROW_IDS:
        assert row_id in text
    assert len(re.findall(r"oracle-[vbpiu]-[0-9]{3}", text)) >= len(REQUIRED_ROW_IDS)


def test_unsupported_rows_are_static_only_or_no_live_resource() -> None:
    text = _terraform_text()

    for row_id in UNSUPPORTED_ROW_IDS:
        start = text.index(f"{row_id} = {{")
        block = text[start : start + 500]
        assert "static-only" in block
        assert "no live resource" in block


def test_no_lambda_invocation_compute_networking_or_organizations_resources() -> None:
    text = _terraform_text()
    lowered = text.lower()

    assert "lambda:invokefunction" not in lowered
    assert "aws_lambda_function" not in lowered
    assert "aws_lambda_function_url" not in lowered
    assert "aws_lambda_event_source_mapping" not in lowered
    assert "aws_vpc" not in lowered
    assert "aws_subnet" not in lowered
    assert "aws_internet_gateway" not in lowered
    assert "aws_route_table" not in lowered
    assert "aws_security_group" not in lowered
    assert "aws_s3_bucket" not in lowered
    assert "aws_instance" not in lowered
    assert "aws_db_instance" not in lowered
    assert "aws_rds" not in lowered
    assert "aws_dynamodb_table" not in lowered
    assert "aws_organizations" not in lowered
    assert "aws_iam_service_linked_role" not in lowered


def test_no_access_key_secret_or_raw_credential_resources() -> None:
    text = _terraform_text().lower()

    assert "aws_iam_access_key" not in text
    assert "aws_secretsmanager_secret" not in text
    assert "aws_ssm_parameter" not in text
    assert "secret_access_key" not in text
    assert "session_token" not in text
    assert "raw_credentials" not in text


def test_readme_warns_not_to_run_until_phase4_and_lists_non_claims() -> None:
    readme = README.read_text(encoding="utf-8")

    assert "Do not run in production." in readme
    assert "Dedicated sandbox account only." in readme
    assert "No Terraform apply in this PR." in readme
    assert "No AWS resources are created by this PR." in readme
    assert "Do not run until Phase 4 approval" in readme
    assert "expected_account_id" in readme
    assert "I_UNDERSTAND_THIS_IS_A_DEDICATED_IAMSCOPE_SANDBOX" in readme
    assert "source-principal inline policies" in readme
    assert "permission boundaries attached to selected test users" in readme
    assert "explicit deny policy attached to the selected deny probe user" in readme
    assert "Unsupported rows remain static-only" in readme
    for claim in NON_CLAIMS:
        assert claim in readme


def test_no_generated_terraform_or_live_artifacts_are_committed() -> None:
    forbidden_names = {
        "result.json",
        "terraform.tfstate",
        "terraform.tfstate.backup",
        ".terraform.lock.hcl",
        "terraform-outputs.json",
    }
    forbidden_suffixes = (".tfplan", ".log")

    files = [path for path in SANDBOX_DIR.rglob("*") if path.is_file()]
    assert forbidden_names.isdisjoint({path.name for path in files})
    assert not any(path.name.endswith(forbidden_suffixes) for path in files)
    assert not any(".terraform" in path.parts for path in files)


def test_no_score_or_pass_fail_machine_fields_are_introduced() -> None:
    text = _all_sandbox_text().lower()

    assert "composite_score" not in text
    assert "benchmark_passed" not in text
    assert "pass_fail" not in text
    assert "no composite benchmark score" in text
    assert "no pass/fail benchmark label" in text
