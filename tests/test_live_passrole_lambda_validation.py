from __future__ import annotations

import importlib.util
import json
import sys
from pathlib import Path
from types import ModuleType

import pytest

REPO_ROOT = Path(__file__).resolve().parents[1]
LIVE_DIR = REPO_ROOT / "tests" / "live" / "aws" / "passrole_lambda_validation"
RUNNER = LIVE_DIR / "run_live_validation.py"
TERRAFORM_DIR = LIVE_DIR / "terraform"
ACK_VALUE = "I_UNDERSTAND_THIS_CREATES_AND_DELETES_TEST_AWS_RESOURCES"


def _load_runner() -> ModuleType:
    spec = importlib.util.spec_from_file_location("passrole_lambda_live_validation", RUNNER)
    assert spec is not None
    assert spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


@pytest.fixture()
def runner() -> ModuleType:
    return _load_runner()


def _set_required_env(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("IAMSCOPE_LIVE_AWS_ACK", ACK_VALUE)
    monkeypatch.setenv("AWS_PROFILE", "iamscope-test-profile")
    monkeypatch.setenv("AWS_REGION", "us-east-1")
    monkeypatch.setenv("IAMSCOPE_EXPECTED_AWS_ACCOUNT_ID", "123456\u003789012")


def test_runner_refuses_without_acknowledgement(
    monkeypatch: pytest.MonkeyPatch, runner: ModuleType, tmp_path: Path
) -> None:
    monkeypatch.delenv("IAMSCOPE_LIVE_AWS_ACK", raising=False)
    monkeypatch.setenv("AWS_PROFILE", "iamscope-test-profile")
    monkeypatch.setenv("AWS_REGION", "us-east-1")
    monkeypatch.setenv("IAMSCOPE_EXPECTED_AWS_ACCOUNT_ID", "123456\u003789012")

    with pytest.raises(runner.ConfigError, match="IAMSCOPE_LIVE_AWS_ACK"):
        runner.load_config(["--role-arn", "arn:aws:iam::123456\u003789012:role/test", "--out", str(tmp_path)])


def test_runner_refuses_without_expected_account_id(
    monkeypatch: pytest.MonkeyPatch, runner: ModuleType, tmp_path: Path
) -> None:
    monkeypatch.setenv("IAMSCOPE_LIVE_AWS_ACK", ACK_VALUE)
    monkeypatch.setenv("AWS_PROFILE", "iamscope-test-profile")
    monkeypatch.setenv("AWS_REGION", "us-east-1")
    monkeypatch.delenv("IAMSCOPE_EXPECTED_AWS_ACCOUNT_ID", raising=False)

    with pytest.raises(runner.ConfigError, match="IAMSCOPE_EXPECTED_AWS_ACCOUNT_ID"):
        runner.load_config(["--role-arn", "arn:aws:iam::123456\u003789012:role/test", "--out", str(tmp_path)])


def test_runner_refuses_repository_output_path(monkeypatch: pytest.MonkeyPatch, runner: ModuleType) -> None:
    _set_required_env(monkeypatch)

    with pytest.raises(runner.ConfigError, match="repository tree"):
        runner.load_config(["--role-arn", "arn:aws:iam::123456\u003789012:role/test", "--out", str(REPO_ROOT)])


def test_config_parsing_uses_terraform_outputs_without_aws_credentials(
    monkeypatch: pytest.MonkeyPatch, runner: ModuleType, tmp_path: Path
) -> None:
    _set_required_env(monkeypatch)
    terraform_outputs = tmp_path / "terraform-outputs.json"
    terraform_outputs.write_text(
        json.dumps(
            {
                "lambda_execution_role_arn": {
                    "value": "arn:aws:iam::123456\u003789012:role/iamscope-live-passrole-lambda-test-lambda-exec-role"
                }
            }
        )
    )

    config = runner.load_config(["--terraform-outputs", str(terraform_outputs), "--out", str(tmp_path / "out")])

    assert config.aws_profile == "iamscope-test-profile"
    assert config.aws_region == "us-east-1"
    assert config.expected_account_id == "123456\u003789012"
    assert config.role_arn.endswith("iamscope-live-passrole-lambda-test-lambda-exec-role")
    assert config.validation_mode == "allowed"
    assert config.expected_observed_aws_result == "create_function_succeeded"


def test_denied_config_parsing_uses_terraform_outputs_without_aws_credentials(
    monkeypatch: pytest.MonkeyPatch, runner: ModuleType, tmp_path: Path
) -> None:
    _set_required_env(monkeypatch)
    terraform_outputs = tmp_path / "terraform-outputs.json"
    terraform_outputs.write_text(
        json.dumps(
            {
                "lambda_execution_role_arn": {
                    "value": "arn:aws:iam::123456\u003789012:role/iamscope-live-passrole-lambda-test-lambda-exec-role"
                },
                "denied_source_role_arn": {
                    "value": "arn:aws:iam::123456\u003789012:role/iamscope-live-passrole-lambda-test-denied-source-role"
                },
            }
        )
    )

    config = runner.load_config(
        [
            "--mode",
            "denied_missing_passrole",
            "--terraform-outputs",
            str(terraform_outputs),
            "--out",
            str(tmp_path / "out"),
        ]
    )

    assert config.validation_mode == "denied_missing_passrole"
    assert config.expected_observed_aws_result == "access_denied"
    assert config.role_arn.endswith("iamscope-live-passrole-lambda-test-lambda-exec-role")
    assert config.denied_source_role_arn is not None
    assert config.denied_source_role_arn.endswith("iamscope-live-passrole-lambda-test-denied-source-role")
    assert config.source_principal_arn == config.denied_source_role_arn


def test_denied_mode_requires_denied_source_role(
    monkeypatch: pytest.MonkeyPatch, runner: ModuleType, tmp_path: Path
) -> None:
    _set_required_env(monkeypatch)

    with pytest.raises(runner.ConfigError, match="denied source role ARN"):
        runner.load_config(
            [
                "--mode",
                "denied_missing_passrole",
                "--role-arn",
                "arn:aws:iam::123456\u003789012:role/iamscope-live-passrole-lambda-test-lambda-exec-role",
                "--out",
                str(tmp_path / "out"),
            ]
        )


def test_result_shape_preserves_non_claims_and_redaction(runner: ModuleType, tmp_path: Path) -> None:
    config = runner.LiveValidationConfig(
        aws_profile="iamscope-test-profile",
        aws_region="us-east-1",
        expected_account_id="123456\u003789012",
        role_arn="arn:aws:iam::123456\u003789012:role/iamscope-live-passrole-lambda-test-lambda-exec-role",
        output_dir=tmp_path,
        function_name="iamscope-live-passrole-lambda-test-202606\u00302000000",
        expected_iamscope_verdict="validated",
        source_principal_arn="arn:aws:iam::123456\u003789012:role/iamscope-live-passrole-lambda-test-source",
    )

    result = runner.build_result(
        config=config,
        observed_result="create_function_succeeded",
        cleanup_status="deleted_not_found_verified",
        function_created=True,
    )

    assert result["attempted_action"] == "lambda:CreateFunction"
    assert result["validation_mode"] == "allowed"
    assert result["expected_observed_aws_result"] == "create_function_succeeded"
    assert result["account_id"] == "123456\u003789012"
    assert result["observed_aws_result"] == "create_function_succeeded"
    assert result["safety"]["lambda_invoke_function_called"] is False
    assert result["safety"]["triggers_created"] is False
    assert result["safety"]["downstream_actions_tested"] is False
    assert result["non_claims"] == {
        "not_production_readiness": True,
        "not_broad_iamscope_correctness": True,
        "not_broad_passrole_correctness": True,
        "not_exploitability_proof": True,
        "not_downstream_authorization_proof": True,
        "function_was_not_invoked": True,
    }


def test_denied_result_shape_preserves_expected_denial_and_non_claims(runner: ModuleType, tmp_path: Path) -> None:
    config = runner.LiveValidationConfig(
        aws_profile="iamscope-test-profile",
        aws_region="us-east-1",
        expected_account_id="123456\u003789012",
        role_arn="arn:aws:iam::123456\u003789012:role/iamscope-live-passrole-lambda-test-lambda-exec-role",
        output_dir=tmp_path,
        function_name="iamscope-live-passrole-lambda-test-202606\u00302000000",
        expected_iamscope_verdict=None,
        source_principal_arn="arn:aws:iam::123456\u003789012:role/iamscope-live-passrole-lambda-test-denied-source-role",
        validation_mode="denied_missing_passrole",
        expected_observed_aws_result="access_denied",
        denied_source_role_arn="arn:aws:iam::123456\u003789012:role/iamscope-live-passrole-lambda-test-denied-source-role",
    )

    result = runner.build_result(
        config=config,
        observed_result="access_denied",
        cleanup_status="not_needed",
        function_created=False,
        error_category="AccessDeniedException",
    )

    assert result["validation_mode"] == "denied_missing_passrole"
    assert result["expected_observed_aws_result"] == "access_denied"
    assert result["observed_aws_result"] == "access_denied"
    assert result["function_created"] is False
    assert result["cleanup_status"] == "not_needed"
    assert result["denied_source_role_arn"] == config.denied_source_role_arn
    assert result["safety"]["lambda_invoke_function_called"] is False
    assert result["safety"]["downstream_actions_tested"] is False
    assert result["non_claims"]["not_broad_iamscope_correctness"] is True
    assert result["non_claims"]["not_exploitability_proof"] is True


def test_no_generated_live_outputs_or_terraform_artifacts_committed() -> None:
    forbidden_names = {
        ".terraform",
        ".terraform.lock.hcl",
        "terraform.tfstate",
        "terraform.tfstate.backup",
        "result.json",
        "terraform.tfvars",
    }
    tracked_like_files = {path.name for path in LIVE_DIR.rglob("*") if path.is_file()}
    assert forbidden_names.isdisjoint(tracked_like_files)
    assert not any(path.suffix == ".tfplan" for path in LIVE_DIR.rglob("*"))


def test_terraform_fixture_uses_test_prefix_required_tags_and_account_guard() -> None:
    terraform_text = "\n".join(path.read_text() for path in TERRAFORM_DIR.glob("*.tf"))
    assert "profile = var.aws_profile" in terraform_text
    assert 'data "aws_caller_identity" "current"' in terraform_text
    assert "data.aws_caller_identity.current.account_id == var.expected_account_id" in terraform_text
    assert "depends_on = [terraform_data.expected_account_guard]" in terraform_text
    assert "iamscope-live-passrole-lambda-test" in terraform_text
    assert "Project" in terraform_text
    assert "IAMScope" in terraform_text
    assert "Purpose" in terraform_text
    assert "ControlledLiveValidation" in terraform_text
    assert "Owner" in terraform_text
    assert "TestOnly" in terraform_text


def test_terraform_fixture_defines_denied_source_without_passrole_allow() -> None:
    terraform_text = "\n".join(path.read_text() for path in TERRAFORM_DIR.glob("*.tf"))
    assert 'variable "denied_source_trusted_principal_arn"' in terraform_text
    assert 'resource "aws_iam_role" "denied_source"' in terraform_text
    assert 'data "aws_iam_policy_document" "denied_source_assume_role"' in terraform_text
    assert "data.aws_caller_identity.current.arn" in terraform_text
    assert 'data "aws_iam_policy_document" "denied_source_lambda_create"' in terraform_text
    assert '"lambda:CreateFunction"' in terraform_text
    assert 'resource "aws_iam_role_policy_attachment" "denied_source_lambda_create"' in terraform_text
    assert 'output "denied_source_role_arn"' in terraform_text
    assert 'output "denied_source_role_name"' in terraform_text

    denied_policy_start = terraform_text.index('data "aws_iam_policy_document" "denied_source_lambda_create"')
    denied_policy_end = terraform_text.index('resource "aws_iam_role" "lambda_execution"')
    denied_policy_text = terraform_text[denied_policy_start:denied_policy_end]
    assert "iam:PassRole" not in denied_policy_text


def test_denied_mode_classifies_access_denied_without_creating_function(
    monkeypatch: pytest.MonkeyPatch, runner: ModuleType, tmp_path: Path
) -> None:
    class FakeClientError(Exception):
        def __init__(self, code: str) -> None:
            self.response = {"Error": {"Code": code}}
            super().__init__(code)

    class FakeStsClient:
        def get_caller_identity(self) -> dict[str, str]:
            return {"Account": "123456\u003789012"}

        def assume_role(self, **kwargs: object) -> dict[str, dict[str, str]]:
            assert str(kwargs["RoleArn"]).endswith("iamscope-live-passrole-lambda-test-denied-source-role")
            assert kwargs["RoleSessionName"] == "iamscope-live-passrole-denied-validation"
            return {
                "Credentials": {
                    "AccessKeyId": "test-access-key",
                    "SecretAccessKey": "test-secret-key",
                    "SessionToken": "test-session-token",
                }
            }

    class FakeLambdaClient:
        def create_function(self, **_kwargs: object) -> object:
            raise FakeClientError("AccessDeniedException")

    class FakeSession:
        def __init__(self, **kwargs: object) -> None:
            self.kwargs = kwargs

        def client(self, service_name: str) -> object:
            if service_name == "sts":
                return FakeStsClient()
            if service_name == "lambda":
                assert self.kwargs.get("aws_session_token") == "test-session-token"
                return FakeLambdaClient()
            raise AssertionError(f"unexpected service {service_name}")

    fake_boto3 = ModuleType("boto3")
    fake_boto3.Session = FakeSession  # type: ignore[attr-defined]
    fake_botocore = ModuleType("botocore")
    fake_exceptions = ModuleType("botocore.exceptions")
    fake_exceptions.ClientError = FakeClientError  # type: ignore[attr-defined]
    monkeypatch.setitem(sys.modules, "boto3", fake_boto3)
    monkeypatch.setitem(sys.modules, "botocore", fake_botocore)
    monkeypatch.setitem(sys.modules, "botocore.exceptions", fake_exceptions)

    config = runner.LiveValidationConfig(
        aws_profile="iamscope-test-profile",
        aws_region="us-east-1",
        expected_account_id="123456\u003789012",
        role_arn="arn:aws:iam::123456\u003789012:role/iamscope-live-passrole-lambda-test-lambda-exec-role",
        output_dir=tmp_path,
        function_name="iamscope-live-passrole-lambda-test-202606\u00302000000",
        expected_iamscope_verdict=None,
        source_principal_arn="arn:aws:iam::123456\u003789012:role/iamscope-live-passrole-lambda-test-denied-source-role",
        validation_mode="denied_missing_passrole",
        expected_observed_aws_result="access_denied",
        denied_source_role_arn="arn:aws:iam::123456\u003789012:role/iamscope-live-passrole-lambda-test-denied-source-role",
    )

    result = runner.run_live_validation(config)

    assert result["observed_aws_result"] == "access_denied"
    assert result["function_created"] is False
    assert result["cleanup_status"] == "not_needed"
    assert result["error_category"] == "AccessDeniedException"
    assert result["validation_mode"] == "denied_missing_passrole"


def test_cleanup_failure_exits_nonzero_after_writing_result(
    monkeypatch: pytest.MonkeyPatch, runner: ModuleType, tmp_path: Path
) -> None:
    config = runner.LiveValidationConfig(
        aws_profile="iamscope-test-profile",
        aws_region="us-east-1",
        expected_account_id="123456\u003789012",
        role_arn="arn:aws:iam::123456\u003789012:role/iamscope-live-passrole-lambda-test-lambda-exec-role",
        output_dir=tmp_path,
        function_name="iamscope-live-passrole-lambda-test-202606\u00302000000",
        expected_iamscope_verdict="validated",
        source_principal_arn=None,
    )
    result = runner.build_result(
        config=config,
        observed_result="create_function_succeeded",
        cleanup_status="delete_failed:AccessDeniedException",
        function_created=True,
    )

    monkeypatch.setattr(runner, "load_config", lambda _argv=None: config)
    monkeypatch.setattr(runner, "run_live_validation", lambda _config: result)

    assert runner.main([]) == 1
    written = json.loads((tmp_path / "result.json").read_text())
    assert written["cleanup_status"] == "delete_failed:AccessDeniedException"


def test_denied_unexpected_create_cleanup_failure_exits_nonzero_after_writing_result(
    monkeypatch: pytest.MonkeyPatch, runner: ModuleType, tmp_path: Path
) -> None:
    config = runner.LiveValidationConfig(
        aws_profile="iamscope-test-profile",
        aws_region="us-east-1",
        expected_account_id="123456\u003789012",
        role_arn="arn:aws:iam::123456\u003789012:role/iamscope-live-passrole-lambda-test-lambda-exec-role",
        output_dir=tmp_path,
        function_name="iamscope-live-passrole-lambda-test-202606\u00302000000",
        expected_iamscope_verdict=None,
        source_principal_arn="arn:aws:iam::123456\u003789012:role/iamscope-live-passrole-lambda-test-denied-source-role",
        validation_mode="denied_missing_passrole",
        expected_observed_aws_result="access_denied",
        denied_source_role_arn="arn:aws:iam::123456\u003789012:role/iamscope-live-passrole-lambda-test-denied-source-role",
    )
    result = runner.build_result(
        config=config,
        observed_result="create_function_succeeded",
        cleanup_status="delete_status_unknown",
        function_created=True,
    )

    monkeypatch.setattr(runner, "load_config", lambda _argv=None: config)
    monkeypatch.setattr(runner, "run_live_validation", lambda _config: result)

    assert runner.main([]) == 1
    written = json.loads((tmp_path / "result.json").read_text())
    assert written["validation_mode"] == "denied_missing_passrole"
    assert written["cleanup_status"] == "delete_status_unknown"


def test_cleanup_failure_helper_allows_no_create_or_verified_delete(runner: ModuleType) -> None:
    assert runner.cleanup_failed_closed({"function_created": False, "cleanup_status": "not_needed"}) is False
    assert (
        runner.cleanup_failed_closed({"function_created": True, "cleanup_status": "deleted_not_found_verified"})
        is False
    )
    assert runner.cleanup_failed_closed({"function_created": True, "cleanup_status": "delete_status_unknown"}) is True
