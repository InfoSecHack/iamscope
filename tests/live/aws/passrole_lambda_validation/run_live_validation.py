#!/usr/bin/env python3
from __future__ import annotations

import argparse
import io
import json
import os
import re
import sys
import zipfile
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

ACK_VALUE = "I_UNDERSTAND_THIS_CREATES_AND_DELETES_TEST_AWS_RESOURCES"
DEFAULT_OUTPUT_DIR = Path("/tmp/iamscope-live-passrole-lambda-validation")
DEFAULT_FUNCTION_PREFIX = "iamscope-live-passrole-lambda-test"
REPO_ROOT = Path(__file__).resolve().parents[4]
ACCOUNT_ID_RE = re.compile(r"^[0-9]{12}$")


@dataclass(frozen=True)
class LiveValidationConfig:
    aws_profile: str
    aws_region: str
    expected_account_id: str
    role_arn: str
    output_dir: Path
    function_name: str
    expected_iamscope_verdict: str | None
    source_principal_arn: str | None


class ConfigError(ValueError):
    pass


def _utc_now() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def _is_inside_repo(path: Path) -> bool:
    resolved = path.expanduser().resolve()
    repo = REPO_ROOT.resolve()
    return resolved == repo or repo in resolved.parents


def _require_output_outside_repo(path: Path) -> None:
    if os.environ.get("IAMSCOPE_LIVE_AWS_TEST_ALLOW_REPO_OUTPUT") == "1":
        return
    if _is_inside_repo(path):
        raise ConfigError("refusing to write live validation output inside the repository tree")


def _require_env(name: str) -> str:
    value = os.environ.get(name, "").strip()
    if not value:
        raise ConfigError(f"required environment variable is not set: {name}")
    return value


def _load_role_arn_from_terraform_outputs(path: Path) -> str:
    try:
        payload = json.loads(path.read_text())
    except OSError as exc:
        raise ConfigError(f"could not read Terraform output JSON: {path}") from exc
    except json.JSONDecodeError as exc:
        raise ConfigError(f"invalid Terraform output JSON: {path}") from exc

    for key in ("lambda_execution_role_arn", "execution_role_arn", "role_arn"):
        item = payload.get(key)
        if isinstance(item, dict) and isinstance(item.get("value"), str):
            return item["value"]
        if isinstance(item, str):
            return item
    raise ConfigError("Terraform output JSON did not include lambda_execution_role_arn")


def _resolve_role_arn(args: argparse.Namespace) -> str:
    if args.role_arn:
        return str(args.role_arn).strip()
    env_role_arn = os.environ.get("IAMSCOPE_LIVE_PASSROLE_LAMBDA_ROLE_ARN", "").strip()
    if env_role_arn:
        return env_role_arn
    terraform_outputs = args.terraform_outputs or os.environ.get("IAMSCOPE_LIVE_PASSROLE_LAMBDA_TERRAFORM_OUTPUTS")
    if terraform_outputs:
        return _load_role_arn_from_terraform_outputs(Path(terraform_outputs))
    raise ConfigError(
        "missing Lambda execution role ARN; pass --role-arn, set "
        "IAMSCOPE_LIVE_PASSROLE_LAMBDA_ROLE_ARN, or pass --terraform-outputs"
    )


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Run one controlled live PassRole-to-Lambda validation case.")
    parser.add_argument("--out", default=str(DEFAULT_OUTPUT_DIR), help="Output directory outside the repository tree.")
    parser.add_argument("--role-arn", help="Test Lambda execution role ARN to pass to CreateFunction.")
    parser.add_argument(
        "--terraform-outputs", help="Path to sanitized terraform output -json file containing role ARN."
    )
    parser.add_argument("--function-name", help="Optional test Lambda function name override.")
    parser.add_argument(
        "--expected-iamscope-verdict", help="Optional selected IAMScope verdict label for the tested path."
    )
    return parser.parse_args(argv)


def load_config(argv: list[str] | None = None) -> LiveValidationConfig:
    args = parse_args(argv)
    ack = _require_env("IAMSCOPE_LIVE_AWS_ACK")
    if ack != ACK_VALUE:
        raise ConfigError("IAMSCOPE_LIVE_AWS_ACK has the wrong value; refusing live AWS validation")

    aws_profile = _require_env("AWS_PROFILE")
    aws_region = _require_env("AWS_REGION")
    expected_account_id = _require_env("IAMSCOPE_EXPECTED_AWS_ACCOUNT_ID")
    if not ACCOUNT_ID_RE.fullmatch(expected_account_id):
        raise ConfigError("IAMSCOPE_EXPECTED_AWS_ACCOUNT_ID must be a 12-digit test account id")

    output_dir = Path(args.out)
    _require_output_outside_repo(output_dir)

    timestamp = datetime.now(timezone.utc).strftime("%Y%m%d%H%M%S")
    function_name = args.function_name or f"{DEFAULT_FUNCTION_PREFIX}-{timestamp}"
    if not function_name.startswith(DEFAULT_FUNCTION_PREFIX):
        raise ConfigError(f"function name must start with {DEFAULT_FUNCTION_PREFIX}")

    return LiveValidationConfig(
        aws_profile=aws_profile,
        aws_region=aws_region,
        expected_account_id=expected_account_id,
        role_arn=_resolve_role_arn(args),
        output_dir=output_dir,
        function_name=function_name,
        expected_iamscope_verdict=args.expected_iamscope_verdict,
        source_principal_arn=os.environ.get("IAMSCOPE_LIVE_PASSROLE_LAMBDA_SOURCE_PRINCIPAL_ARN"),
    )


def _lambda_zip_bytes() -> bytes:
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w", zipfile.ZIP_DEFLATED) as archive:
        archive.writestr(
            "index.py",
            "def handler(event, context):\n    return {'status': 'not_invoked_by_iamscope_live_validation'}\n",
        )
    return buffer.getvalue()


def build_result(
    *,
    config: LiveValidationConfig,
    observed_result: str,
    cleanup_status: str,
    function_created: bool,
    error_category: str | None = None,
) -> dict[str, Any]:
    return {
        "fixture_id": "controlled_live_passrole_lambda_validation_001",
        "schema_version": "0.1",
        "timestamp": _utc_now(),
        "account_id": config.expected_account_id,
        "region": config.aws_region,
        "source_principal_arn": config.source_principal_arn,
        "attempted_action": "lambda:CreateFunction",
        "role_passed": config.role_arn,
        "function_name": config.function_name,
        "expected_iamscope_verdict": config.expected_iamscope_verdict,
        "observed_aws_result": observed_result,
        "function_created": function_created,
        "cleanup_status": cleanup_status,
        "error_category": error_category,
        "safety": {
            "live_aws_used": True,
            "sts_get_caller_identity_called": True,
            "lambda_create_function_called": True,
            "lambda_invoke_function_called": False,
            "triggers_created": False,
            "function_url_created": False,
            "event_source_mappings_created": False,
            "aliases_or_versions_created": False,
            "downstream_actions_tested": False,
        },
        "non_claims": {
            "not_production_readiness": True,
            "not_broad_iamscope_correctness": True,
            "not_broad_passrole_correctness": True,
            "not_exploitability_proof": True,
            "not_downstream_authorization_proof": True,
            "function_was_not_invoked": True,
        },
    }


def _write_result(config: LiveValidationConfig, result: dict[str, Any]) -> Path:
    config.output_dir.mkdir(parents=True, exist_ok=True)
    path = config.output_dir / "result.json"
    path.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n")
    return path


def _client_error_code(exc: Exception) -> str:
    response = getattr(exc, "response", None)
    if isinstance(response, dict):
        error = response.get("Error")
        if isinstance(error, dict) and isinstance(error.get("Code"), str):
            return error["Code"]
    return exc.__class__.__name__


def run_live_validation(config: LiveValidationConfig) -> dict[str, Any]:
    import boto3
    from botocore.exceptions import ClientError

    session = boto3.Session(profile_name=config.aws_profile, region_name=config.aws_region)
    sts = session.client("sts")
    identity = sts.get_caller_identity()
    account_id = str(identity.get("Account", ""))
    if account_id != config.expected_account_id:
        raise ConfigError("STS account id did not match IAMSCOPE_EXPECTED_AWS_ACCOUNT_ID; aborting before Lambda calls")

    lambda_client = session.client("lambda")
    function_created = False
    observed_result = "other_error"
    cleanup_status = "not_needed"
    error_category: str | None = None

    try:
        lambda_client.create_function(
            FunctionName=config.function_name,
            Runtime="python3.12",
            Role=config.role_arn,
            Handler="index.handler",
            Code={"ZipFile": _lambda_zip_bytes()},
            Description="IAMScope controlled live PassRole-to-Lambda validation fixture; not invoked.",
            Timeout=3,
            MemorySize=128,
            Publish=False,
            Tags={
                "Project": "IAMScope",
                "Purpose": "ControlledLiveValidation",
                "Owner": "TestOnly",
            },
        )
        function_created = True
        observed_result = "create_function_succeeded"
        lambda_client.get_function_configuration(FunctionName=config.function_name)
    except ClientError as exc:
        code = _client_error_code(exc)
        error_category = code
        if code in {"AccessDenied", "AccessDeniedException", "UnauthorizedOperation"}:
            observed_result = "access_denied"
        else:
            observed_result = "other_error"
    finally:
        if function_created:
            try:
                lambda_client.delete_function(FunctionName=config.function_name)
                try:
                    lambda_client.get_function(FunctionName=config.function_name)
                    cleanup_status = "delete_requested_but_function_still_found"
                except ClientError as exc:
                    cleanup_status = (
                        "deleted_not_found_verified"
                        if _client_error_code(exc) == "ResourceNotFoundException"
                        else "delete_status_unknown"
                    )
            except ClientError as exc:
                cleanup_status = f"delete_failed:{_client_error_code(exc)}"

    return build_result(
        config=config,
        observed_result=observed_result,
        cleanup_status=cleanup_status,
        function_created=function_created,
        error_category=error_category,
    )


def main(argv: list[str] | None = None) -> int:
    try:
        config = load_config(argv)
        result = run_live_validation(config)
        path = _write_result(config, result)
    except ConfigError as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 2

    print("IAMScope controlled live PassRole-to-Lambda validation")
    print(f"Account: {config.expected_account_id}")
    print(f"Region: {config.aws_region}")
    print(f"Observed AWS result: {result['observed_aws_result']}")
    print(f"Cleanup status: {result['cleanup_status']}")
    print(f"Result: {path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
