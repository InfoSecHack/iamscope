from __future__ import annotations

import argparse
import importlib
import json
import re
from json import JSONDecodeError
from pathlib import Path
from typing import Any, Protocol

from benchmarks.common import dump_json, load_json
from benchmarks.runtime.sts_probe_plan import build_validation

REPORT_TYPE = "sts_probe_executor_simulation"
ALLOWED_MODES = {"simulate", "validate_only", "live_probe"}
REJECTED_LIVE_MODES = {"live", "execute", "assume_role"}
RESULT_CLASSIFICATIONS = {
    "assumed",
    "denied",
    "inconclusive",
    "simulated_not_executed",
    "skipped_safety_guard",
    "configuration_error",
    "unexpected_account",
    "malformed_probe",
}
REQUIRED_OPERATOR_CONFIRMATION = "I understand this will call sts:AssumeRole once for test IAM resources only"
MAX_LIVE_PROBES = 1
EVIDENCE_BOUNDARY = (
    "STS probe executor output is a narrow runtime-probe evidence track. Live mode can only show whether "
    "one configured test principal can assume one configured test role under explicit test conditions. "
    "It does not prove production readiness, broad runtime exploitability, downstream authorization, "
    "or broad IAMScope correctness."
)


class StsClient(Protocol):
    def assume_role(self, **kwargs: Any) -> dict[str, Any]:
        ...


def build_executor_report_from_paths(
    plan_path: str | Path,
    *,
    mode: str,
    allow_live_mode: bool = False,
    operator_confirmation: str | None = None,
    output_paths_supplied: bool = False,
    sts_client: StsClient | None = None,
) -> dict[str, Any]:
    _validate_mode(mode)
    path = Path(plan_path)
    plan = _load_plan_for_executor(path)
    try:
        validation_report = build_validation(plan, plan_path=path)
    except ValueError as exc:
        return _base_report(
            mode=mode,
            plan_path=path,
            execution_results=[
                _execution_result(
                    probe_id="plan",
                    classification="configuration_error",
                    reasons=[f"probe plan validation rejected the plan: {exc}"],
                )
            ],
        )

    if mode == "live_probe":
        execution_results = _live_probe_results(
            validation_report=validation_report,
            plan=plan,
            allow_live_mode=allow_live_mode,
            operator_confirmation=operator_confirmation,
            output_paths_supplied=output_paths_supplied,
            sts_client=sts_client,
        )
    else:
        execution_results = [
            _execution_result_from_validation_result(result, mode=mode)
            for result in validation_report["validation_results"]
        ]
    return _base_report(mode=mode, plan_path=path, execution_results=execution_results)


def write_executor_report(report: dict[str, Any], json_out: str | Path) -> None:
    dump_json(json_out, report)


def render_markdown_report(report: dict[str, Any]) -> str:
    lines = [
        "# IAMScope STS Probe Executor",
        "",
        "Bounded output for the STS AssumeRole executor interface.",
        "",
        f"Mode: `{report['mode']}`.",
        "",
        "No AWS calls are made in `simulate` or `validate_only` mode."
        if not report["live_aws_used"]
        else "AWS calls are limited to the single allowed `sts:AssumeRole` action.",
        "",
        f"Live AWS used: `{str(report['live_aws_used']).lower()}`.",
        "",
        f"AWS calls made: `{str(report['aws_calls_made']).lower()}`.",
        "",
        f"STS AssumeRole called: `{str(report['sts_assume_role_called']).lower()}`.",
        "",
        "No downstream AWS actions are performed.",
        "",
        "No production-readiness claim is made.",
        "",
        "No broad exploitability claim is made.",
        "",
        "This report is a narrow runtime-probe evidence track. It does not prove downstream "
        "authorization, production readiness, broad runtime exploitability, or broad IAMScope "
        "semantic correctness.",
        "",
        "## Inputs",
        "",
        f"- Mode: `{report['mode']}`.",
        f"- Plan path: `{report['plan_path']}`.",
        f"- Live AWS used: `{str(report['live_aws_used']).lower()}`.",
        f"- AWS calls made: `{str(report['aws_calls_made']).lower()}`.",
        f"- STS AssumeRole called: `{str(report['sts_assume_role_called']).lower()}`.",
        f"- Credentials obtained: `{str(report['credentials_obtained']).lower()}`.",
        "",
        "## Execution Results",
        "",
        "| Probe | Classification | Reasons |",
        "| --- | --- | --- |",
    ]
    for result in report["execution_results"]:
        lines.append(
            "| {probe_id} | {classification} | {reasons} |".format(
                probe_id=_markdown_value(result.get("probe_id")),
                classification=_markdown_value(result.get("result_classification")),
                reasons=_markdown_value(", ".join(result.get("reasons", []))),
            )
        )

    lines.extend(
        [
            "",
            "## Caveats",
            "",
            "- No downstream AWS actions are performed after AssumeRole.",
            "- No production-readiness claim is made.",
            "- No broad exploitability claim is made.",
            "- No composite score is emitted.",
            "- Returned credentials are never written to output or used for downstream calls.",
            "- Outputs must not include credentials, tokens, secrets, or raw AWS debug logs.",
            "",
        ]
    )
    return "\n".join(lines)


def write_markdown_report(report: dict[str, Any], markdown_out: str | Path) -> None:
    destination = Path(markdown_out)
    destination.parent.mkdir(parents=True, exist_ok=True)
    destination.write_text(render_markdown_report(report))


def _base_report(*, mode: str, plan_path: Path, execution_results: list[dict[str, Any]]) -> dict[str, Any]:
    live_aws_used = any(bool(result.get("live_aws_used")) for result in execution_results)
    aws_calls_made = any(bool(result.get("aws_calls_made")) for result in execution_results)
    sts_assume_role_called = any(bool(result.get("sts_assume_role_called")) for result in execution_results)
    credentials_obtained = any(bool(result.get("credentials_obtained")) for result in execution_results)
    return {
        "report_type": REPORT_TYPE,
        "mode": mode,
        "live_aws_used": live_aws_used,
        "aws_calls_made": aws_calls_made,
        "sts_assume_role_called": sts_assume_role_called,
        "credentials_obtained": credentials_obtained,
        "plan_path": str(plan_path),
        "execution_results": execution_results,
        "caveats": [
            "narrow_sts_probe_only: live mode is limited to sts:AssumeRole for one validated test role",
            "no_downstream_actions: returned credentials are not used for any downstream AWS API call",
            "credential_sanitization: raw credentials, tokens, and secrets are never emitted",
            "no_production_readiness: output is not a production-readiness claim",
            "no_broad_exploitability: output is not a broad runtime exploitability claim",
            "no_aggregate_scoring: results are per-probe records only",
        ],
        "evidence_boundary": EVIDENCE_BOUNDARY,
    }


def _execution_result_from_validation_result(result: dict[str, Any], *, mode: str) -> dict[str, Any]:
    validation_classification = result.get("result_classification")
    if validation_classification == "valid":
        classification = "simulated_not_executed" if mode == "simulate" else "skipped_safety_guard"
        reasons = [
            "probe plan satisfies dry-run validation",
            "live STS execution is intentionally not implemented in this skeleton",
        ]
    elif validation_classification == "malformed_probe":
        classification = "malformed_probe"
        reasons = list(result.get("reasons", []))
    elif validation_classification == "skipped_safety_guard":
        classification = "skipped_safety_guard"
        reasons = list(result.get("reasons", []))
    else:
        classification = "configuration_error"
        reasons = list(result.get("reasons", []))

    return _execution_result(
        probe_id=str(result.get("probe_id", "unknown")),
        classification=classification,
        reasons=reasons,
        source_principal_arn=result.get("source_principal_arn"),
        target_role_arn=result.get("target_role_arn"),
        expected_account_id=result.get("expected_account_id"),
    )


def _live_probe_results(
    *,
    validation_report: dict[str, Any],
    plan: dict[str, Any],
    allow_live_mode: bool,
    operator_confirmation: str | None,
    output_paths_supplied: bool,
    sts_client: StsClient | None,
) -> list[dict[str, Any]]:
    validation_results = validation_report["validation_results"]
    refusal_reasons = _live_precondition_refusal_reasons(
        validation_results=validation_results,
        plan=plan,
        allow_live_mode=allow_live_mode,
        operator_confirmation=operator_confirmation,
        output_paths_supplied=output_paths_supplied,
    )
    if refusal_reasons:
        return [
            _execution_result_from_refusal(
                result,
                classification=_classification_for_validation_result(result),
                extra_reasons=refusal_reasons,
            )
            for result in validation_results
        ]

    probe = plan["probes"][0]
    client = sts_client
    if client is None:
        try:
            client = _build_default_sts_client(probe["aws_profile"])
        except Exception as exc:
            return [
                _execution_result(
                    probe_id=str(probe["probe_id"]),
                    classification="configuration_error",
                    reasons=[f"unable to construct STS client safely: {_safe_error_category(exc)}"],
                    source_principal_arn=probe.get("source_principal_arn"),
                    target_role_arn=probe.get("target_role_arn"),
                    expected_account_id=probe.get("expected_account_id"),
                )
            ]
    return [_execute_live_probe(probe, client)]


def _live_precondition_refusal_reasons(
    *,
    validation_results: list[dict[str, Any]],
    plan: dict[str, Any],
    allow_live_mode: bool,
    operator_confirmation: str | None,
    output_paths_supplied: bool,
) -> list[str]:
    reasons: list[str] = []
    if not allow_live_mode:
        reasons.append("allow_live_mode must be explicitly enabled")
    if operator_confirmation != REQUIRED_OPERATOR_CONFIRMATION:
        reasons.append("operator confirmation phrase is missing or does not match required text")
    if not output_paths_supplied:
        reasons.append("json_out and markdown_out must both be supplied for live_probe mode")
    if len(validation_results) != MAX_LIVE_PROBES:
        reasons.append(f"live_probe mode supports exactly {MAX_LIVE_PROBES} probe per invocation")
    if any(result.get("result_classification") != "valid" for result in validation_results):
        reasons.append("dry-run validation must be valid for every probe before live_probe mode")
    if _plan_has_disallowed_live_fields(plan):
        reasons.append("downstream actions or raw debug logging are not allowed in live_probe mode")
    return reasons


def _plan_has_disallowed_live_fields(value: Any) -> bool:
    disallowed = {"downstream_actions", "raw_debug_logging", "debug", "collect", "terraform"}
    if isinstance(value, dict):
        return any(key in disallowed or _plan_has_disallowed_live_fields(child) for key, child in value.items())
    if isinstance(value, list):
        return any(_plan_has_disallowed_live_fields(child) for child in value)
    return False


def _classification_for_validation_result(result: dict[str, Any]) -> str:
    classification = result.get("result_classification")
    if classification == "malformed_probe":
        return "malformed_probe"
    if classification == "skipped_safety_guard":
        return "skipped_safety_guard"
    return "configuration_error"


def _execution_result_from_refusal(
    result: dict[str, Any],
    *,
    classification: str,
    extra_reasons: list[str],
) -> dict[str, Any]:
    reasons = list(result.get("reasons", [])) + extra_reasons
    return _execution_result(
        probe_id=str(result.get("probe_id", "unknown")),
        classification=classification,
        reasons=reasons,
        source_principal_arn=result.get("source_principal_arn"),
        target_role_arn=result.get("target_role_arn"),
        expected_account_id=result.get("expected_account_id"),
    )


def _execute_live_probe(probe: dict[str, Any], sts_client: StsClient) -> dict[str, Any]:
    params: dict[str, Any] = {
        "RoleArn": probe["target_role_arn"],
        "RoleSessionName": probe["session_name_prefix"],
        "DurationSeconds": probe["duration_seconds"],
    }
    if probe.get("external_id"):
        params["ExternalId"] = probe["external_id"]

    try:
        response = sts_client.assume_role(**params)
    except Exception as exc:
        category = _safe_error_category(exc)
        classification = "denied" if category == "access_denied" else "inconclusive"
        return _execution_result(
            probe_id=str(probe["probe_id"]),
            classification=classification,
            reasons=[f"sts_assume_role_result={category}"],
            source_principal_arn=probe.get("source_principal_arn"),
            target_role_arn=probe.get("target_role_arn"),
            expected_account_id=probe.get("expected_account_id"),
            live_aws_used=True,
            aws_calls_made=True,
            sts_assume_role_called=True,
            credentials_obtained=False,
            safe_error_category=category,
        )

    observed_account = _assumed_role_account(response)
    if observed_account and observed_account != probe["expected_account_id"]:
        return _execution_result(
            probe_id=str(probe["probe_id"]),
            classification="unexpected_account",
            reasons=["assumed role account did not match expected_account_id"],
            source_principal_arn=probe.get("source_principal_arn"),
            target_role_arn=probe.get("target_role_arn"),
            expected_account_id=probe.get("expected_account_id"),
            observed_account_id=observed_account,
            live_aws_used=True,
            aws_calls_made=True,
            sts_assume_role_called=True,
            credentials_obtained=bool(response.get("Credentials")),
        )

    if not isinstance(response, dict) or not response.get("Credentials"):
        return _execution_result(
            probe_id=str(probe["probe_id"]),
            classification="inconclusive",
            reasons=["sts_assume_role_response_missing_credentials"],
            source_principal_arn=probe.get("source_principal_arn"),
            target_role_arn=probe.get("target_role_arn"),
            expected_account_id=probe.get("expected_account_id"),
            observed_account_id=observed_account,
            live_aws_used=True,
            aws_calls_made=True,
            sts_assume_role_called=True,
            credentials_obtained=False,
        )

    return _execution_result(
        probe_id=str(probe["probe_id"]),
        classification="assumed",
        reasons=["sts_assume_role_succeeded"],
        source_principal_arn=probe.get("source_principal_arn"),
        target_role_arn=probe.get("target_role_arn"),
        expected_account_id=probe.get("expected_account_id"),
        observed_account_id=observed_account,
        live_aws_used=True,
        aws_calls_made=True,
        sts_assume_role_called=True,
        credentials_obtained=True,
    )


def _execution_result(
    *,
    probe_id: str,
    classification: str,
    reasons: list[str],
    source_principal_arn: Any = "unavailable",
    target_role_arn: Any = "unavailable",
    expected_account_id: Any = "unavailable",
    observed_account_id: Any = "unavailable",
    live_aws_used: bool = False,
    aws_calls_made: bool = False,
    sts_assume_role_called: bool = False,
    credentials_obtained: bool = False,
    safe_error_category: str | None = None,
) -> dict[str, Any]:
    _validate_classification(classification)
    result = {
        "probe_id": probe_id,
        "result_classification": classification,
        "reasons": reasons,
        "source_principal_arn": source_principal_arn,
        "target_role_arn": target_role_arn,
        "expected_account_id": expected_account_id,
        "observed_account_id": observed_account_id,
        "live_aws_used": live_aws_used,
        "aws_calls_made": aws_calls_made,
        "sts_assume_role_called": sts_assume_role_called,
        "credentials_obtained": credentials_obtained,
    }
    if safe_error_category:
        result["safe_error_category"] = safe_error_category
    return result


def _load_plan_for_executor(path: Path) -> dict[str, Any]:
    if not path.exists():
        raise ValueError(f"STS probe plan path does not exist: {path}")
    if not path.is_file():
        raise ValueError(f"STS probe plan path is not a file: {path}")
    try:
        payload = load_json(path)
    except JSONDecodeError as exc:
        raise ValueError(f"STS probe plan is malformed JSON: {path}") from exc
    if not isinstance(payload, dict):
        raise ValueError("STS probe plan must be a JSON object")
    return payload


def _validate_mode(mode: str) -> None:
    if mode in REJECTED_LIVE_MODES or mode not in ALLOWED_MODES:
        raise ValueError(f"unsupported STS executor mode: {mode!r}")


def _validate_classification(classification: str) -> None:
    if classification not in RESULT_CLASSIFICATIONS:
        raise ValueError(f"unsupported no-call STS executor classification: {classification!r}")


def _markdown_value(value: Any) -> str:
    if value is None:
        return "n/a"
    return str(value).replace("|", "\\|")


def _build_default_sts_client(aws_profile: str) -> StsClient:
    boto3 = importlib.import_module("boto3")
    session = boto3.Session(profile_name=aws_profile)
    return session.client("sts")


def _safe_error_category(exc: Exception) -> str:
    response = getattr(exc, "response", None)
    if isinstance(response, dict):
        code = response.get("Error", {}).get("Code")
        if code in {"AccessDenied", "AccessDeniedException", "UnauthorizedOperation"}:
            return "access_denied"
        if code in {"ExpiredToken", "InvalidClientTokenId", "UnrecognizedClientException"}:
            return "profile_error"
        if code in {"ValidationError", "MalformedPolicyDocument"}:
            return "validation_error"
        if code:
            return "sts_error"
    name = exc.__class__.__name__.lower()
    if "accessdenied" in name or "access_denied" in name:
        return "access_denied"
    if "timeout" in name or "network" in name or "connection" in name:
        return "network_or_timeout"
    return "unknown_sanitized"


def _assumed_role_account(response: Any) -> str | None:
    if not isinstance(response, dict):
        return None
    arn = response.get("AssumedRoleUser", {}).get("Arn")
    if not isinstance(arn, str):
        return None
    match = re.fullmatch(r"arn:aws:sts::(?P<account>[0-9]{12}):assumed-role/.+", arn)
    if not match:
        return None
    return match.group("account")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Run the STS AssumeRole executor skeleton in no-call/simulation mode."
    )
    parser.add_argument("--plan", required=True, type=Path, help="STS probe plan JSON file.")
    parser.add_argument("--json-out", type=Path, help="Optional path for the JSON simulation report.")
    parser.add_argument("--markdown-out", type=Path, help="Optional path for the Markdown simulation report.")
    parser.add_argument("--mode", required=True, help="Executor mode: simulate, validate_only, or live_probe.")
    parser.add_argument("--allow-live-mode", action="store_true", help="Required explicit opt-in for live_probe.")
    parser.add_argument("--operator-confirmation", help="Required confirmation phrase for live_probe.")
    args = parser.parse_args(argv)

    try:
        report = build_executor_report_from_paths(
            args.plan,
            mode=args.mode,
            allow_live_mode=args.allow_live_mode,
            operator_confirmation=args.operator_confirmation,
            output_paths_supplied=bool(args.json_out and args.markdown_out),
        )
    except ValueError as exc:
        parser.error(str(exc))

    if args.json_out:
        write_executor_report(report, args.json_out)
        print(f"sts_probe_executor_simulation_json={args.json_out.resolve()}")
    if args.markdown_out:
        write_markdown_report(report, args.markdown_out)
        print(f"sts_probe_executor_simulation_markdown={args.markdown_out.resolve()}")
    if not args.json_out and not args.markdown_out:
        print(json.dumps(report, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
