from __future__ import annotations

import argparse
import json
import re
from json import JSONDecodeError
from pathlib import Path
from typing import Any

from benchmarks.common import dump_json, load_json

SCHEMA_VERSION = "0.1"
PLAN_TYPE = "sts_assume_role_probe_plan"
REPORT_TYPE = "sts_probe_plan_validation"
ALLOWED_MODES = {"dry_run", "validate_only"}
ALLOWED_EXPECTED_OUTCOMES = {"assumed", "denied", "inconclusive"}
RESULT_CLASSIFICATIONS = {"valid", "invalid", "skipped_safety_guard", "malformed_probe"}
MAX_DURATION_SECONDS = 900
MAX_SESSION_NAME_PREFIX_LENGTH = 32
IAM_ROLE_ARN_RE = re.compile(r"^arn:aws:iam::(?P<account>[0-9]{12}):role/[A-Za-z0-9+=,.@_/-]+$")
IAM_PRINCIPAL_ARN_RE = re.compile(r"^arn:aws:iam::(?P<account>[0-9]{12}):(user|role)/[A-Za-z0-9+=,.@_/-]+$")
SESSION_NAME_PREFIX_RE = re.compile(r"^[A-Za-z0-9+=,.@_-]{1,32}$")
PRODUCTION_MARKERS = ("prod", "production", "customer", "enterprise")
TEST_MARKERS = ("test", "sandbox", "dev", "staging", "iam_scope", "iamscope")
TOP_LEVEL_REQUIRED_FIELDS = {"schema_version", "plan_type", "mode", "probes"}
TOP_LEVEL_ALLOWED_FIELDS = {*TOP_LEVEL_REQUIRED_FIELDS, "caveats", "notes"}
PROBE_REQUIRED_FIELDS = {
    "probe_id",
    "source_principal_arn",
    "target_role_arn",
    "aws_profile",
    "expected_account_id",
    "session_name_prefix",
    "duration_seconds",
    "expected_outcome",
    "evidence_boundary",
    "safety_notes",
}
PROBE_ALLOWED_FIELDS = {*PROBE_REQUIRED_FIELDS, "region", "external_id"}
FORBIDDEN_FIELDS = {
    "composite_score",
    "overall_score",
    "grade",
    "ranking",
    "pass_rate",
    "production_readiness",
    "benchmark_passed",
    "severity",
    "credentials",
    "access_key",
    "secret_key",
    "session_token",
    "token",
}
EVIDENCE_BOUNDARY = (
    "Dry-run STS probe plan validation only; this makes no AWS calls, does not execute runtime probes, "
    "does not prove runtime reachability, does not prove production readiness, and does not prove broad "
    "runtime exploitability."
)


def build_validation_from_paths(plan_path: str | Path) -> dict[str, Any]:
    path = Path(plan_path)
    plan = _load_probe_plan(path)
    return build_validation(plan, plan_path=path)


def build_validation(plan: dict[str, Any], *, plan_path: str | Path) -> dict[str, Any]:
    _validate_top_level_plan(plan)
    probes = plan["probes"]
    seen_probe_ids: set[str] = set()
    validation_results = [
        _validate_probe(probe, index=index, seen_probe_ids=seen_probe_ids) for index, probe in enumerate(probes)
    ]

    return {
        "report_type": REPORT_TYPE,
        "schema_version": SCHEMA_VERSION,
        "dry_run_only": True,
        "live_aws_used": False,
        "aws_calls_made": False,
        "plan_path": str(plan_path),
        "plan_mode": plan["mode"],
        "probe_count": len(validation_results),
        "validation_results": validation_results,
        "caveats": [
            "dry_run_only: validates probe plans and safety guards without executing probes",
            "no_aws_calls: this validator does not call AWS or STS AssumeRole",
            "no_runtime_proof: validation output is not runtime reachability evidence",
            "no_production_readiness: validation is not a production-readiness claim",
            "no_aggregate_scoring: results are per-probe validation records only",
            "safe_summaries_only: outputs must not include credentials, tokens, secrets, or raw AWS logs",
        ],
        "evidence_boundary": EVIDENCE_BOUNDARY,
    }


def write_validation(report: dict[str, Any], json_out: str | Path) -> None:
    dump_json(json_out, report)


def render_markdown_report(report: dict[str, Any]) -> str:
    lines = [
        "# IAMScope STS Probe Plan Validation",
        "",
        "Dry-run only validation for STS AssumeRole runtime probe plans.",
        "",
        "No AWS calls are made.",
        "",
        "No runtime proof is produced.",
        "",
        "No production-readiness claim is made.",
        "",
        "This report validates configuration and safety guardrails only. It does not execute runtime probes, "
        "call STS AssumeRole, prove broad runtime exploitability, or expand IAMScope semantic correctness claims.",
        "",
        "## Inputs",
        "",
        f"- Plan path: `{report['plan_path']}`.",
        f"- Plan mode: `{report['plan_mode']}`.",
        f"- Dry-run only: `{str(report['dry_run_only']).lower()}`.",
        f"- Live AWS used: `{str(report['live_aws_used']).lower()}`.",
        f"- AWS calls made: `{str(report['aws_calls_made']).lower()}`.",
        "",
        "## Validation Results",
        "",
        "| Probe | Status | Reasons | Target Role | Source Principal |",
        "| --- | --- | --- | --- | --- |",
    ]
    for result in report["validation_results"]:
        lines.append(
            "| {probe_id} | {status} | {reasons} | {target} | {source} |".format(
                probe_id=_markdown_value(result.get("probe_id")),
                status=_markdown_value(result.get("result_classification")),
                reasons=_markdown_value(", ".join(result.get("reasons", []))),
                target=_markdown_value(result.get("target_role_arn")),
                source=_markdown_value(result.get("source_principal_arn")),
            )
        )

    lines.extend(
        [
            "",
            "## Caveats",
            "",
            "- Dry-run only: this report validates probe plans and safety guards without executing probes.",
            "- No AWS calls: this validator does not call AWS or STS AssumeRole.",
            "- No runtime proof: validation output is not runtime reachability evidence.",
            "- No production-readiness claim is made.",
            "- No composite score is emitted.",
            "- Outputs must not include credentials, tokens, secrets, or raw AWS debug logs.",
            "",
        ]
    )
    return "\n".join(lines)


def write_markdown_report(report: dict[str, Any], markdown_out: str | Path) -> None:
    destination = Path(markdown_out)
    destination.parent.mkdir(parents=True, exist_ok=True)
    destination.write_text(render_markdown_report(report))


def _load_probe_plan(path: Path) -> dict[str, Any]:
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


def _validate_top_level_plan(plan: dict[str, Any]) -> None:
    _reject_forbidden_fields(plan)
    _require_fields(plan, TOP_LEVEL_REQUIRED_FIELDS, context="STS probe plan")
    _reject_unknown_fields(plan, TOP_LEVEL_ALLOWED_FIELDS, context="STS probe plan")
    if plan["schema_version"] != SCHEMA_VERSION:
        raise ValueError(f"unsupported STS probe plan schema_version: {plan['schema_version']!r}")
    if plan["plan_type"] != PLAN_TYPE:
        raise ValueError(f"STS probe plan plan_type must be {PLAN_TYPE!r}")
    if plan["mode"] not in ALLOWED_MODES:
        raise ValueError(f"unsupported STS probe plan mode: {plan['mode']!r}")
    if not isinstance(plan["probes"], list):
        raise ValueError("STS probe plan field 'probes' must be a list")


def _validate_probe(probe: Any, *, index: int, seen_probe_ids: set[str]) -> dict[str, Any]:
    if not isinstance(probe, dict):
        return _result(
            probe_id=f"probe_{index}",
            classification="malformed_probe",
            reasons=[f"probe {index} must be an object"],
        )
    _reject_forbidden_fields(probe)
    reasons: list[str] = []
    missing = sorted(field for field in PROBE_REQUIRED_FIELDS if field not in probe)
    if missing:
        reasons.append(f"missing required field(s): {', '.join(missing)}")
    unknown = sorted(field for field in probe if field not in PROBE_ALLOWED_FIELDS)
    if unknown:
        reasons.append(f"unknown field(s): {', '.join(unknown)}")

    probe_id = probe.get("probe_id")
    if not _non_empty_string(probe_id):
        reasons.append("probe_id must be a non-empty string")
        probe_id = f"probe_{index}"
    elif probe_id in seen_probe_ids:
        reasons.append("duplicate probe_id")
    else:
        seen_probe_ids.add(probe_id)

    source_principal_arn = probe.get("source_principal_arn")
    target_role_arn = probe.get("target_role_arn")
    aws_profile = probe.get("aws_profile")
    expected_account_id = probe.get("expected_account_id")
    session_name_prefix = probe.get("session_name_prefix")
    duration_seconds = probe.get("duration_seconds")
    expected_outcome = probe.get("expected_outcome")

    malformed_reasons = _malformed_probe_reasons(
        source_principal_arn=source_principal_arn,
        target_role_arn=target_role_arn,
        expected_account_id=expected_account_id,
    )
    reasons.extend(malformed_reasons)
    reasons.extend(
        _safety_guard_reasons(
            source_principal_arn=source_principal_arn,
            target_role_arn=target_role_arn,
            aws_profile=aws_profile,
            expected_account_id=expected_account_id,
            session_name_prefix=session_name_prefix,
            duration_seconds=duration_seconds,
            expected_outcome=expected_outcome,
            evidence_boundary=probe.get("evidence_boundary"),
            safety_notes=probe.get("safety_notes"),
        )
    )

    if malformed_reasons:
        classification = "malformed_probe"
    elif reasons:
        classification = "skipped_safety_guard" if _has_safety_guard_block(reasons) else "invalid"
    else:
        classification = "valid"
        reasons.append("plan satisfies dry-run safety validation")

    return _result(
        probe_id=str(probe_id),
        classification=classification,
        reasons=reasons,
        source_principal_arn=source_principal_arn,
        target_role_arn=target_role_arn,
        expected_account_id=expected_account_id,
    )


def _malformed_probe_reasons(
    *,
    source_principal_arn: Any,
    target_role_arn: Any,
    expected_account_id: Any,
) -> list[str]:
    reasons: list[str] = []
    if target_role_arn is not None and "*" in str(target_role_arn):
        reasons.append("target_role_arn must not contain wildcards")
    if source_principal_arn is not None and "*" in str(source_principal_arn):
        reasons.append("source_principal_arn must not contain wildcards")
    if target_role_arn is not None and not _role_account(target_role_arn):
        reasons.append("target_role_arn must be an IAM role ARN")
    if source_principal_arn is not None and not _principal_account(source_principal_arn):
        reasons.append("source_principal_arn must be an IAM principal ARN")
    if expected_account_id is not None and not _account_id(expected_account_id):
        reasons.append("expected_account_id must be a 12-digit account ID")
    return reasons


def _safety_guard_reasons(
    *,
    source_principal_arn: Any,
    target_role_arn: Any,
    aws_profile: Any,
    expected_account_id: Any,
    session_name_prefix: Any,
    duration_seconds: Any,
    expected_outcome: Any,
    evidence_boundary: Any,
    safety_notes: Any,
) -> list[str]:
    reasons: list[str] = []
    target_account = _role_account(target_role_arn)
    if target_account and _account_id(expected_account_id) and target_account != expected_account_id:
        reasons.append("target role account does not match expected_account_id")
    if not _non_empty_string(aws_profile):
        reasons.append("aws_profile must be explicitly supplied")
    if not _safe_session_name_prefix(session_name_prefix):
        reasons.append("session_name_prefix must be bounded and STS-safe")
    if not _bounded_duration(duration_seconds):
        reasons.append(f"duration_seconds must be an integer from 1 to {MAX_DURATION_SECONDS}")
    if expected_outcome is not None and expected_outcome not in ALLOWED_EXPECTED_OUTCOMES:
        reasons.append("expected_outcome must be assumed, denied, or inconclusive")
    if not _non_empty_string(evidence_boundary):
        reasons.append("evidence_boundary must be non-empty")
    if not _non_empty_string(safety_notes):
        reasons.append("safety_notes must be non-empty")
    for field_name, value in (
        ("source_principal_arn", source_principal_arn),
        ("target_role_arn", target_role_arn),
        ("aws_profile", aws_profile),
    ):
        if _looks_production_like(value):
            reasons.append(f"{field_name} contains production-like markers without a test marker")
    return reasons


def _result(
    *,
    probe_id: str,
    classification: str,
    reasons: list[str],
    source_principal_arn: Any = None,
    target_role_arn: Any = None,
    expected_account_id: Any = None,
) -> dict[str, Any]:
    _validated_result_classification(classification)
    return {
        "probe_id": probe_id,
        "result_classification": classification,
        "reasons": reasons,
        "source_principal_arn": _safe_value(source_principal_arn),
        "target_role_arn": _safe_value(target_role_arn),
        "expected_account_id": _safe_value(expected_account_id),
    }


def _reject_forbidden_fields(value: Any, *, path: str = "$") -> None:
    if isinstance(value, dict):
        for key, child in value.items():
            if key in FORBIDDEN_FIELDS:
                raise ValueError(f"forbidden STS probe plan field at {path}.{key}: {key}")
            _reject_forbidden_fields(child, path=f"{path}.{key}")
    elif isinstance(value, list):
        for index, child in enumerate(value):
            _reject_forbidden_fields(child, path=f"{path}[{index}]")


def _require_fields(payload: dict[str, Any], required_fields: set[str], *, context: str) -> None:
    missing = sorted(field for field in required_fields if field not in payload)
    if missing:
        raise ValueError(f"{context} missing required field(s): {', '.join(missing)}")


def _reject_unknown_fields(payload: dict[str, Any], allowed_fields: set[str], *, context: str) -> None:
    unknown = sorted(field for field in payload if field not in allowed_fields)
    if unknown:
        raise ValueError(f"{context} has unknown field(s): {', '.join(unknown)}")


def _role_account(value: Any) -> str | None:
    if not isinstance(value, str):
        return None
    match = IAM_ROLE_ARN_RE.fullmatch(value)
    if not match:
        return None
    return match.group("account")


def _principal_account(value: Any) -> str | None:
    if not isinstance(value, str):
        return None
    match = IAM_PRINCIPAL_ARN_RE.fullmatch(value)
    if not match:
        return None
    return match.group("account")


def _account_id(value: Any) -> str | None:
    if isinstance(value, str) and re.fullmatch(r"[0-9]{12}", value):
        return value
    return None


def _safe_session_name_prefix(value: Any) -> bool:
    return isinstance(value, str) and SESSION_NAME_PREFIX_RE.fullmatch(value) is not None


def _bounded_duration(value: Any) -> bool:
    return isinstance(value, int) and not isinstance(value, bool) and 0 < value <= MAX_DURATION_SECONDS


def _looks_production_like(value: Any) -> bool:
    if not isinstance(value, str):
        return False
    lowered = value.lower()
    return any(marker in lowered for marker in PRODUCTION_MARKERS) and not any(
        marker in lowered for marker in TEST_MARKERS
    )


def _has_safety_guard_block(reasons: list[str]) -> bool:
    safety_guard_markers = (
        "target role account does not match expected_account_id",
        "contains production-like markers without a test marker",
    )
    return any(reason in safety_guard_markers for reason in reasons)


def _non_empty_string(value: Any) -> bool:
    return isinstance(value, str) and bool(value.strip())


def _safe_value(value: Any) -> Any:
    return "unavailable" if value is None else value


def _validated_result_classification(value: str) -> str:
    if value not in RESULT_CLASSIFICATIONS:
        raise ValueError(f"unsupported STS probe validation classification: {value!r}")
    return value


def _markdown_value(value: Any) -> str:
    if value is None:
        return "n/a"
    return str(value).replace("|", "\\|")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Validate an STS AssumeRole probe plan without calling AWS.")
    parser.add_argument("--plan", required=True, type=Path, help="STS probe plan JSON file.")
    parser.add_argument("--json-out", type=Path, help="Optional path for the structured JSON validation report.")
    parser.add_argument("--markdown-out", type=Path, help="Optional path for the Markdown validation report.")
    args = parser.parse_args(argv)

    try:
        report = build_validation_from_paths(args.plan)
    except ValueError as exc:
        parser.error(str(exc))

    if args.json_out:
        write_validation(report, args.json_out)
        print(f"sts_probe_plan_validation_json={args.json_out.resolve()}")
    if args.markdown_out:
        write_markdown_report(report, args.markdown_out)
        print(f"sts_probe_plan_validation_markdown={args.markdown_out.resolve()}")
    if not args.json_out and not args.markdown_out:
        print(json.dumps(report, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
