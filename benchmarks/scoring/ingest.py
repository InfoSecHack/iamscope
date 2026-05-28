from __future__ import annotations

import argparse
import re
import subprocess
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from benchmarks.common import MANIFEST_VERSION, dump_json, load_json


CASE_CONTEXT_LABELS: dict[str, dict[str, str]] = {
    "env03_identity_deny_group_escalation": {
        "source_label": "alice_arn",
        "target_label": "admins_arn",
    },
    "env05_permission_boundary_blocked_chain": {
        "source_label": "alice_arn",
        "target_label": "admin_arn",
    },
    "env06_validated_admin_reachability": {
        "source_label": "alice_arn",
        "target_label": "admin_arn",
    },
    "env07_validated_non_admin_reachability": {
        "source_label": "alice_arn",
        "target_label": "reader_arn",
    },
    "env08_trust_condition_blocked_admin": {
        "source_label": "alice_arn",
        "target_label": "conditioned_admin_arn",
    },
    "env09_boundary_removed_validated_admin": {
        "source_label": "alice_arn",
        "target_label": "admin_arn",
    },
    "env10_trust_condition_removed_validated_admin": {
        "source_label": "alice_arn",
        "target_label": "admin_arn",
    },
    "env11_broad_trust_condition_blocked_admin": {
        "source_label": "alice_arn",
        "target_label": "broad_conditioned_admin_arn",
    },
    "env12_scp_blocked_assumerole": {
        "source_label": "alice_arn",
        "target_label": "admin_arn",
    },
    "env13_complete_scp_blocked_assumerole": {
        "source_label": "alice_arn",
        "target_label": "admin_arn",
    },
    "env14_permission_condition_blocked_admin": {
        "source_label": "alice_arn",
        "target_label": "admin_arn",
    },
    "env15_permission_condition_removed_validated_admin": {
        "source_label": "alice_arn",
        "target_label": "admin_arn",
    },
    "env16_identity_deny_removed_validated_group_escalation": {
        "source_label": "alice_arn",
        "target_label": "admins_arn",
    },
    "env17_scp_removed_validated_admin": {
        "source_label": "alice_arn",
        "target_label": "admin_arn",
    },
    "env18_lambda_passrole_validated": {
        "source_label": "alice_arn",
        "target_label": "lambda_admin_role_arn",
    },
    "env19_passedtoservice_scoped_away_nonvalidated": {
        "source_label": "alice_arn",
        "target_label": "lambda_admin_role_arn",
    },
    "env20_ecs_passrole_validated": {
        "source_label": "alice_arn",
        "target_label": "ecs_admin_role_arn",
    },
    "env21_ecs_passedtoservice_scoped_away_nonvalidated": {
        "source_label": "alice_arn",
        "target_label": "ecs_admin_role_arn",
    },
    "env22_cross_account_validated_admin": {
        "source_label": "alice_arn",
        "target_label": "admin_arn",
    },
    "env23_cross_account_trust_scoped_away_nonvalidated": {
        "source_label": "alice_arn",
        "target_label": "admin_arn",
    },
    "env24_s3_resource_policy_allow": {
        "source_label": "reader_arn",
        "target_label": "bucket_arn",
    },
    "env25_s3_resource_policy_allow_scoped_away_nonvalidated": {
        "source_label": "reader_arn",
        "target_label": "bucket_arn",
        "decoy_label": "decoy_arn",
    },
    "env26_multihop_chain_validated_admin": {
        "source_label": "alice_arn",
        "target_label": "admin_arn",
        "hop1_label": "hop1_arn",
        "hop2_label": "hop2_arn",
    },
    "env27_multihop_trust_scoped_away_nonvalidated": {
        "source_label": "alice_arn",
        "target_label": "admin_arn",
        "decoy_label": "decoy_arn",
        "hop1_label": "hop1_arn",
        "hop2_label": "hop2_arn",
    },
    "deg07_missing_required_artifacts": {
        "source_label": "alice_arn",
        "target_label": "admin_arn",
    },
}


def _case_manifest_path(repo_root: Path, case_id: str) -> Path:
    return repo_root / "benchmarks" / "cases" / f"{case_id}.json"


def _parse_run_log_context(run_log_text: str, case_id: str) -> dict[str, Any]:
    labels = CASE_CONTEXT_LABELS.get(case_id)
    if labels is None:
        raise ValueError(f"unsupported case_id for archive ingest: {case_id}")
    values: dict[str, str] = {}
    account_id: str | None = None
    for line in run_log_text.splitlines():
        match = re.match(r"^\s*([A-Za-z0-9_]+)\s*:\s*(.+?)\s*$", line)
        if not match:
            continue
        key, value = match.groups()
        if value.startswith("arn:"):
            values[key] = value
        elif key == "account_id" and re.fullmatch(r"\d{12}", value):
            account_id = value
    source_provider_id = values.get(labels["source_label"])
    target_provider_id = values.get(labels["target_label"])
    if not isinstance(source_provider_id, str) or not isinstance(target_provider_id, str):
        raise ValueError(f"could not infer source/target provider IDs from run.log for case_id {case_id}")
    context: dict[str, Any] = {
        "source_provider_id": source_provider_id,
        "target_provider_id": target_provider_id,
    }
    decoy_label = labels.get("decoy_label")
    if decoy_label is not None:
        decoy_provider_id = values.get(decoy_label)
        if not isinstance(decoy_provider_id, str):
            raise ValueError(f"could not infer decoy provider ID from run.log for case_id {case_id}")
        context["decoy_provider_id"] = decoy_provider_id
    hop1_label = labels.get("hop1_label")
    if hop1_label is not None:
        hop1_provider_id = values.get(hop1_label)
        if not isinstance(hop1_provider_id, str):
            raise ValueError(f"could not infer hop1 provider ID from run.log for case_id {case_id}")
        context["hop1_provider_id"] = hop1_provider_id
    hop2_label = labels.get("hop2_label")
    if hop2_label is not None:
        hop2_provider_id = values.get(hop2_label)
        if not isinstance(hop2_provider_id, str):
            raise ValueError(f"could not infer hop2 provider ID from run.log for case_id {case_id}")
        context["hop2_provider_id"] = hop2_provider_id
    if account_id is not None:
        context["account_id"] = account_id
    return context


def _parse_scenario_validation_status(text: str) -> str:
    upper_text = text.upper()
    if "PASS" in upper_text or "PASSED" in upper_text:
        return "pass"
    if "FAIL" in upper_text or "FAILED" in upper_text:
        return "fail"
    return "unknown"


def _infer_started_at_from_run_id(run_id: str) -> str | None:
    match = re.search(r"(\d{8}T\d{6}Z)", run_id)
    if match is None:
        return None
    raw = match.group(1)
    started = datetime.strptime(raw, "%Y%m%dT%H%M%SZ").replace(tzinfo=timezone.utc)
    return started.isoformat().replace("+00:00", "Z")


def _infer_ended_at(paths: list[Path]) -> str | None:
    existing = [path for path in paths if path.exists()]
    if not existing:
        return None
    ended = max(datetime.fromtimestamp(path.stat().st_mtime, tz=timezone.utc) for path in existing)
    return ended.isoformat().replace("+00:00", "Z")


def _infer_git_sha(repo_root: Path) -> str | None:
    try:
        result = subprocess.run(
            ["git", "rev-parse", "HEAD"],
            cwd=repo_root,
            check=True,
            capture_output=True,
            text=True,
        )
    except (FileNotFoundError, subprocess.CalledProcessError):
        return None
    git_sha = result.stdout.strip()
    return git_sha or None


def ingest_archive(case_id: str, archive_dir: Path, out_path: Path, repo_root: Path) -> dict[str, Any]:
    case_manifest_file = _case_manifest_path(repo_root, case_id)
    if not case_manifest_file.exists():
        raise FileNotFoundError(f"missing Phase 0 case manifest for case_id {case_id}: {case_manifest_file}")
    case_manifest = load_json(case_manifest_file)

    run_log_path = archive_dir / "run.log"
    scenario_validate_path = archive_dir / "scenario_validate.txt"
    scenario_path = archive_dir / "collect" / "scenario.json"
    findings_path = archive_dir / "collect" / "findings.json"
    required_paths = {
        "run.log": run_log_path,
        "scenario_validate.txt": scenario_validate_path,
    }
    missing = [name for name, path in required_paths.items() if not path.exists()]
    if missing:
        raise FileNotFoundError(f"missing required archive artifacts: {', '.join(missing)}")

    binding_metadata_path = archive_dir / "collect" / "binding_metadata.json"
    expected_findings_path = archive_dir / "expected_findings.json"
    run_id = archive_dir.name
    run_log_text = run_log_path.read_text()
    scenario_validate_text = scenario_validate_path.read_text()
    started_at = _infer_started_at_from_run_id(run_id)
    ended_at = _infer_ended_at(
        [
            run_log_path,
            scenario_validate_path,
            scenario_path,
            findings_path,
            binding_metadata_path,
            expected_findings_path,
        ]
    )
    benchmark_date = (started_at or ended_at or datetime.now(tz=timezone.utc).isoformat().replace("+00:00", "Z"))[:10]
    artifacts: dict[str, str] = {
        "scenario_json": str(scenario_path),
        "findings_json": str(findings_path),
        "run_log": str(run_log_path),
        "scenario_validate_txt": str(scenario_validate_path),
    }
    if binding_metadata_path.exists():
        artifacts["binding_metadata_json"] = str(binding_metadata_path)
    if expected_findings_path.exists():
        artifacts["expected_findings_json"] = str(expected_findings_path)

    environment = case_manifest.get("environment", {}).get("acceptance_env")
    if not isinstance(environment, str):
        environment = str(archive_dir)

    run_manifest: dict[str, Any] = {
        "manifest_type": "benchmark_run_manifest",
        "schema_version": MANIFEST_VERSION,
        "run_id": run_id,
        "case_id": case_id,
        "tool_name": "iamscope",
        "git_sha": _infer_git_sha(repo_root),
        "started_at": started_at,
        "ended_at": ended_at,
        "authority": "live_aws",
        "confidence": "high",
        "benchmark_date": benchmark_date,
        "environment": environment,
        "tool_claims": [],
        "context": _parse_run_log_context(run_log_text, case_id),
        "artifact_status": {
            "scenario_validation": _parse_scenario_validation_status(scenario_validate_text),
            "artifact_retention": "complete" if scenario_path.exists() and findings_path.exists() else "incomplete",
        },
        "artifacts": artifacts,
    }
    dump_json(out_path, run_manifest)
    return run_manifest


def main() -> None:
    parser = argparse.ArgumentParser(description="Ingest a live benchmark archive into a Phase 0 run manifest")
    parser.add_argument("--case-id", required=True)
    parser.add_argument("--archive-dir", required=True)
    parser.add_argument("--out", required=True)
    parser.add_argument("--repo-root", default=str(Path.cwd()))
    args = parser.parse_args()
    ingest_archive(args.case_id, Path(args.archive_dir), Path(args.out), Path(args.repo_root))


if __name__ == "__main__":
    main()
