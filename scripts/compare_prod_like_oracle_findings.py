#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import re
import sys
from collections import Counter
from dataclasses import dataclass
from pathlib import Path
from typing import Any


SANDBOX_PREFIX = "iamscope-prodlike-v1-"
ORACLE_I001_BOUNDARY_TRIAGE_NOTE = (
    "emitted blocked due complete-confidence boundary evidence; likely oracle/fixture expectation conflict, "
    "not automatically an IAMScope false positive"
)
UNCERTAINTY_PROBE_EXTRA_TRIAGE_NOTE = (
    "extra blocked path induced by uncertainty-probe boundary/policy shape; "
    "not part of deterministic oracle mapping"
)

NON_CLAIMS = [
    "not broad IAMScope correctness",
    "not production readiness",
    "not full oracle success",
    "not production AWS",
    "not exploitability proof",
    "not downstream authorization proof",
    "not Lambda invocation behavior",
    "not generic Deny correctness",
    "no composite benchmark score",
    "no pass/fail benchmark label",
]

ORACLE_ROW_MAPPINGS = {
    "oracle-v-001": {
        "pattern_id": "passrole_lambda",
        "source_name": "iamscope-prodlike-v1-ci-deployer",
        "target_name": "iamscope-prodlike-v1-lambda-exec-scoped",
        "expected_verdict": "validated",
    },
    "oracle-v-002": {
        "pattern_id": "passrole_ecs",
        "source_name": "iamscope-prodlike-v1-ecs-deployer",
        "target_name": "iamscope-prodlike-v1-ecs-task-scoped",
        "expected_verdict": "validated",
    },
    "oracle-v-006": {
        "pattern_id": "passrole_lambda",
        "source_name": "iamscope-prodlike-v1-ci-deployer",
        "target_name": "iamscope-prodlike-v1-service-mediated-target",
        "expected_verdict": "validated",
    },
    "oracle-b-001": {
        "pattern_id": "passrole_lambda",
        "source_name": "iamscope-prodlike-v1-boundary-probe",
        "target_name": "iamscope-prodlike-v1-lambda-exec-boundary",
        "expected_verdict": "blocked",
    },
    "oracle-b-005": {
        "pattern_id": "passrole_lambda",
        "source_name": "iamscope-prodlike-v1-deny-probe",
        "target_name": "iamscope-prodlike-v1-service-mediated-target",
        "expected_verdict": "blocked",
    },
    "oracle-i-001": {
        "pattern_id": "passrole_lambda",
        "source_name": "iamscope-prodlike-v1-uncertainty-probe",
        "target_name": "iamscope-prodlike-v1-lambda-exec-scoped",
        "expected_verdict": "inconclusive",
    },
}

NOT_CURRENTLY_LIVE_COMPARABLE_ROWS = {
    "oracle-v-003",
    "oracle-v-004",
    "oracle-v-005",
    "oracle-b-002",
    "oracle-b-003",
    "oracle-b-004",
    "oracle-p-001",
    "oracle-p-002",
    "oracle-p-003",
    "oracle-p-004",
    "oracle-i-002",
    "oracle-i-003",
    "oracle-i-004",
    "oracle-i-005",
}


@dataclass(frozen=True)
class FindingView:
    finding_id: str
    pattern_id: str
    verdict: str
    source_name: str
    target_name: str
    source_has_sandbox_prefix: bool
    target_has_sandbox_prefix: bool

    @property
    def mapping_key(self) -> tuple[str, str, str]:
        return (self.pattern_id, self.source_name, self.target_name)


def _repo_root() -> Path:
    return Path(__file__).resolve().parents[1]


def _load_json(path: Path) -> Any:
    with path.open("r", encoding="utf-8") as handle:
        return json.load(handle)


def _oracle_rows(payload: Any) -> list[dict[str, Any]]:
    if isinstance(payload, dict):
        rows = payload.get("oracle_rows")
    else:
        rows = payload
    if not isinstance(rows, list):
        raise ValueError("oracle input must contain an oracle_rows list")
    return rows


def _findings(payload: Any) -> list[dict[str, Any]]:
    if isinstance(payload, dict):
        findings = payload.get("findings")
    else:
        findings = payload
    if not isinstance(findings, list):
        raise ValueError("findings input must contain a findings list")
    return findings


def _resource_name(provider_id: Any) -> str:
    value = str(provider_id or "")
    if not value:
        return ""
    for marker in (":user/", ":role/", ":policy/"):
        if marker in value:
            return value.split(marker, 1)[1].split("/")[-1]
    return value.rstrip("/").split("/")[-1]


def _finding_view(finding: dict[str, Any]) -> FindingView:
    source_name = _resource_name(finding.get("source", {}).get("provider_id"))
    target_name = _resource_name(finding.get("target", {}).get("provider_id"))
    return FindingView(
        finding_id=str(finding.get("finding_id") or ""),
        pattern_id=str(finding.get("pattern_id") or ""),
        verdict=str(finding.get("verdict") or ""),
        source_name=source_name,
        target_name=target_name,
        source_has_sandbox_prefix=SANDBOX_PREFIX in source_name,
        target_has_sandbox_prefix=SANDBOX_PREFIX in target_name,
    )


def _refuse_repo_output(out_dir: Path) -> None:
    repo = _repo_root().resolve()
    resolved = out_dir.resolve()
    if resolved == repo or repo in resolved.parents:
        raise SystemExit(f"refusing to write comparison output inside repository tree: {out_dir}")


def _raw_identifier_hits(payload: Any) -> list[str]:
    text = json.dumps(payload, sort_keys=True)
    hits = set(re.findall(r"\b(?!000000000000\b)[0-9]{12}\b", text))
    hits.update(re.findall(r"arn:aws:iam::(?!000000000000\b)[0-9]{12}[^\"\\s]*", text))
    return sorted(hits)


def _mapping_key(spec: dict[str, str]) -> tuple[str, str, str]:
    return (spec["pattern_id"], spec["source_name"], spec["target_name"])


def _oracle_mismatch_triage_note(row_id: str, expected_verdict: str, emitted_verdicts: list[str]) -> str | None:
    if row_id == "oracle-i-001" and expected_verdict == "inconclusive" and "blocked" in emitted_verdicts:
        return ORACLE_I001_BOUNDARY_TRIAGE_NOTE
    return None


def _unmapped_sandbox_extra_triage_note(finding: FindingView) -> str | None:
    if finding.source_name == f"{SANDBOX_PREFIX}uncertainty-probe" and finding.verdict == "blocked":
        return UNCERTAINTY_PROBE_EXTRA_TRIAGE_NOTE
    return None


def compare(oracle_payload: Any, findings_payload: Any) -> dict[str, Any]:
    oracle_rows = _oracle_rows(oracle_payload)
    raw_findings = _findings(findings_payload)
    finding_views = [_finding_view(finding) for finding in raw_findings]

    mapped_findings: dict[tuple[str, str, str], list[FindingView]] = {}
    for finding in finding_views:
        mapped_findings.setdefault(finding.mapping_key, []).append(finding)

    rows: list[dict[str, Any]] = []
    supported_mapping_keys = {_mapping_key(spec) for spec in ORACLE_ROW_MAPPINGS.values()}
    consumed_keys: set[tuple[str, str, str]] = set()
    unsupported_static_only_rows: list[dict[str, str]] = []

    for oracle_row in oracle_rows:
        row_id = str(oracle_row["oracle_row_id"])
        expected_category = str(oracle_row["expected_category"])
        base = {
            "oracle_row_id": row_id,
            "expected_category": expected_category,
            "pattern": str(oracle_row.get("pattern", "")),
        }

        if expected_category == "unsupported":
            row = {
                **base,
                "comparison_category": "unsupported_static_only",
                "emitted_verdict": None,
                "source_name": None,
                "target_name": None,
                "reason": "unsupported oracle row remains static-only and is not counted as a false positive or false negative",
            }
            unsupported_static_only_rows.append({"oracle_row_id": row_id, "expected_category": expected_category})
            rows.append(row)
            continue

        mapping = ORACLE_ROW_MAPPINGS.get(row_id)
        if mapping is None:
            category = (
                "not_currently_live_comparable"
                if row_id in NOT_CURRENTLY_LIVE_COMPARABLE_ROWS
                else "oracle_missing"
            )
            rows.append(
                {
                    **base,
                    "comparison_category": category,
                    "emitted_verdict": None,
                    "source_name": None,
                    "target_name": None,
                    "reason": (
                        "current reasoner/output set did not emit a comparable finding for this row"
                        if category == "not_currently_live_comparable"
                        else "no deterministic v1 mapping or emitted finding was available"
                    ),
                }
            )
            continue

        key = _mapping_key(mapping)
        candidates = mapped_findings.get(key, [])
        if not candidates:
            rows.append(
                {
                    **base,
                    "comparison_category": "oracle_missing",
                    "expected_verdict": mapping["expected_verdict"],
                    "emitted_verdict": None,
                    "pattern_id": mapping["pattern_id"],
                    "source_name": mapping["source_name"],
                    "target_name": mapping["target_name"],
                    "reason": "no emitted sandbox-source finding matched the deterministic v1 mapping",
                }
            )
            continue

        consumed_keys.add(key)
        emitted_verdicts = sorted({candidate.verdict for candidate in candidates})
        expected_verdict = mapping["expected_verdict"]
        category = "oracle_match" if expected_verdict in emitted_verdicts else "oracle_mismatch"
        row = {
            **base,
            "comparison_category": category,
            "expected_verdict": expected_verdict,
            "emitted_verdict": emitted_verdicts[0] if len(emitted_verdicts) == 1 else emitted_verdicts,
            "pattern_id": mapping["pattern_id"],
            "source_name": mapping["source_name"],
            "target_name": mapping["target_name"],
            "finding_ids": [candidate.finding_id for candidate in candidates],
            "reason": (
                "emitted verdict matched expected oracle category"
                if category == "oracle_match"
                else "emitted verdict differed from expected oracle category"
            ),
        }
        triage_note = _oracle_mismatch_triage_note(row_id, expected_verdict, emitted_verdicts)
        if triage_note is not None:
            row["triage_note"] = triage_note
        rows.append(row)

    environmental_extras: list[dict[str, Any]] = []
    unmapped_sandbox_extras: list[dict[str, Any]] = []
    for finding in finding_views:
        if finding.mapping_key in consumed_keys:
            continue
        if finding.target_has_sandbox_prefix and not finding.source_has_sandbox_prefix:
            environmental_extras.append(
                {
                    "comparison_category": "environmental_extra",
                    "extra_type": "non_sandbox_source_targets_sandbox_role",
                    "finding_id": finding.finding_id,
                    "pattern_id": finding.pattern_id,
                    "verdict": finding.verdict,
                    "source_name": finding.source_name,
                    "target_name": finding.target_name,
                }
            )
        elif finding.source_has_sandbox_prefix and finding.mapping_key not in supported_mapping_keys:
            extra = {
                "comparison_category": "unmapped_sandbox_extra",
                "extra_type": "sandbox_source_has_no_deterministic_oracle_mapping",
                "finding_id": finding.finding_id,
                "pattern_id": finding.pattern_id,
                "verdict": finding.verdict,
                "source_name": finding.source_name,
                "target_name": finding.target_name,
            }
            triage_note = _unmapped_sandbox_extra_triage_note(finding)
            if triage_note is not None:
                extra["triage_note"] = triage_note
            unmapped_sandbox_extras.append(extra)

    comparison_category_counts = Counter(row["comparison_category"] for row in rows)
    comparison_category_counts.update(extra["comparison_category"] for extra in environmental_extras)
    comparison_category_counts.update(extra["comparison_category"] for extra in unmapped_sandbox_extras)

    result = {
        "metadata": {
            "comparison_mode": "local_prod_like_oracle_comparison",
            "sandbox_prefix": SANDBOX_PREFIX,
            "oracle_mapping_policy": "deterministic_explicit_v1_mapping",
            "local_only": True,
            "live_aws_used": False,
            "terraform_run_by_comparator": False,
            "score_policy": "no composite benchmark score",
            "benchmark_label_policy": "no pass/fail benchmark label",
            "raw_account_ids_written": False,
            "raw_iam_arns_written": False,
        },
        "oracle_row_count": len(oracle_rows),
        "emitted_finding_count": len(finding_views),
        "sandbox_source_finding_count": sum(1 for finding in finding_views if finding.source_has_sandbox_prefix),
        "environmental_extra_count": len(environmental_extras),
        "unmapped_sandbox_extra_count": len(unmapped_sandbox_extras),
        "comparison_category_counts": dict(sorted(comparison_category_counts.items())),
        "verdict_counts": dict(sorted(Counter(finding.verdict for finding in finding_views).items())),
        "pattern_counts": dict(sorted(Counter(finding.pattern_id for finding in finding_views).items())),
        "rows": rows,
        "environmental_extras": environmental_extras,
        "unmapped_sandbox_extras": unmapped_sandbox_extras,
        "unsupported_static_only_rows": unsupported_static_only_rows,
        "non_claims": NON_CLAIMS,
    }

    hits = _raw_identifier_hits(result)
    if hits:
        raise ValueError(f"sanitized comparison output still contains raw identifiers: {hits}")
    return result


def _section_list(title: str, items: list[str]) -> list[str]:
    lines = [f"## {title}", ""]
    if items:
        lines.extend(f"- {item}" for item in items)
    else:
        lines.append("- none")
    lines.append("")
    return lines


def render_summary(result: dict[str, Any]) -> str:
    lines = [
        "# Prod-Like Oracle Comparison Summary",
        "",
        "This local report compares sanitized IAMScope findings to the frozen prod-like oracle using deterministic v1 mappings.",
        "",
        "## Counts",
        "",
        f"- oracle row count: {result['oracle_row_count']}",
        f"- emitted finding count: {result['emitted_finding_count']}",
        f"- sandbox-source finding count: {result['sandbox_source_finding_count']}",
        f"- environmental extra finding count: {result['environmental_extra_count']}",
        f"- unmapped sandbox extra finding count: {result['unmapped_sandbox_extra_count']}",
        "",
        "## Comparison Category Counts",
        "",
    ]
    lines.extend(f"- {key}: {value}" for key, value in result["comparison_category_counts"].items())
    lines.extend(["", "## Emitted Verdict Counts", ""])
    lines.extend(f"- {key}: {value}" for key, value in result["verdict_counts"].items())
    lines.extend(["", "## Emitted Pattern Counts", ""])
    lines.extend(f"- {key}: {value}" for key, value in result["pattern_counts"].items())
    lines.append("")

    rows = result["rows"]
    lines.extend(
        _section_list(
            "Oracle Matches",
            [
                f"{row['oracle_row_id']}: {row.get('pattern_id')} {row.get('source_name')} -> {row.get('target_name')} ({row.get('emitted_verdict')})"
                for row in rows
                if row["comparison_category"] == "oracle_match"
            ],
        )
    )
    lines.extend(
        _section_list(
            "Oracle Mismatches",
            [
                f"{row['oracle_row_id']}: expected {row.get('expected_verdict')}, emitted {row.get('emitted_verdict')} for {row.get('source_name')} -> {row.get('target_name')}"
                + (f"; triage: {row['triage_note']}" if row.get("triage_note") else "")
                for row in rows
                if row["comparison_category"] == "oracle_mismatch"
            ],
        )
    )
    lines.extend(
        _section_list(
            "Oracle Missing Rows",
            [
                f"{row['oracle_row_id']}: {row['expected_category']} ({row['reason']})"
                for row in rows
                if row["comparison_category"] == "oracle_missing"
            ],
        )
    )
    lines.extend(
        _section_list(
            "Not Currently Live Comparable Rows",
            [
                f"{row['oracle_row_id']}: {row['expected_category']} ({row['reason']})"
                for row in rows
                if row["comparison_category"] == "not_currently_live_comparable"
            ],
        )
    )
    lines.extend(
        _section_list(
            "Environmental Extras",
            [
                f"{extra['finding_id']}: {extra['extra_type']} {extra['pattern_id']} {extra['verdict']} {extra['source_name']} -> {extra['target_name']}"
                for extra in result["environmental_extras"]
            ],
        )
    )
    lines.extend(
        _section_list(
            "Unmapped Sandbox Extras",
            [
                f"{extra['finding_id']}: {extra['extra_type']} {extra['pattern_id']} {extra['verdict']} {extra['source_name']} -> {extra['target_name']}"
                + (f"; triage: {extra['triage_note']}" if extra.get("triage_note") else "")
                for extra in result["unmapped_sandbox_extras"]
            ],
        )
    )
    lines.extend(
        _section_list(
            "Unsupported Static-Only Rows",
            [
                f"{row['oracle_row_id']}: {row['expected_category']}"
                for row in result["unsupported_static_only_rows"]
            ],
        )
    )
    lines.extend(_section_list("Non-Claims", list(result["non_claims"])))
    return "\n".join(lines)


def write_outputs(result: dict[str, Any], out_dir: Path) -> None:
    _refuse_repo_output(out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)
    comparison_json = out_dir / "comparison.json"
    summary_md = out_dir / "comparison-summary.md"
    comparison_json.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    summary_md.write_text(render_summary(result), encoding="utf-8")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Compare prod-like IAMScope findings to the frozen oracle.")
    parser.add_argument("--oracle", required=True, type=Path)
    parser.add_argument("--findings", required=True, type=Path)
    parser.add_argument("--out", required=True, type=Path)
    args = parser.parse_args(argv)

    oracle_payload = _load_json(args.oracle)
    findings_payload = _load_json(args.findings)
    result = compare(oracle_payload, findings_payload)
    write_outputs(result, args.out)
    print(f"wrote {args.out / 'comparison-summary.md'}")
    print(f"wrote {args.out / 'comparison.json'}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
