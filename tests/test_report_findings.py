"""Tests for the findings-first report renderer (priority 2).

Covers:
- Empty findings (no-findings-emitted message)
- Single validated finding full-detail render
- Single inconclusive finding with UNKNOWN check highlighting
- Single blocked finding collapsed one-liner
- Single precondition_only finding collapsed one-liner
- Mixed verdicts within one pattern_id (correct ordering)
- Multiple pattern_ids (correct grouping)
- Executive summary (counts, reasoners run/skipped)
- generate_report_from_files with findings_path
- generate_report_from_files without findings_path (back-compat graph-only)
- Reasoner skipped surfacing
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from iamscope.report.findings_renderer import render_findings_section
from iamscope.report.generator import generate_report_from_files

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _empty_findings(*, reasoners_run: list[str] | None = None) -> dict[str, Any]:
    return {
        "schema_version": "1.0",
        "source_tool": "iamscope",
        "source_tool_version": "0.2.14",
        "scenario_hash": "abc123",
        "reasoner_versions": {},
        "findings": [],
        "metadata": {
            "findings_count": 0,
            "reasoners_run": reasoners_run or [],
            "reasoners_skipped": {},
            "verdict_breakdown": {
                "validated": 0,
                "blocked": 0,
                "inconclusive": 1 if False else 0,
                "precondition_only": 0,
            },
            "canonical_hash": "hash123",
            "reasoning_timestamp": "2026-04-08T12:00:00Z",
            "reasoning_duration_seconds": 0.0,
        },
    }


def _build_finding(
    *,
    pattern_id: str = "passrole_lambda",
    pattern_title: str = "Lambda PassRole Privilege Chain",
    verdict: str,
    severity: str,
    title: str,
    source_arn: str = "arn:aws:iam::111111\u003111111:user/Alice",
    target_arn: str = "arn:aws:iam::111111\u003111111:role/AdminRole",
    checks: list[dict[str, Any]] | None = None,
    blockers: list[dict[str, Any]] | None = None,
    assumptions: list[dict[str, Any]] | None = None,
    exit_reason: str = "",
    finding_id: str = "f" * 64,
) -> dict[str, Any]:
    return {
        "finding_id": finding_id,
        "pattern_id": pattern_id,
        "pattern_version": "1.0.0",
        "pattern_title": pattern_title,
        "source": {
            "provider": "aws",
            "node_type": "IAMUser",
            "provider_id": source_arn,
        },
        "target": {
            "provider": "aws",
            "node_type": "IAMRole",
            "provider_id": target_arn,
        },
        "verdict": verdict,
        "severity": severity,
        "title": title,
        "required_checks": checks or [],
        "blockers_observed": blockers or [],
        "assumptions": assumptions or [],
        "evidence": {
            "statement_digests": ["d1", "d2", "d3"],
            "statement_sources": {},
            "edge_refs": ["e1", "e2"],
            "constraint_refs": [],
            "edge_constraint_refs": [],
            "node_refs": ["n1", "n2"],
            "condition_context_assumed": [],
            "reasoning_trace": [{"step": i, "action": "test"} for i in range(1, 11)],
        },
        "scenario_hash": "abc123",
        "reasoner_exit_reason": exit_reason,
    }


def _wrap(*findings: dict[str, Any], **metadata_overrides: Any) -> dict[str, Any]:
    """Wrap a list of findings into a full findings.json-shaped dict."""
    d = _empty_findings()
    d["findings"] = list(findings)
    d["metadata"]["findings_count"] = len(findings)
    # Rebuild verdict_breakdown from the actual findings.
    vb = {"validated": 0, "blocked": 0, "inconclusive": 0, "precondition_only": 0}
    for f in findings:
        v = f.get("verdict", "")
        if v in vb:
            vb[v] += 1
    d["metadata"]["verdict_breakdown"] = vb
    d["metadata"]["reasoners_run"] = sorted({f["pattern_id"] for f in findings})
    d["metadata"].update(metadata_overrides)
    return d


# ---------------------------------------------------------------------------
# Empty findings
# ---------------------------------------------------------------------------


class TestEmptyFindings:
    def test_empty_findings_renders_no_findings_message(self) -> None:
        md = render_findings_section(_empty_findings(reasoners_run=["passrole_lambda"]))
        assert "# Findings" in md
        assert "No findings emitted" in md
        assert "`passrole_lambda`" in md

    def test_empty_findings_shows_zero_count_not_missing(self) -> None:
        md = render_findings_section(_empty_findings())
        assert "Total findings:** 0" in md


# ---------------------------------------------------------------------------
# Validated finding
# ---------------------------------------------------------------------------


class TestValidatedFinding:
    def _make(self) -> dict[str, Any]:
        return _wrap(
            _build_finding(
                verdict="validated",
                severity="critical",
                title="Alice can assume AdminRole via Lambda PassRole chain",
                checks=[
                    {
                        "name": "source_has_lambda_create_function",
                        "description": "Source has lambda:CreateFunction",
                        "state": "pass",
                        "evidence_refs": ["e1"],
                        "reason": "explicit permission edge",
                    },
                    {
                        "name": "source_has_passrole_to_target",
                        "description": "Source can PassRole to target",
                        "state": "pass",
                        "evidence_refs": ["e2"],
                        "reason": "specific resource ARN match",
                    },
                ],
                assumptions=[
                    {
                        "kind": "session_policy",
                        "detail": "no session policy restricts the chain",
                    }
                ],
            )
        )

    def test_shows_validated_critical_header(self) -> None:
        md = render_findings_section(self._make())
        assert "VALIDATED / CRITICAL" in md

    def test_shows_source_and_target_arns(self) -> None:
        md = render_findings_section(self._make())
        assert "arn:aws:iam::111111\u003111111:user/Alice" in md
        assert "arn:aws:iam::111111\u003111111:role/AdminRole" in md

    def test_shows_all_checks_as_pass(self) -> None:
        md = render_findings_section(self._make())
        assert "source_has_lambda_create_function" in md
        assert "source_has_passrole_to_target" in md
        # Both should render as PASS.
        assert md.count("**PASS**") == 2

    def test_shows_assumption_block(self) -> None:
        md = render_findings_section(self._make())
        assert "session_policy" in md
        assert "no session policy restricts the chain" in md

    def test_shows_evidence_counts(self) -> None:
        md = render_findings_section(self._make())
        assert "3 statement digests" in md
        assert "2 edge references" in md
        assert "10-step reasoning trace" in md


# ---------------------------------------------------------------------------
# Inconclusive finding — refuses-to-lie surfacing
# ---------------------------------------------------------------------------


class TestInconclusiveFinding:
    def _make(self) -> dict[str, Any]:
        return _wrap(
            _build_finding(
                verdict="inconclusive",
                severity="high",
                title="Inconclusive Lambda PassRole chain",
                checks=[
                    {
                        "name": "source_has_lambda_create_function",
                        "description": "Source has lambda:CreateFunction",
                        "state": "pass",
                        "evidence_refs": ["e1"],
                        "reason": "explicit permission edge",
                    },
                    {
                        "name": "source_has_passrole_to_target",
                        "description": "Source can PassRole to target",
                        "state": "unknown",
                        "evidence_refs": ["e2"],
                        "reason": (
                            "matching iam:PassRole edge has ambiguity flag "
                            "(hyperedge dst); cannot prove specific-resource coverage"
                        ),
                    },
                ],
                exit_reason="check(s) UNKNOWN: source_has_passrole_to_target",
            )
        )

    def test_shows_inconclusive_high_header(self) -> None:
        md = render_findings_section(self._make())
        assert "INCONCLUSIVE / HIGH" in md

    def test_shows_refuses_to_lie_callout(self) -> None:
        md = render_findings_section(self._make())
        assert "refuses to guess" in md
        assert "Why this is inconclusive" in md

    def test_highlights_unknown_check_reason(self) -> None:
        md = render_findings_section(self._make())
        # The UNKNOWN check's reason should appear in the callout.
        assert "hyperedge" in md

    def test_shows_exit_reason(self) -> None:
        md = render_findings_section(self._make())
        assert "check(s) UNKNOWN: source_has_passrole_to_target" in md


# ---------------------------------------------------------------------------
# Blocked finding — collapsed one-liner
# ---------------------------------------------------------------------------


class TestBlockedFinding:
    def _make(self) -> dict[str, Any]:
        return _wrap(
            _build_finding(
                verdict="blocked",
                severity="info",
                title="Blocked Lambda PassRole chain",
                blockers=[
                    {
                        "kind": "scp",
                        "constraint_id": "c_deny_lambda",
                        "edge_id": "e_witness",
                        "reason": "SCP DenyLambdaCreate denies lambda:CreateFunction",
                    }
                ],
            )
        )

    def test_renders_in_collapsed_section(self) -> None:
        md = render_findings_section(self._make())
        assert "### Collapsed findings" in md

    def test_shows_one_line_summary(self) -> None:
        md = render_findings_section(self._make())
        assert "**BLOCKED**" in md
        assert "scp:" in md
        assert "DenyLambdaCreate" in md

    def test_does_not_render_full_checks_table(self) -> None:
        md = render_findings_section(self._make())
        # The collapsed form should NOT include the "Required checks:" label.
        assert "Required checks:" not in md


# ---------------------------------------------------------------------------
# Precondition-only finding
# ---------------------------------------------------------------------------


class TestPreconditionOnlyFinding:
    def test_renders_as_collapsed_one_liner(self) -> None:
        d = _wrap(
            _build_finding(
                verdict="precondition_only",
                severity="medium",
                title="Precondition-only chain",
                blockers=[
                    {
                        "kind": "passed_to_service",
                        "constraint_id": None,
                        "edge_id": "e1",
                        "reason": "iam:PassedToService scoped to ec2.amazonaws.com (not Lambda)",
                    }
                ],
            )
        )
        md = render_findings_section(d)
        assert "### Collapsed findings" in md
        assert "**PRECONDITION-ONLY**" in md
        assert "ec2.amazonaws.com" in md


# ---------------------------------------------------------------------------
# Mixed verdicts within one pattern_id
# ---------------------------------------------------------------------------


class TestMixedVerdictOrdering:
    def _make_mixed(self) -> dict[str, Any]:
        return _wrap(
            _build_finding(
                verdict="blocked",
                severity="info",
                title="Blocked chain A",
                finding_id="a" * 64,
                blockers=[{"kind": "scp", "constraint_id": "c1", "edge_id": "e1", "reason": "x"}],
            ),
            _build_finding(
                verdict="validated",
                severity="critical",
                title="Validated chain B",
                finding_id="b" * 64,
            ),
            _build_finding(
                verdict="inconclusive",
                severity="high",
                title="Inconclusive chain C",
                finding_id="c" * 64,
                checks=[
                    {
                        "name": "source_has_passrole_to_target",
                        "description": "",
                        "state": "unknown",
                        "evidence_refs": [],
                        "reason": "hyperedge witness",
                    }
                ],
            ),
            _build_finding(
                verdict="precondition_only",
                severity="medium",
                title="Precondition-only chain D",
                finding_id="d" * 64,
                blockers=[{"kind": "trust_missing", "constraint_id": None, "edge_id": None, "reason": "x"}],
            ),
        )

    def test_validated_appears_before_inconclusive(self) -> None:
        md = render_findings_section(self._make_mixed())
        validated_pos = md.find("Validated chain B")
        inconclusive_pos = md.find("Inconclusive chain C")
        assert validated_pos < inconclusive_pos
        assert validated_pos > 0 and inconclusive_pos > 0

    def test_inconclusive_appears_before_collapsed_section(self) -> None:
        md = render_findings_section(self._make_mixed())
        inconclusive_pos = md.find("Inconclusive chain C")
        collapsed_pos = md.find("### Collapsed findings")
        assert inconclusive_pos < collapsed_pos

    def test_collapsed_section_contains_both_blocked_and_precondition(self) -> None:
        md = render_findings_section(self._make_mixed())
        collapsed_start = md.find("### Collapsed findings")
        assert collapsed_start > 0
        collapsed_region = md[collapsed_start:]
        assert "BLOCKED" in collapsed_region
        assert "PRECONDITION-ONLY" in collapsed_region


# ---------------------------------------------------------------------------
# Multiple pattern_ids
# ---------------------------------------------------------------------------


class TestMultiplePatterns:
    def _make_multi(self) -> dict[str, Any]:
        return _wrap(
            _build_finding(
                pattern_id="cross_account_trust",
                pattern_title="Cross-account trust without strong constraints",
                verdict="validated",
                severity="critical",
                title="Cross-account A",
                finding_id="a" * 64,
            ),
            _build_finding(
                pattern_id="passrole_lambda",
                pattern_title="Lambda PassRole Privilege Chain",
                verdict="validated",
                severity="critical",
                title="PassRole B",
                finding_id="b" * 64,
            ),
        )

    def test_both_pattern_headers_rendered(self) -> None:
        md = render_findings_section(self._make_multi())
        assert "## Cross-account trust without strong constraints" in md
        assert "## Lambda PassRole Privilege Chain" in md

    def test_patterns_sorted_alphabetically_by_id(self) -> None:
        md = render_findings_section(self._make_multi())
        # cross_account_trust sorts before passrole_lambda alphabetically.
        ca_pos = md.find("Cross-account trust without strong constraints")
        pl_pos = md.find("Lambda PassRole Privilege Chain")
        assert ca_pos < pl_pos


# ---------------------------------------------------------------------------
# Executive summary
# ---------------------------------------------------------------------------


class TestExecutiveSummary:
    def test_shows_total_count(self) -> None:
        d = _wrap(
            _build_finding(verdict="validated", severity="critical", title="X"),
            _build_finding(verdict="inconclusive", severity="high", title="Y"),
        )
        md = render_findings_section(d)
        assert "Total findings:** 2" in md

    def test_shows_verdict_breakdown_table(self) -> None:
        d = _wrap(
            _build_finding(verdict="validated", severity="critical", title="X"),
            _build_finding(verdict="inconclusive", severity="high", title="Y"),
        )
        md = render_findings_section(d)
        assert "| **validated** | 1 |" in md
        assert "| **inconclusive** | 1 |" in md
        assert "| **blocked** | 0 |" in md

    def test_reasoners_skipped_surfaced_prominently(self) -> None:
        d = _empty_findings(reasoners_run=["cross_account_trust"])
        d["metadata"]["reasoners_skipped"] = {
            "passrole_lambda": "edge_budget_exhausted",
        }
        md = render_findings_section(d)
        assert "Reasoners SKIPPED" in md
        assert "gaps in coverage" in md.lower()
        assert "edge_budget_exhausted" in md

    def test_scenario_hash_surfaced(self) -> None:
        d = _wrap(_build_finding(verdict="validated", severity="high", title="X"))
        d["scenario_hash"] = "c0ffee" * 10
        md = render_findings_section(d)
        assert "c0ffeec0ffee" in md


# ---------------------------------------------------------------------------
# generate_report_from_files integration
# ---------------------------------------------------------------------------


class TestGenerateReportFromFilesIntegration:
    def _write_scenario(self, tmp_path: Path) -> Path:
        scenario = {
            "nodes": [
                {"node_id": "n1", "node_type": "IAMRole"},
                {"node_id": "n2", "node_type": "IAMUser"},
            ],
            "edges": [],
            "constraints": [],
            "edge_constraints": [],
            "metadata": {
                "org_id": "o-test",
                "canonical_hash": "abc123",
                "accounts_collected": 1,
            },
        }
        p = tmp_path / "scenario.json"
        p.write_text(json.dumps(scenario))
        return p

    def _write_findings(self, tmp_path: Path) -> Path:
        findings = _wrap(
            _build_finding(
                verdict="validated",
                severity="critical",
                title="Alice can assume AdminRole",
            )
        )
        p = tmp_path / "findings.json"
        p.write_text(json.dumps(findings))
        return p

    def test_report_with_findings_prepends_findings_section(self, tmp_path: Path) -> None:
        scenario_path = self._write_scenario(tmp_path)
        findings_path = self._write_findings(tmp_path)
        md = generate_report_from_files(
            scenario_path=str(scenario_path),
            findings_path=str(findings_path),
        )
        # Findings section leads.
        findings_pos = md.find("# Findings")
        assert findings_pos >= 0, "# Findings header missing from report"
        # Graph section still present (via the separator).
        assert "---" in md
        assert "Alice can assume AdminRole" in md

    def test_report_without_findings_is_graph_only(self, tmp_path: Path) -> None:
        scenario_path = self._write_scenario(tmp_path)
        md = generate_report_from_files(scenario_path=str(scenario_path))
        # No Findings header.
        assert "# Findings" not in md
        # Graph content should still render.
        assert "IAMScope" in md or "Report" in md or "o-test" in md


# ---------------------------------------------------------------------------
# Regression: back-compat signature without findings_path
# ---------------------------------------------------------------------------


class TestBackCompat:
    def test_generate_report_from_files_accepts_old_signature(self, tmp_path: Path) -> None:
        """Calling generate_report_from_files without findings_path must
        still work — the old graph-only call sites depend on it."""
        scenario = {
            "nodes": [],
            "edges": [],
            "constraints": [],
            "edge_constraints": [],
            "metadata": {"org_id": "o-test", "canonical_hash": "x"},
        }
        p = tmp_path / "scenario.json"
        p.write_text(json.dumps(scenario))
        # Call as old code would: without the new kwarg.
        md = generate_report_from_files(scenario_path=str(p))
        assert isinstance(md, str)
        assert len(md) > 0
