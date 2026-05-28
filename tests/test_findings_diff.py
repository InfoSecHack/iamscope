"""Tests for findings.json semantic diffs keyed by finding_key."""

from __future__ import annotations

import json

import pytest

from iamscope.findings_diff import diff_findings, format_findings_diff


def _finding(
    key: str,
    *,
    finding_id: str = "f" * 64,
    verdict: str = "validated",
    probe: bool = False,
    edge_refs: list[str] | None = None,
    trace_reason: str = "base",
) -> dict:
    trace = [
        {
            "action": "emit_verdict",
            "inputs": [verdict],
            "reason": trace_reason,
            "result": verdict.upper(),
            "step": 1,
        }
    ]
    checks = [
        {
            "description": "base check",
            "evidence_refs": edge_refs or ["edge-a"],
            "name": "base_check",
            "reason": "base",
            "state": "pass" if verdict == "validated" else "fail",
        }
    ]
    blockers = []
    if probe:
        checks.append(
            {
                "description": "probe check",
                "evidence_refs": edge_refs or ["edge-a"],
                "name": "probe_overlay_runtime_truth",
                "reason": "live probe denied",
                "state": "fail",
            }
        )
        blockers.append(
            {
                "constraint_id": None,
                "edge_id": "edge-a",
                "kind": "probe_overlay",
                "reason": "live probe denied",
            }
        )
        trace.append(
            {
                "action": "apply_probe_overlay",
                "inputs": ["edge-a", "probe-1", "probed_correlated_denied"],
                "reason": "probe_id=probe-1",
                "result": "FAIL",
                "step": 2,
            }
        )
    return {
        "assumptions": [],
        "blockers_observed": blockers,
        "evidence": {
            "condition_context_assumed": [],
            "constraint_refs": ["control-a"] if probe else [],
            "edge_constraint_refs": [],
            "edge_refs": edge_refs or ["edge-a"],
            "node_refs": ["node-a"],
            "reasoning_trace": trace,
            "statement_digests": ["digest-a"],
            "statement_sources": {"digest-a": ["policy", 0, "stmt"]},
        },
        "finding_id": finding_id,
        "finding_key": key,
        "pattern_id": "cross_account_trust",
        "pattern_title": "Cross-account trust",
        "pattern_version": "1.0.0",
        "reasoner_exit_reason": "reason",
        "required_checks": checks,
        "scenario_hash": "s" * 64,
        "severity": "high",
        "source": {"provider_id": "arn:aws:iam::111:role/Source"},
        "target": {"provider_id": "arn:aws:iam::222:role/Target"},
        "title": "test finding",
        "verdict": verdict,
    }


def _doc(*findings: dict) -> dict:
    return {
        "findings": list(findings),
        "metadata": {"canonical_hash": "h" * 64},
    }


def test_identical_files_have_zero_semantic_changes() -> None:
    before = _doc(_finding("key-a"))
    after = json.loads(json.dumps(before))

    result = diff_findings(before, after)

    assert result.summary["changed_semantic_findings"] == 0
    assert result.changes == ()
    assert "No semantic finding changes" in format_findings_diff(result)


def test_same_key_changed_verdict_is_reported() -> None:
    before = _doc(_finding("key-a", finding_id="a" * 64, verdict="validated"))
    after = _doc(_finding("key-a", finding_id="b" * 64, verdict="blocked"))

    result = diff_findings(before, after)

    assert result.summary["changed_semantic_findings"] == 1
    assert result.summary["verdict_changes"] == 1
    change = result.changes[0]
    assert change.finding_key == "key-a"
    assert change.baseline_verdict == "validated"
    assert change.candidate_verdict == "blocked"
    assert "verdict_changed" in change.change_types


def test_same_key_added_probe_trace_and_evidence_is_reported() -> None:
    before = _doc(_finding("key-a", finding_id="a" * 64, verdict="validated"))
    after = _doc(
        _finding(
            "key-a",
            finding_id="b" * 64,
            verdict="blocked",
            probe=True,
        )
    )

    result = diff_findings(before, after)

    change = result.changes[0]
    assert result.summary["probe_evidence_additions"] == 1
    assert change.probe_evidence_added is True
    assert "probe_evidence_added" in change.change_types
    assert "reasoning_trace_changed" in change.change_types
    assert "evidence_changed" in change.change_types


def test_added_and_removed_findings_are_reported() -> None:
    before = _doc(_finding("key-removed"))
    after = _doc(_finding("key-added"))

    result = diff_findings(before, after)

    assert result.summary["added_semantic_findings"] == 1
    assert result.summary["removed_semantic_findings"] == 1
    assert result.summary["changed_semantic_findings"] == 2
    change_types = {change.change_types[0] for change in result.changes}
    assert change_types == {"added_semantic_finding", "removed_semantic_finding"}


def test_missing_finding_key_is_rejected() -> None:
    before = _doc(_finding("key-a"))
    after_finding = _finding("key-a")
    after_finding.pop("finding_key")
    after = _doc(after_finding)

    with pytest.raises(ValueError, match="missing finding_key"):
        diff_findings(before, after)
