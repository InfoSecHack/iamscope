"""CLI tests for diff-findings."""

from __future__ import annotations

import json
from pathlib import Path

from iamscope.cli import main


def test_diff_findings_command_writes_json(tmp_path: Path) -> None:
    """diff-findings compares by finding_key and writes JSON."""
    baseline = {
        "findings": [
            {
                "finding_id": "a" * 64,
                "finding_key": "k" * 64,
                "verdict": "validated",
                "evidence": {"reasoning_trace": []},
                "required_checks": [],
                "blockers_observed": [],
                "source": {"provider_id": "src"},
                "target": {"provider_id": "dst"},
                "pattern_id": "cross_account_trust",
                "title": "title",
            }
        ],
        "metadata": {"canonical_hash": "h" * 64},
    }
    candidate = {
        "findings": [
            {
                "finding_id": "b" * 64,
                "finding_key": "k" * 64,
                "verdict": "blocked",
                "evidence": {
                    "constraint_refs": ["control"],
                    "reasoning_trace": [{"action": "apply_probe_overlay"}],
                },
                "required_checks": [{"name": "probe_overlay_runtime_truth"}],
                "blockers_observed": [{"kind": "probe_overlay"}],
                "source": {"provider_id": "src"},
                "target": {"provider_id": "dst"},
                "pattern_id": "cross_account_trust",
                "title": "title",
            }
        ],
        "metadata": {"canonical_hash": "i" * 64},
    }
    baseline_path = tmp_path / "baseline.json"
    candidate_path = tmp_path / "candidate.json"
    output_path = tmp_path / "diff.json"
    baseline_path.write_text(json.dumps(baseline), encoding="utf-8")
    candidate_path.write_text(json.dumps(candidate), encoding="utf-8")

    exit_code = main(
        [
            "diff-findings",
            str(baseline_path),
            str(candidate_path),
            "--format",
            "json",
            "--output",
            str(output_path),
        ]
    )

    assert exit_code == 0
    report = json.loads(output_path.read_text(encoding="utf-8"))
    assert report["summary"]["verdict_changes"] == 1
    assert report["summary"]["probe_evidence_additions"] == 1
