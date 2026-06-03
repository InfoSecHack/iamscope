"""Tests for the `iamscope why` finding introspection subcommand.

Covers:
- `locate_finding` filtering (prefix, exact, substring, combined, zero/multi)
- `explain_finding` rendering for all 4 verdict types
- UNKNOWN check callout (refuses-to-lie signal)
- Blocker rendering for PRECONDITION_ONLY and BLOCKED verdicts
- Verbose trace rendering
- Color enabled vs disabled
- Disambiguation list formatting
- CLI handler via main() end-to-end with a temp findings.json
"""

from __future__ import annotations

import json
import tempfile
from pathlib import Path

import pytest

from iamscope.why import (
    _ambiguity_hint,
    _Colors,
    explain_finding,
    format_disambiguation_list,
    locate_finding,
    should_use_color,
)

# ---------------------------------------------------------------------------
# Fixture data
# ---------------------------------------------------------------------------


def _validated_finding() -> dict:
    return {
        "finding_id": "abc123def456" + "0" * 52,
        "pattern_id": "secrets_blast_radius",
        "pattern_version": "1.0.0",
        "verdict": "validated",
        "severity": "high",
        "title": "Validated secret read: Alice can call GetSecretValue",
        "source": {
            "provider": "aws",
            "node_type": "IAMUser",
            "provider_id": "arn:aws:iam::111111\u003111111:user/Alice",
            "region": "aws-global",
        },
        "target": {
            "provider": "aws",
            "node_type": "SecretsManagerSecret",
            "provider_id": "arn:aws:secretsmanager:us-east-1:111111\u003111111:secret:prod/db",
            "region": "us-east-1",
        },
        "required_checks": [
            {
                "name": "principal_has_get_secret_value_permission",
                "description": "",
                "state": "pass",
                "evidence_refs": ["edge-1"],
                "reason": "permission edge witnessed",
            },
            {
                "name": "permission_edge_targets_clean_witness",
                "description": "",
                "state": "pass",
                "evidence_refs": ["edge-1"],
                "reason": "clean witness edge",
            },
            {
                "name": "no_scp_blocks_get_secret_value",
                "description": "",
                "state": "pass",
                "evidence_refs": ["edge-1"],
                "reason": "no SCP bindings observed",
            },
            {
                "name": "no_boundary_blocks_get_secret_value",
                "description": "",
                "state": "pass",
                "evidence_refs": ["edge-1"],
                "reason": "no permission boundary bindings observed",
            },
            {
                "name": "kms_key_policy_allows_decrypt_for_principal",
                "description": "",
                "state": "pass",
                "evidence_refs": ["edge-1"],
                "reason": "secret uses AWS-managed default KMS key",
            },
        ],
        "blockers_observed": [],
        "assumptions": [],
        "evidence": {
            "statement_digests": ["d" * 64],
            "statement_sources": {},
            "edge_refs": ["edge-1"],
            "constraint_refs": [],
            "edge_constraint_refs": [],
            "node_refs": ["node-1", "node-2"],
            "condition_context_assumed": [],
            "reasoning_trace": [
                {
                    "step": 1,
                    "action": "check_principal_has_get_secret_value_permission",
                    "inputs": ("arn:aws:iam::111111\u003111111:user/Alice",),
                    "result": "PASS",
                    "reason": "permission edge witnessed",
                },
                {
                    "step": 2,
                    "action": "check_permission_edge_targets_clean_witness",
                    "inputs": ("edge-1",),
                    "result": "PASS",
                    "reason": "clean",
                },
            ],
            "bundle_digest": "b" * 64,
        },
        "scenario_hash": "s" * 64,
        "reasoner_exit_reason": "all checks PASS; principal is non-admin",
    }


def _inconclusive_finding() -> dict:
    f = _validated_finding()
    f["finding_id"] = "incabc" + "1" * 58
    f["verdict"] = "inconclusive"
    f["severity"] = "medium"
    f["title"] = "Inconclusive secret read: Alice, wildcard resource"
    f["required_checks"][1] = {
        "name": "permission_edge_targets_clean_witness",
        "description": "",
        "state": "unknown",
        "evidence_refs": ["edge-1"],
        "reason": "edge traverses wildcard/hyperedge ambiguity",
    }
    f["reasoner_exit_reason"] = "permission edge has wildcard resource or hyperedge dst"
    return f


def _precondition_finding() -> dict:
    f = _validated_finding()
    f["finding_id"] = "prec" + "2" * 60
    f["verdict"] = "precondition_only"
    f["severity"] = "medium"
    f["title"] = "Precondition-only: KMS blocks Alice"
    f["required_checks"][4] = {
        "name": "kms_key_policy_allows_decrypt_for_principal",
        "description": "",
        "state": "fail",
        "evidence_refs": ["edge-1"],
        "reason": "no KMS policy Allow statement covers principal",
    }
    f["blockers_observed"] = [
        {
            "kind": "kms_key_policy",
            "constraint_id": "kms-node-1",
            "edge_id": "edge-1",
            "reason": "no KMS policy Allow statement covers principal",
        },
    ]
    f["reasoner_exit_reason"] = "KMS key policy does not allow kms:Decrypt for principal"
    return f


def _blocked_finding() -> dict:
    f = _validated_finding()
    f["finding_id"] = "blk" + "3" * 61
    f["verdict"] = "blocked"
    f["severity"] = "info"
    f["title"] = "Blocked secret read: SCP denies"
    f["required_checks"][2] = {
        "name": "no_scp_blocks_get_secret_value",
        "description": "",
        "state": "fail",
        "evidence_refs": ["scp-constraint-1"],
        "reason": "SCP p-deny-getsecret blocks (complete)",
    }
    f["blockers_observed"] = [
        {
            "kind": "scp",
            "constraint_id": "scp-constraint-1",
            "edge_id": "edge-1",
            "reason": "SCP denies GetSecretValue",
        },
    ]
    f["reasoner_exit_reason"] = "SCP blocks secretsmanager:GetSecretValue"
    return f


# ---------------------------------------------------------------------------
# _Colors
# ---------------------------------------------------------------------------


class TestColors:
    def test_disabled_returns_plain_text(self) -> None:
        c = _Colors(enabled=False)
        assert c.green("hello") == "hello"
        assert c.red("hello") == "hello"
        assert c.yellow("hello") == "hello"
        assert c.blue("hello") == "hello"
        assert c.dim("hello") == "hello"
        assert c.bold("hello") == "hello"

    def test_enabled_wraps_with_ansi(self) -> None:
        c = _Colors(enabled=True)
        assert c.green("x") == "\033[32mx\033[0m"
        assert c.red("x") == "\033[31mx\033[0m"
        assert c.yellow("x") == "\033[33mx\033[0m"


class TestShouldUseColor:
    def test_explicit_no_color_wins(self) -> None:
        assert not should_use_color(explicit_no_color=True)

    def test_default_follows_tty(self) -> None:
        # In a test environment, stdout is usually not a TTY
        result = should_use_color(explicit_no_color=False)
        assert isinstance(result, bool)


# ---------------------------------------------------------------------------
# locate_finding
# ---------------------------------------------------------------------------


class TestLocateFinding:
    def test_no_filter_returns_error(self) -> None:
        matches, error = locate_finding([_validated_finding()])
        assert matches == []
        assert error is not None
        assert "no filter" in error.lower()

    def test_finding_id_prefix_match(self) -> None:
        findings = [_validated_finding(), _inconclusive_finding()]
        matches, error = locate_finding(findings, finding_id="abc123")
        assert error is None
        assert len(matches) == 1
        assert matches[0]["finding_id"].startswith("abc123")

    def test_finding_id_no_match(self) -> None:
        matches, error = locate_finding(
            [_validated_finding()],
            finding_id="nonexistent",
        )
        assert matches == []
        assert error is not None

    def test_pattern_id_exact_match(self) -> None:
        findings = [
            _validated_finding(),
            {
                "finding_id": "x" * 64,
                "pattern_id": "other_reasoner",
                "source": {"provider_id": "a"},
                "target": {"provider_id": "b"},
                "verdict": "validated",
                "severity": "high",
            },
        ]
        matches, error = locate_finding(
            findings,
            pattern_id="secrets_blast_radius",
        )
        assert error is None
        assert len(matches) == 1
        assert matches[0]["pattern_id"] == "secrets_blast_radius"

    def test_source_substring_match(self) -> None:
        findings = [_validated_finding()]
        matches, error = locate_finding(findings, source_arn="Alice")
        assert error is None
        assert len(matches) == 1

    def test_target_substring_match(self) -> None:
        findings = [_validated_finding()]
        matches, error = locate_finding(findings, target_arn="prod/db")
        assert error is None
        assert len(matches) == 1

    def test_combined_filters_and_semantics(self) -> None:
        """Multiple filters are AND — all must match."""
        findings = [_validated_finding()]
        # source matches but target doesn't → no match
        matches, _ = locate_finding(
            findings,
            source_arn="Alice",
            target_arn="NoMatch",
        )
        assert matches == []
        # both match → match
        matches, _ = locate_finding(
            findings,
            source_arn="Alice",
            target_arn="prod/db",
        )
        assert len(matches) == 1

    def test_multiple_matches_returned(self) -> None:
        """locate_finding returns all matches — caller disambiguates."""
        findings = [_validated_finding(), _inconclusive_finding()]
        matches, error = locate_finding(
            findings,
            pattern_id="secrets_blast_radius",
        )
        assert error is None
        assert len(matches) == 2


# ---------------------------------------------------------------------------
# explain_finding
# ---------------------------------------------------------------------------


class TestExplainFinding:
    def test_validated_includes_verdict_header(self) -> None:
        out = explain_finding(_validated_finding(), use_color=False)
        assert "VALIDATED" in out
        assert "HIGH" in out

    def test_validated_shows_all_pass_checks(self) -> None:
        out = explain_finding(_validated_finding(), use_color=False)
        assert out.count("[✓]") >= 4  # At least 4 PASS checks

    def test_inconclusive_has_refuses_to_lie_callout(self) -> None:
        out = explain_finding(_inconclusive_finding(), use_color=False)
        assert "refuses-to-lie" in out.lower() or "refuses to lie" in out.lower()
        assert "INCONCLUSIVE" in out
        # Should mention the specific UNKNOWN check
        assert "permission_edge_targets_clean_witness" in out

    def test_inconclusive_includes_ambiguity_hint(self) -> None:
        out = explain_finding(_inconclusive_finding(), use_color=False)
        assert "wildcard" in out.lower() or "hyperedge" in out.lower()

    def test_precondition_only_shows_blocker(self) -> None:
        out = explain_finding(_precondition_finding(), use_color=False)
        assert "kms_key_policy" in out
        assert "Blockers observed" in out

    def test_blocked_shows_scp_blocker(self) -> None:
        out = explain_finding(_blocked_finding(), use_color=False)
        assert "BLOCKED" in out
        assert "scp" in out

    def test_verbose_includes_reasoning_trace(self) -> None:
        out = explain_finding(
            _validated_finding(),
            verbose=True,
            use_color=False,
        )
        assert "Reasoning trace" in out
        assert "Step 1" in out
        assert "Step 2" in out

    def test_non_verbose_omits_trace(self) -> None:
        out = explain_finding(
            _validated_finding(),
            verbose=False,
            use_color=False,
        )
        assert "Reasoning trace" not in out

    def test_source_and_target_shown(self) -> None:
        out = explain_finding(_validated_finding(), use_color=False)
        assert "Alice" in out
        assert "prod/db" in out

    def test_verdict_reasoning_shown(self) -> None:
        out = explain_finding(_validated_finding(), use_color=False)
        assert "Verdict reasoning" in out
        assert "all checks PASS" in out

    def test_no_color_output_has_no_ansi_escapes(self) -> None:
        out = explain_finding(_validated_finding(), use_color=False)
        assert "\033[" not in out

    def test_color_output_has_ansi_escapes(self) -> None:
        out = explain_finding(_validated_finding(), use_color=True)
        assert "\033[" in out

    def test_evidence_bundle_counts_shown(self) -> None:
        out = explain_finding(_validated_finding(), use_color=False)
        assert "statement digest" in out
        assert "edge ref" in out
        assert "node ref" in out

    def test_scenario_hash_shown_in_footer(self) -> None:
        out = explain_finding(_validated_finding(), use_color=False)
        assert "scenario_hash" in out


# ---------------------------------------------------------------------------
# _ambiguity_hint
# ---------------------------------------------------------------------------


class TestAmbiguityHint:
    def test_wildcard_hint(self) -> None:
        check = {"reason": "edge traverses wildcard resource"}
        hint = _ambiguity_hint(check)
        assert "wildcard" in hint.lower()

    def test_condition_hint(self) -> None:
        check = {"reason": "matching statement has Condition block"}
        hint = _ambiguity_hint(check)
        assert "condition" in hint.lower()

    def test_partial_hint(self) -> None:
        check = {"reason": "SCP parse_status is partial"}
        hint = _ambiguity_hint(check)
        assert "partial" in hint.lower()

    def test_deny_hint(self) -> None:
        check = {"reason": "KMS policy contains Deny statement"}
        hint = _ambiguity_hint(check)
        assert "deny" in hint.lower()

    def test_unrecognized_returns_raw_reason(self) -> None:
        check = {"reason": "some totally unfamiliar reason"}
        hint = _ambiguity_hint(check)
        assert hint == "some totally unfamiliar reason"


# ---------------------------------------------------------------------------
# format_disambiguation_list
# ---------------------------------------------------------------------------


class TestDisambiguationList:
    def test_shows_count_header(self) -> None:
        findings = [_validated_finding(), _inconclusive_finding()]
        out = format_disambiguation_list(findings, use_color=False)
        assert "2 findings match" in out

    def test_shows_all_matches(self) -> None:
        findings = [_validated_finding(), _inconclusive_finding()]
        out = format_disambiguation_list(findings, use_color=False)
        assert "VALIDATED" in out
        assert "INCONCLUSIVE" in out

    def test_shows_refine_hint(self) -> None:
        findings = [_validated_finding(), _inconclusive_finding()]
        out = format_disambiguation_list(findings, use_color=False)
        assert "--finding-id" in out or "--source" in out


# ---------------------------------------------------------------------------
# CLI integration: end-to-end via main()
# ---------------------------------------------------------------------------


class TestCliIntegration:
    def _write_findings(self, path: Path, findings: list[dict]) -> None:
        """Write a minimal findings.json structure."""
        data = {
            "metadata": {
                "tool_version": "0.2.23",
                "reasoners_run": ["secrets_blast_radius"],
                "verdict_breakdown": {"validated": len(findings)},
                "scenario_hash": "s" * 64,
                "findings_hash": "h" * 64,
            },
            "findings": findings,
        }
        path.write_text(json.dumps(data))

    def test_why_with_finding_id_success(self) -> None:
        from iamscope.cli import main

        with tempfile.TemporaryDirectory() as td:
            path = Path(td) / "findings.json"
            self._write_findings(path, [_validated_finding()])
            rc = main(
                [
                    "why",
                    "--findings",
                    str(path),
                    "--finding-id",
                    "abc123",
                    "--no-color",
                ]
            )
            assert rc == 0

    def test_why_missing_file_returns_1(self) -> None:
        from iamscope.cli import main

        with tempfile.TemporaryDirectory() as td:
            path = Path(td) / "nonexistent.json"
            rc = main(["why", "--findings", str(path), "--finding-id", "x"])
            assert rc == 1

    def test_why_no_match_returns_1(self) -> None:
        from iamscope.cli import main

        with tempfile.TemporaryDirectory() as td:
            path = Path(td) / "findings.json"
            self._write_findings(path, [_validated_finding()])
            rc = main(
                [
                    "why",
                    "--findings",
                    str(path),
                    "--finding-id",
                    "nonexistent",
                    "--no-color",
                ]
            )
            assert rc == 1

    def test_why_multiple_matches_returns_1(self) -> None:
        """Multiple matches should disambiguate and return 1."""
        from iamscope.cli import main

        with tempfile.TemporaryDirectory() as td:
            path = Path(td) / "findings.json"
            self._write_findings(
                path,
                [_validated_finding(), _inconclusive_finding()],
            )
            rc = main(
                [
                    "why",
                    "--findings",
                    str(path),
                    "--pattern",
                    "secrets_blast_radius",
                    "--no-color",
                ]
            )
            assert rc == 1

    def test_why_combined_filters_narrows(self) -> None:
        """Combining pattern + source should narrow to single match."""
        from iamscope.cli import main

        with tempfile.TemporaryDirectory() as td:
            path = Path(td) / "findings.json"
            validated = _validated_finding()
            inconclusive = _inconclusive_finding()
            inconclusive["source"] = dict(validated["source"])
            inconclusive["source"]["provider_id"] = "arn:aws:iam::111111\u003111111:user/Bob"
            self._write_findings(path, [validated, inconclusive])
            rc = main(
                [
                    "why",
                    "--findings",
                    str(path),
                    "--pattern",
                    "secrets_blast_radius",
                    "--source",
                    "Alice",
                    "--no-color",
                ]
            )
            assert rc == 0

    def test_why_verbose_flag(self) -> None:
        from iamscope.cli import main

        with tempfile.TemporaryDirectory() as td:
            path = Path(td) / "findings.json"
            self._write_findings(path, [_validated_finding()])
            rc = main(
                [
                    "why",
                    "--findings",
                    str(path),
                    "--finding-id",
                    "abc123",
                    "--verbose",
                    "--no-color",
                ]
            )
            assert rc == 0

    def test_why_empty_findings_returns_0(self) -> None:
        from iamscope.cli import main

        with tempfile.TemporaryDirectory() as td:
            path = Path(td) / "findings.json"
            self._write_findings(path, [])
            rc = main(
                [
                    "why",
                    "--findings",
                    str(path),
                    "--finding-id",
                    "x",
                    "--no-color",
                ]
            )
            assert rc == 0

    def test_why_captures_stdout(self, capsys: pytest.CaptureFixture[str]) -> None:
        from iamscope.cli import main

        with tempfile.TemporaryDirectory() as td:
            path = Path(td) / "findings.json"
            self._write_findings(path, [_validated_finding()])
            main(
                [
                    "why",
                    "--findings",
                    str(path),
                    "--finding-id",
                    "abc123",
                    "--no-color",
                ]
            )
            captured = capsys.readouterr()
            assert "VALIDATED" in captured.out
            assert "Alice" in captured.out
