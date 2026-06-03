"""v1 characterization tests for iamscope/verify.py.

These tests pin the CURRENT behavior of the v0.2.35-baseline IAM
simulator verification module as a safety net before Session 5
extends it to v2. Every test documents one code path; if a Session 5
change alters a path, the corresponding pinning test breaks
visibly — the developer then decides whether the change is
intentional (update the test) or accidental (revert the change).

v1 scope: only `secrets_blast_radius` findings with
`verdict="validated"` are verified. All other patterns and verdicts
are silently skipped. The module calls
`iam.simulate_principal_policy()` and compares the simulator's
`EvalDecision` against iamscope's `validated` verdict.

All boto3 calls are mocked — no real AWS required.
"""

from __future__ import annotations

import json
from argparse import Namespace
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from unittest.mock import MagicMock, patch

from iamscope.verify import cmd_verify

_ACCOUNT = "111111\u003111111"
_USER_ARN = f"arn:aws:iam::{_ACCOUNT}:user/Alice"
_SECRET_ARN = f"arn:aws:secretsmanager:us-east-1:{_ACCOUNT}:secret:prod/db-password-abc123"


def _findings_doc(
    findings: list[dict[str, Any]] | None = None,
) -> dict[str, Any]:
    """Build a minimal findings.json dict."""
    if findings is None:
        findings = [_validated_secret_finding()]
    return {
        "findings": findings,
        "scenario_hash": "a" * 64,
        "metadata": {"canonical_hash": "b" * 64},
    }


def _validated_secret_finding(
    *,
    verdict: str = "validated",
    pattern_id: str = "secrets_blast_radius",
    source_arn: str = _USER_ARN,
    target_arn: str = _SECRET_ARN,
) -> dict[str, Any]:
    return {
        "pattern_id": pattern_id,
        "verdict": verdict,
        "finding_id": "f" * 64,
        "source": {"provider_id": source_arn, "node_type": "IAMUser"},
        "target": {"provider_id": target_arn, "node_type": "SecretsManagerSecret"},
    }


def _write_findings(tmp_path: Path, doc: dict[str, Any]) -> str:
    p = tmp_path / "findings.json"
    p.write_text(json.dumps(doc))
    return str(p)


def _make_args(
    findings_path: str,
    *,
    profile: str = "test-profile",
    output: str | None = None,
    check_target_state: bool = False,
) -> Namespace:
    return Namespace(
        findings=findings_path,
        profile=profile,
        output=output,
        check_target_state=check_target_state,
    )


def _mock_session(
    *,
    simulate_response: dict[str, Any] | None = None,
    simulate_side_effect: Exception | None = None,
    describe_response: dict[str, Any] | None = None,
    describe_side_effect: Exception | None = None,
) -> MagicMock:
    """Build a mock boto3 Session whose .client() returns controlled
    mocks for IAM and SecretsManager."""
    session = MagicMock()

    iam_client = MagicMock()
    if simulate_side_effect:
        iam_client.simulate_principal_policy.side_effect = simulate_side_effect
    elif simulate_response:
        iam_client.simulate_principal_policy.return_value = simulate_response

    sm_client = MagicMock()
    if describe_side_effect:
        sm_client.describe_secret.side_effect = describe_side_effect
    elif describe_response:
        sm_client.describe_secret.return_value = describe_response

    def _client(service_name: str, **kwargs: Any) -> MagicMock:
        if service_name == "iam":
            return iam_client
        if service_name == "secretsmanager":
            return sm_client
        return MagicMock()

    session.client = _client
    return session


class TestV1HappyPath:
    """Simulator returns 'allowed' → iamscope agrees → exit 0."""

    def test_agreement_returns_exit_0(self, tmp_path: Path) -> None:
        fpath = _write_findings(tmp_path, _findings_doc())
        args = _make_args(fpath)

        mock_sess = _mock_session(
            simulate_response={
                "EvaluationResults": [{"EvalDecision": "allowed"}],
            },
        )
        with patch("boto3.Session", return_value=mock_sess):
            rc = cmd_verify(args)

        assert rc == 0

    def test_agreement_writes_output_report(self, tmp_path: Path) -> None:
        """v2 output: grouped-per-finding under findings_verification,
        with SimulatorVerdict (8 fields), TargetStateCheck (4 fields),
        and aggregated final_verdict."""
        fpath = _write_findings(tmp_path, _findings_doc())
        out = str(tmp_path / "report.json")
        args = _make_args(fpath, output=out)

        mock_sess = _mock_session(
            simulate_response={
                "EvaluationResults": [{"EvalDecision": "allowed"}],
            },
        )
        with patch("boto3.Session", return_value=mock_sess):
            cmd_verify(args)

        report = json.loads(Path(out).read_text())
        assert report["agreements"] == 1
        assert report["disagreements"] == 0
        assert report["inconclusive"] == 0
        assert report["errors"] == 0
        assert report["total_findings"] == 1
        assert report["verifiable_findings"] == 1
        assert "verified_at" in report

        fid = "f" * 64
        assert fid in report["findings_verification"]
        entry = report["findings_verification"][fid]

        assert entry["final_verdict"] == "agreed"

        sv = entry["simulator_verdict"]
        assert sv["result"] == "simulator_validated"
        assert sv["simulated_action"] == "secretsmanager:GetSecretValue"
        assert sv["simulated_principal"] == _USER_ARN
        assert sv["simulated_resource"] == _SECRET_ARN
        assert sv["context_keys_applied"] == []
        assert sv["raw_api_response_digest"]
        assert sv["reason"]
        assert sv["timestamp"]

        ts = entry["target_state"]
        assert ts["checked"] is False


class TestV1Disagreement:
    """Simulator returns something other than 'allowed' → exit 1."""

    def test_explicit_deny_returns_exit_1(self, tmp_path: Path) -> None:
        fpath = _write_findings(tmp_path, _findings_doc())
        args = _make_args(fpath)

        mock_sess = _mock_session(
            simulate_response={
                "EvaluationResults": [{"EvalDecision": "explicitDeny"}],
            },
        )
        with patch("boto3.Session", return_value=mock_sess):
            rc = cmd_verify(args)

        assert rc == 1

    def test_implicit_deny_returns_exit_1(self, tmp_path: Path) -> None:
        fpath = _write_findings(tmp_path, _findings_doc())
        args = _make_args(fpath)

        mock_sess = _mock_session(
            simulate_response={
                "EvaluationResults": [{"EvalDecision": "implicitDeny"}],
            },
        )
        with patch("boto3.Session", return_value=mock_sess):
            rc = cmd_verify(args)

        assert rc == 1


class TestV1ApiError:
    """Simulator call raises ClientError → error result, continues."""

    def test_client_error_returns_exit_0_when_only_finding(
        self,
        tmp_path: Path,
    ) -> None:
        """A single finding that errors out is simulator_inconclusive.
        With 0 disagreements, exit code is 0 (preserved from v1)."""
        from botocore.exceptions import ClientError

        fpath = _write_findings(tmp_path, _findings_doc())
        out = str(tmp_path / "report.json")
        args = _make_args(fpath, output=out)

        error_response = {"Error": {"Code": "AccessDenied", "Message": "no"}}
        mock_sess = _mock_session(
            simulate_side_effect=ClientError(error_response, "SimulatePrincipalPolicy"),
        )
        with patch("boto3.Session", return_value=mock_sess):
            rc = cmd_verify(args)

        assert rc == 0
        report = json.loads(Path(out).read_text())
        fid = "f" * 64
        entry = report["findings_verification"][fid]
        assert entry["simulator_verdict"]["result"] == "simulator_inconclusive"
        assert entry["final_verdict"] == "inconclusive"
        assert report["errors"] == 1
        assert report["inconclusive"] == 1
        assert report["disagreements"] == 0


class TestV1UnsupportedPattern:
    """Findings with unsupported pattern_id or non-validated verdict
    are filtered out before any AWS calls."""

    def test_cross_account_trust_now_supported(self, tmp_path: Path) -> None:
        """v2: cross_account_trust is now in _SUPPORTED. A validated
        finding with an IAMUser source gets a simulator call. Updated
        from v1 'skipped' behavior where boto3.Session was not called."""
        doc = _findings_doc(
            findings=[
                _validated_secret_finding(
                    pattern_id="cross_account_trust",
                    source_arn="arn:aws:iam::111111\u003111111:user/Attacker",
                ),
            ]
        )
        # Ensure source has node_type for the source-type gating
        doc["findings"][0]["source"]["node_type"] = "IAMUser"
        fpath = _write_findings(tmp_path, doc)
        out = str(tmp_path / "report.json")
        args = _make_args(fpath, output=out)

        mock_sess = _mock_session(
            simulate_response={
                "EvaluationResults": [{"EvalDecision": "allowed"}],
            },
        )
        with patch("boto3.Session", return_value=mock_sess):
            rc = cmd_verify(args)

        assert rc == 0
        report = json.loads(Path(out).read_text())
        fid = "f" * 64
        entry = report["findings_verification"][fid]
        assert entry["simulator_verdict"]["result"] == "simulator_validated"
        assert entry["simulator_verdict"]["simulated_action"] == "sts:AssumeRole"
        assert entry["final_verdict"] == "agreed"

    def test_inconclusive_verdict_skipped(self, tmp_path: Path) -> None:
        """Same pattern_id but verdict != 'validated' → skipped."""
        doc = _findings_doc(
            findings=[
                _validated_secret_finding(verdict="inconclusive"),
            ]
        )
        fpath = _write_findings(tmp_path, doc)
        args = _make_args(fpath)

        with patch("boto3.Session") as mock_session_cls:
            rc = cmd_verify(args)
            mock_session_cls.assert_not_called()

        assert rc == 0

    def test_empty_findings_list(self, tmp_path: Path) -> None:
        doc = _findings_doc(findings=[])
        fpath = _write_findings(tmp_path, doc)
        args = _make_args(fpath)

        with patch("boto3.Session") as mock_session_cls:
            rc = cmd_verify(args)
            mock_session_cls.assert_not_called()

        assert rc == 0


class TestV1TargetStateCheck:
    """--check-target-state flag triggers a liveness check that can
    demote an agreement to a disagreement."""

    def test_live_target_preserves_agreement(self, tmp_path: Path) -> None:
        fpath = _write_findings(tmp_path, _findings_doc())
        out = str(tmp_path / "report.json")
        args = _make_args(fpath, output=out, check_target_state=True)

        mock_sess = _mock_session(
            simulate_response={
                "EvaluationResults": [{"EvalDecision": "allowed"}],
            },
            describe_response={
                "CreatedDate": datetime(2026, 1, 1, tzinfo=timezone.utc),
            },
        )
        with patch("boto3.Session", return_value=mock_sess):
            rc = cmd_verify(args)

        assert rc == 0
        fid = "f" * 64
        report = json.loads(Path(out).read_text())
        entry = report["findings_verification"][fid]
        assert entry["simulator_verdict"]["result"] == "simulator_validated"
        assert entry["target_state"]["checked"] is True
        assert entry["target_state"]["state"] == "live"
        assert entry["final_verdict"] == "agreed"

    def test_missing_target_demotes_agreement(self, tmp_path: Path) -> None:
        """Simulator says 'allowed' but the target is deleted at verify
        time → demotes final_verdict to 'disagreed'. Simulator verdict
        itself stays simulator_validated (simulator is correct about
        policy; the target just doesn't exist anymore)."""
        from botocore.exceptions import ClientError

        fpath = _write_findings(tmp_path, _findings_doc())
        out = str(tmp_path / "report.json")
        args = _make_args(fpath, output=out, check_target_state=True)

        error_response = {
            "Error": {"Code": "ResourceNotFoundException", "Message": "gone"},
        }
        mock_sess = _mock_session(
            simulate_response={
                "EvaluationResults": [{"EvalDecision": "allowed"}],
            },
            describe_side_effect=ClientError(
                error_response,
                "DescribeSecret",
            ),
        )
        with patch("boto3.Session", return_value=mock_sess):
            rc = cmd_verify(args)

        assert rc == 1
        fid = "f" * 64
        report = json.loads(Path(out).read_text())
        entry = report["findings_verification"][fid]
        assert entry["simulator_verdict"]["result"] == "simulator_validated"
        assert entry["target_state"]["checked"] is True
        assert entry["target_state"]["state"] == "missing"
        assert entry["final_verdict"] == "disagreed"


class TestV1FileErrors:
    """File-level error handling returns exit code 2."""

    def test_missing_file_returns_exit_2(self, tmp_path: Path) -> None:
        args = _make_args(str(tmp_path / "nonexistent.json"))
        rc = cmd_verify(args)
        assert rc == 2

    def test_invalid_json_returns_exit_2(self, tmp_path: Path) -> None:
        bad = tmp_path / "bad.json"
        bad.write_text("not json{{{")
        args = _make_args(str(bad))
        rc = cmd_verify(args)
        assert rc == 2
