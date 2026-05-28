"""Session 5 Step 4 — v2 pattern extension tests.

Covers the 4 newly-supported patterns (cross_account_trust,
passrole_lambda, passrole_ecs, s3_bucket_takeover), multi-hop
explicit inconclusive handling, source-type gating for
cross_account_trust, and conditions_signal breadcrumb.

15 tests total:
- 4 per-pattern happy path (simulator_validated)
- 4 per-pattern disagreement (simulator_disagreement)
- 2 cross_account_trust source-type inconclusive
  (AccountPrincipalSet, OIDCProvider)
- 3 multi-hop explicit inconclusive
  (admin_reachability, assume_role_chain,
   iam_group_membership_escalation)
- 2 conditions_signal tests (with/without condition checks)
"""

from __future__ import annotations

import json
from argparse import Namespace
from pathlib import Path
from typing import Any
from unittest.mock import MagicMock, patch

from iamscope.verify import cmd_verify

_ACCOUNT = "111111111111"
_USER_ARN = f"arn:aws:iam::{_ACCOUNT}:user/Alice"
_ROLE_ARN = f"arn:aws:iam::{_ACCOUNT}:role/TargetRole"
_BUCKET_ARN = "arn:aws:s3:::corp-secrets"
_SECRET_ARN = f"arn:aws:secretsmanager:us-east-1:{_ACCOUNT}:secret:prod/db-password-abc123"
_EXTERNAL_ACCOUNT = "999999999999"
_ACCOUNT_ROOT_ARN = f"arn:aws:iam::{_EXTERNAL_ACCOUNT}:root"
_OIDC_ARN = f"arn:aws:iam::{_ACCOUNT}:oidc-provider/token.actions.githubusercontent.com"


def _finding(
    *,
    pattern_id: str,
    source_arn: str = _USER_ARN,
    source_type: str = "IAMUser",
    target_arn: str = _ROLE_ARN,
    target_type: str = "IAMRole",
    verdict: str = "validated",
    required_checks: list[dict[str, Any]] | None = None,
) -> dict[str, Any]:
    f: dict[str, Any] = {
        "finding_id": f"{'0' * 56}{pattern_id[:8]:0>8}",
        "pattern_id": pattern_id,
        "source": {
            "node_type": source_type,
            "provider_id": source_arn,
        },
        "target": {
            "node_type": target_type,
            "provider_id": target_arn,
        },
        "verdict": verdict,
    }
    if required_checks is not None:
        f["required_checks"] = required_checks
    else:
        f["required_checks"] = []
    return f


def _doc(*findings: dict[str, Any]) -> dict[str, Any]:
    return {
        "findings": list(findings),
        "scenario_hash": "a" * 64,
        "metadata": {"canonical_hash": "b" * 64},
    }


def _write(tmp_path: Path, doc: dict[str, Any]) -> str:
    p = tmp_path / "findings.json"
    p.write_text(json.dumps(doc))
    return str(p)


def _args(
    fpath: str,
    *,
    output: str | None = None,
    check_target_state: bool = False,
) -> Namespace:
    return Namespace(
        findings=fpath,
        profile="test",
        output=output,
        check_target_state=check_target_state,
    )


def _mock_session(
    *,
    simulate_response: dict[str, Any] | None = None,
) -> MagicMock:
    session = MagicMock()
    iam = MagicMock()
    if simulate_response:
        iam.simulate_principal_policy.return_value = simulate_response
    session.client.return_value = iam
    return session


_ALLOWED = {"EvaluationResults": [{"EvalDecision": "allowed"}]}
_DENIED = {"EvaluationResults": [{"EvalDecision": "explicitDeny"}]}


# -------------------------------------------------------------------
# Per-pattern happy path: simulator_validated
# -------------------------------------------------------------------


class TestPatternHappyPath:
    """Each supported pattern with simulator returning 'allowed'."""

    def test_cross_account_trust_validated(self, tmp_path: Path) -> None:
        f = _finding(
            pattern_id="cross_account_trust",
            source_arn=f"arn:aws:iam::{_EXTERNAL_ACCOUNT}:role/Specific",
            source_type="IAMRole",
        )
        fpath = _write(tmp_path, _doc(f))
        out = str(tmp_path / "r.json")
        mock = _mock_session(simulate_response=_ALLOWED)
        with patch("boto3.Session", return_value=mock):
            rc = cmd_verify(_args(fpath, output=out))
        assert rc == 0
        report = json.loads(Path(out).read_text())
        entry = report["findings_verification"][f["finding_id"]]
        assert entry["simulator_verdict"]["result"] == "simulator_validated"
        assert entry["simulator_verdict"]["simulated_action"] == "sts:AssumeRole"
        assert entry["final_verdict"] == "agreed"

    def test_passrole_lambda_validated(self, tmp_path: Path) -> None:
        f = _finding(pattern_id="passrole_lambda")
        fpath = _write(tmp_path, _doc(f))
        out = str(tmp_path / "r.json")
        mock = _mock_session(simulate_response=_ALLOWED)
        with patch("boto3.Session", return_value=mock):
            rc = cmd_verify(_args(fpath, output=out))
        assert rc == 0
        entry = json.loads(Path(out).read_text())["findings_verification"][f["finding_id"]]
        assert entry["simulator_verdict"]["result"] == "simulator_validated"
        assert entry["simulator_verdict"]["simulated_action"] == "iam:PassRole"

    def test_passrole_ecs_validated(self, tmp_path: Path) -> None:
        f = _finding(pattern_id="passrole_ecs")
        fpath = _write(tmp_path, _doc(f))
        out = str(tmp_path / "r.json")
        mock = _mock_session(simulate_response=_ALLOWED)
        with patch("boto3.Session", return_value=mock):
            rc = cmd_verify(_args(fpath, output=out))
        assert rc == 0
        entry = json.loads(Path(out).read_text())["findings_verification"][f["finding_id"]]
        assert entry["simulator_verdict"]["result"] == "simulator_validated"
        assert entry["simulator_verdict"]["simulated_action"] == "iam:PassRole"

    def test_s3_bucket_takeover_validated(self, tmp_path: Path) -> None:
        f = _finding(
            pattern_id="s3_bucket_takeover",
            target_arn=_BUCKET_ARN,
            target_type="S3Bucket",
        )
        fpath = _write(tmp_path, _doc(f))
        out = str(tmp_path / "r.json")
        mock = _mock_session(simulate_response=_ALLOWED)
        with patch("boto3.Session", return_value=mock):
            rc = cmd_verify(_args(fpath, output=out))
        assert rc == 0
        entry = json.loads(Path(out).read_text())["findings_verification"][f["finding_id"]]
        assert entry["simulator_verdict"]["result"] == "simulator_validated"
        assert entry["simulator_verdict"]["simulated_action"] == "s3:PutBucketPolicy"


# -------------------------------------------------------------------
# Per-pattern disagreement: simulator_disagreement
# -------------------------------------------------------------------


class TestPatternDisagreement:
    """Each supported pattern with simulator returning 'explicitDeny'."""

    def test_cross_account_trust_disagreed(self, tmp_path: Path) -> None:
        f = _finding(
            pattern_id="cross_account_trust",
            source_arn=f"arn:aws:iam::{_EXTERNAL_ACCOUNT}:role/Specific",
            source_type="IAMRole",
        )
        fpath = _write(tmp_path, _doc(f))
        mock = _mock_session(simulate_response=_DENIED)
        with patch("boto3.Session", return_value=mock):
            rc = cmd_verify(_args(fpath))
        assert rc == 1

    def test_passrole_lambda_disagreed(self, tmp_path: Path) -> None:
        f = _finding(pattern_id="passrole_lambda")
        fpath = _write(tmp_path, _doc(f))
        mock = _mock_session(simulate_response=_DENIED)
        with patch("boto3.Session", return_value=mock):
            rc = cmd_verify(_args(fpath))
        assert rc == 1

    def test_passrole_ecs_disagreed(self, tmp_path: Path) -> None:
        f = _finding(pattern_id="passrole_ecs")
        fpath = _write(tmp_path, _doc(f))
        mock = _mock_session(simulate_response=_DENIED)
        with patch("boto3.Session", return_value=mock):
            rc = cmd_verify(_args(fpath))
        assert rc == 1

    def test_s3_bucket_takeover_disagreed(self, tmp_path: Path) -> None:
        f = _finding(
            pattern_id="s3_bucket_takeover",
            target_arn=_BUCKET_ARN,
            target_type="S3Bucket",
        )
        fpath = _write(tmp_path, _doc(f))
        mock = _mock_session(simulate_response=_DENIED)
        with patch("boto3.Session", return_value=mock):
            rc = cmd_verify(_args(fpath))
        assert rc == 1


# -------------------------------------------------------------------
# Source-type gating: cross_account_trust with non-IAM sources
# -------------------------------------------------------------------


class TestSourceTypeGating:
    """cross_account_trust findings where source is not IAMUser/IAMRole
    get simulator_inconclusive without calling the simulator."""

    def test_account_principal_set_inconclusive(
        self,
        tmp_path: Path,
    ) -> None:
        f = _finding(
            pattern_id="cross_account_trust",
            source_arn=_ACCOUNT_ROOT_ARN,
            source_type="AccountPrincipalSet",
        )
        fpath = _write(tmp_path, _doc(f))
        out = str(tmp_path / "r.json")
        with patch("boto3.Session") as mock_cls:
            mock_sess = MagicMock()
            mock_sess.client.return_value = MagicMock()
            mock_cls.return_value = mock_sess
            rc = cmd_verify(_args(fpath, output=out))
            mock_sess.client.return_value.simulate_principal_policy.assert_not_called()
        assert rc == 0
        entry = json.loads(Path(out).read_text())["findings_verification"][f["finding_id"]]
        assert entry["simulator_verdict"]["result"] == "simulator_inconclusive"
        assert "AccountPrincipalSet" in entry["simulator_verdict"]["reason"]
        assert entry["final_verdict"] == "inconclusive"

    def test_oidc_provider_inconclusive(self, tmp_path: Path) -> None:
        f = _finding(
            pattern_id="cross_account_trust",
            source_arn=_OIDC_ARN,
            source_type="OIDCProvider",
        )
        fpath = _write(tmp_path, _doc(f))
        out = str(tmp_path / "r.json")
        with patch("boto3.Session") as mock_cls:
            mock_sess = MagicMock()
            mock_sess.client.return_value = MagicMock()
            mock_cls.return_value = mock_sess
            rc = cmd_verify(_args(fpath, output=out))
            mock_sess.client.return_value.simulate_principal_policy.assert_not_called()
        assert rc == 0
        entry = json.loads(Path(out).read_text())["findings_verification"][f["finding_id"]]
        assert entry["simulator_verdict"]["result"] == "simulator_inconclusive"
        assert "OIDCProvider" in entry["simulator_verdict"]["reason"]


# -------------------------------------------------------------------
# Multi-hop patterns: explicit inconclusive, no API call
# -------------------------------------------------------------------


class TestMultiHopInconclusive:
    """Multi-hop patterns get simulator_inconclusive with documented
    reason. No simulator API call is made."""

    def test_admin_reachability_inconclusive(self, tmp_path: Path) -> None:
        f = _finding(pattern_id="admin_reachability")
        fpath = _write(tmp_path, _doc(f))
        out = str(tmp_path / "r.json")
        with patch("boto3.Session") as mock_cls:
            mock_sess = MagicMock()
            mock_sess.client.return_value = MagicMock()
            mock_cls.return_value = mock_sess
            rc = cmd_verify(_args(fpath, output=out))
            mock_sess.client.return_value.simulate_principal_policy.assert_not_called()
        assert rc == 0
        entry = json.loads(Path(out).read_text())["findings_verification"][f["finding_id"]]
        assert entry["simulator_verdict"]["result"] == "simulator_inconclusive"
        assert "multi-hop" in entry["simulator_verdict"]["reason"]

    def test_assume_role_chain_inconclusive(self, tmp_path: Path) -> None:
        f = _finding(pattern_id="assume_role_chain")
        fpath = _write(tmp_path, _doc(f))
        out = str(tmp_path / "r.json")
        with patch("boto3.Session") as mock_cls:
            mock_sess = MagicMock()
            mock_sess.client.return_value = MagicMock()
            mock_cls.return_value = mock_sess
            rc = cmd_verify(_args(fpath, output=out))
        assert rc == 0
        entry = json.loads(Path(out).read_text())["findings_verification"][f["finding_id"]]
        assert entry["simulator_verdict"]["result"] == "simulator_inconclusive"
        assert "multi-hop" in entry["simulator_verdict"]["reason"]

    def test_iam_group_membership_escalation_inconclusive(
        self,
        tmp_path: Path,
    ) -> None:
        f = _finding(pattern_id="iam_group_membership_escalation")
        fpath = _write(tmp_path, _doc(f))
        out = str(tmp_path / "r.json")
        with patch("boto3.Session") as mock_cls:
            mock_sess = MagicMock()
            mock_sess.client.return_value = MagicMock()
            mock_cls.return_value = mock_sess
            rc = cmd_verify(_args(fpath, output=out))
        assert rc == 0
        entry = json.loads(Path(out).read_text())["findings_verification"][f["finding_id"]]
        assert entry["simulator_verdict"]["result"] == "simulator_inconclusive"
        assert "multi-hop" in entry["simulator_verdict"]["reason"]


# -------------------------------------------------------------------
# Conditions signal breadcrumb
# -------------------------------------------------------------------


class TestConditionsSignal:
    """conditions_signal is a per-finding operator breadcrumb that
    indicates whether the finding's required_checks mention conditions.
    It does NOT gate the simulator call — all VALIDATED findings are
    simulated unconditionally per v0.3.0 design (reasoner invariant 5
    guarantees condition concerns are resolved before VALIDATED)."""

    def test_conditions_present_true(self, tmp_path: Path) -> None:
        """Finding with a condition-related required_check signals True."""
        f = _finding(
            pattern_id="passrole_lambda",
            required_checks=[
                {"name": "source_has_lambda_create_function", "state": "pass", "reason": "ok"},
                {
                    "name": "passrole_condition_scoped_to_lambda_or_absent",
                    "state": "pass",
                    "reason": "no condition block on PassRole statement",
                },
            ],
        )
        fpath = _write(tmp_path, _doc(f))
        out = str(tmp_path / "r.json")
        mock = _mock_session(simulate_response=_ALLOWED)
        with patch("boto3.Session", return_value=mock):
            cmd_verify(_args(fpath, output=out))
        entry = json.loads(Path(out).read_text())["findings_verification"][f["finding_id"]]
        cs = entry["conditions_signal"]
        assert cs["conditions_present"] is True
        assert cs["detected_via"] == "required_checks_heuristic"
        assert cs["note"]

    def test_conditions_present_false(self, tmp_path: Path) -> None:
        """Finding with no condition-related checks signals False."""
        f = _finding(
            pattern_id="s3_bucket_takeover",
            target_arn=_BUCKET_ARN,
            target_type="S3Bucket",
            required_checks=[
                {"name": "principal_has_put_bucket_policy_permission", "state": "pass", "reason": "ok"},
            ],
        )
        fpath = _write(tmp_path, _doc(f))
        out = str(tmp_path / "r.json")
        mock = _mock_session(simulate_response=_ALLOWED)
        with patch("boto3.Session", return_value=mock):
            cmd_verify(_args(fpath, output=out))
        entry = json.loads(Path(out).read_text())["findings_verification"][f["finding_id"]]
        cs = entry["conditions_signal"]
        assert cs["conditions_present"] is False
        assert cs["note"] == ""


# -------------------------------------------------------------------
# Liveness check scoping (Step 7.5 — v1 inherited defect fix)
# -------------------------------------------------------------------


class TestLivenessCheckScoping:
    """v0.3.0: --check-target-state only invokes _check_secret_target_state
    for secrets_blast_radius findings. For other patterns, target_state
    returns not_applicable without calling any describe API — preventing
    the v1 bug where non-secret ARNs (IAM roles with empty region)
    caused ValueError: Invalid endpoint: secretsmanager..amazonaws.com.

    Discovered in Step 8 real-AWS acceptance testing."""

    def test_passrole_lambda_returns_not_applicable(
        self,
        tmp_path: Path,
    ) -> None:
        """passrole_lambda target is an IAM role (global, empty region).
        Liveness check must NOT call SecretsManager describe."""
        f = _finding(pattern_id="passrole_lambda")
        fpath = _write(tmp_path, _doc(f))
        out = str(tmp_path / "r.json")
        mock = _mock_session(simulate_response=_ALLOWED)
        with patch("boto3.Session", return_value=mock):
            rc = cmd_verify(
                _args(
                    fpath,
                    output=out,
                    check_target_state=True,
                )
            )
        assert rc == 0
        entry = json.loads(Path(out).read_text())["findings_verification"][f["finding_id"]]
        ts = entry["target_state"]
        assert ts["checked"] is False
        assert ts["state"] == "not_applicable"
        assert "passrole_lambda" in ts["reason"]
        assert entry["final_verdict"] == "agreed"

    def test_s3_bucket_takeover_returns_not_applicable(
        self,
        tmp_path: Path,
    ) -> None:
        """s3_bucket_takeover target is an S3 bucket ARN. Liveness
        check must NOT call SecretsManager describe."""
        f = _finding(
            pattern_id="s3_bucket_takeover",
            target_arn=_BUCKET_ARN,
            target_type="S3Bucket",
        )
        fpath = _write(tmp_path, _doc(f))
        out = str(tmp_path / "r.json")
        mock = _mock_session(simulate_response=_ALLOWED)
        with patch("boto3.Session", return_value=mock):
            rc = cmd_verify(
                _args(
                    fpath,
                    output=out,
                    check_target_state=True,
                )
            )
        assert rc == 0
        entry = json.loads(Path(out).read_text())["findings_verification"][f["finding_id"]]
        ts = entry["target_state"]
        assert ts["checked"] is False
        assert ts["state"] == "not_applicable"
        assert "s3_bucket_takeover" in ts["reason"]
        assert entry["final_verdict"] == "agreed"
