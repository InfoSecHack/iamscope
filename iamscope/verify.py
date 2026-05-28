"""iamscope verify — cross-check validated findings against AWS IAM
Policy Simulator as authoritative ground truth.

v2 (v0.3.0): extends v1's secrets_blast_radius-only scope to five
patterns (cross_account_trust, passrole_lambda, passrole_ecs,
s3_bucket_takeover, secrets_blast_radius). Produces structured
SimulatorVerdict + TargetStateCheck objects per finding. Conservative
on conditions (simulator_inconclusive for conditional findings) and
multi-hop patterns (simulator_inconclusive with explicit reason).

Exit codes: 0 = all verified findings agreed (or nothing to verify
or all inconclusive), 1 = one or more disagreements (investigate),
2 = file/argument/session error.

Output schema (--output):
  Grouped per finding under `findings_verification`:
    findings_verification.<finding_id>.simulator_verdict — 8 fields
    findings_verification.<finding_id>.target_state — 4 fields
    findings_verification.<finding_id>.conditions_signal — 3 fields
      (operator breadcrumb: conditions_present, detected_via, note)
    findings_verification.<finding_id>.final_verdict — aggregated string
  Summary counts at root: agreements, disagreements, inconclusive,
  errors, total_findings, verifiable_findings, verified_at,
  scenario_hash.

  `simulator_verdict` and `target_state` are semantically different
  signals: the simulator asks "does AWS's authorization engine agree
  the edge is authorized?" (policy evaluation), while the liveness
  check asks "does the target resource still exist?" (runtime state).
  They live as sibling keys, not embedded in one another, so future
  RuntimeVerificationVerdict from roadmap Session 9 can slot in as
  a third sibling cleanly.
"""

from __future__ import annotations

import hashlib
import json
import logging
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any

logger = logging.getLogger(__name__)

_SUPPORTED = {
    "cross_account_trust",
    "passrole_ecs",
    "passrole_lambda",
    "s3_bucket_takeover",
    "secrets_blast_radius",
}
_ACTION_FOR_PATTERN = {
    "cross_account_trust": "sts:AssumeRole",
    "passrole_ecs": "iam:PassRole",
    "passrole_lambda": "iam:PassRole",
    "s3_bucket_takeover": "s3:PutBucketPolicy",
    "secrets_blast_radius": "secretsmanager:GetSecretValue",
}
_MULTI_HOP_PATTERNS = {
    "admin_reachability",
    "assume_role_chain",
    "iam_group_membership_escalation",
}
_SIMULATABLE_SOURCE_TYPES = {"IAMUser", "IAMRole"}


# ---------------------------------------------------------------------------
# Structured verdict dataclasses
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class SimulatorVerdict:
    """Result of calling iam:SimulatePrincipalPolicy for one finding.

    Fields are immutable after construction. `to_dict()` produces the
    JSON-serializable shape embedded in findings_verification output.
    `from_dict()` round-trips from the serialized form.
    """

    result: str
    simulated_action: str
    simulated_resource: str
    simulated_principal: str
    # Immutable at dataclass level via tuple; serialized as JSON list
    # in to_dict(). Round-tripping through from_dict() converts
    # list → tuple. Always () for v0.3.0 (context-key mapping
    # deferred to future session).
    context_keys_applied: tuple[str, ...] = ()
    raw_api_response_digest: str = ""
    reason: str = ""
    timestamp: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "context_keys_applied": list(self.context_keys_applied),
            "raw_api_response_digest": self.raw_api_response_digest,
            "reason": self.reason,
            "result": self.result,
            "simulated_action": self.simulated_action,
            "simulated_principal": self.simulated_principal,
            "simulated_resource": self.simulated_resource,
            "timestamp": self.timestamp,
        }

    @classmethod
    def from_dict(cls, d: dict[str, Any]) -> SimulatorVerdict:
        return cls(
            result=d["result"],
            simulated_action=d["simulated_action"],
            simulated_resource=d["simulated_resource"],
            simulated_principal=d["simulated_principal"],
            context_keys_applied=tuple(d.get("context_keys_applied", ())),
            raw_api_response_digest=d.get("raw_api_response_digest", ""),
            reason=d.get("reason", ""),
            timestamp=d.get("timestamp", ""),
        )


@dataclass(frozen=True)
class TargetStateCheck:
    """Result of the --check-target-state liveness query for one finding.

    Semantically independent from SimulatorVerdict: the simulator
    evaluates authorization policy, the liveness check evaluates
    runtime resource state. Both are needed for a complete verdict.

    When --check-target-state is not passed, `checked=False` and
    the other fields are empty defaults.
    """

    checked: bool = False
    state: str = ""
    reason: str = ""
    timestamp: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "checked": self.checked,
            "reason": self.reason,
            "state": self.state,
            "timestamp": self.timestamp,
        }

    @classmethod
    def from_dict(cls, d: dict[str, Any]) -> TargetStateCheck:
        return cls(
            checked=d.get("checked", False),
            state=d.get("state", ""),
            reason=d.get("reason", ""),
            timestamp=d.get("timestamp", ""),
        )


# ---------------------------------------------------------------------------
# Final verdict aggregation
# ---------------------------------------------------------------------------


def _aggregate_final_verdict(
    sim: SimulatorVerdict,
    tsc: TargetStateCheck,
) -> str:
    """Combine simulator verdict + target state into a single string.

    Aggregation logic:
    - simulator_disagreement → "disagreed" regardless of target state
    - simulator_inconclusive → "inconclusive" regardless of target state
    - simulator_validated + target not checked → "agreed"
    - simulator_validated + target live → "agreed"
    - simulator_validated + target missing/pending_deletion → "disagreed"
    - simulator_validated + any other target state → "inconclusive"
      (includes access_denied, error, and any unexpected value from
      _check_secret_target_state; the conservative default is "I can't
      confirm the target is reachable, so I can't confirm agreement")

    Note: target_state "not_applicable" (liveness check not implemented
    for this pattern in v0.3.0) is treated like not-checked — it does
    NOT demote the final verdict. The simulator's answer stands alone.
    """
    if sim.result == "simulator_disagreement":
        return "disagreed"
    if sim.result == "simulator_inconclusive":
        return "inconclusive"
    # sim.result == "simulator_validated"
    if not tsc.checked:
        return "agreed"
    if tsc.state in ("live", "not_applicable"):
        return "agreed"
    if tsc.state in ("missing", "pending_deletion"):
        return "disagreed"
    return "inconclusive"


# ---------------------------------------------------------------------------
# Conditions signal — operator-visible breadcrumb (not a gate)
# ---------------------------------------------------------------------------


def _compute_conditions_signal(finding: dict[str, Any]) -> dict[str, Any]:
    """Detect whether a finding's required_checks mention conditions.

    v0.3.0 heuristic: scan `required_checks[*].name` for any name
    containing "condition". This is an operator-visible breadcrumb,
    NOT a simulator gating mechanism — all VALIDATED findings are
    simulated unconditionally because reasoner invariant 5 ensures
    condition-related assumptions are resolved before VALIDATED.

    The signal tells operators "this simulator result evaluates policy
    as-if-no-conditions; the finding's reasoner already evaluated the
    conditions and found them favorable."
    """
    checks = finding.get("required_checks", [])
    has_condition = any("condition" in c.get("name", "").lower() for c in checks)
    result: dict[str, Any] = {
        "conditions_present": has_condition,
        "detected_via": "required_checks_heuristic",
    }
    if has_condition:
        result["note"] = "finding had condition-related required_checks; simulator evaluates policy as-if-no-conditions"
    else:
        result["note"] = ""
    return result


# ---------------------------------------------------------------------------
# Target state checker (preserved from v1)
# ---------------------------------------------------------------------------


def _check_secret_target_state(
    session: Any,
    target_arn: str,
) -> tuple[str, str]:
    """Query live target state to catch scan-time vs exec-time drift.

    Feature #3 from the "elite in practice" roadmap: a finding that was
    VALIDATED at scan time might not work at exec time if the target
    has been deleted, disabled, put in pending-deletion, or otherwise
    degraded between the scan and the report. Without this check,
    iamscope will confidently report a path to a target that no longer
    exists — the worst kind of stale finding in a real assessment.

    Returns (status, reason):
        ("live", <creation_date_iso>) — target exists and is usable
        ("pending_deletion", <delete_date>) — scheduled for deletion
        ("missing", "ResourceNotFoundException") — deleted or wrong region
        ("access_denied", "...") — collector profile lost list perm
        ("error", "<ExceptionName>: <msg>") — anything else

    The reasoner-side verdict is not mutated here; the caller decides
    whether to demote the finding. This function is purely observational
    and is safe to run with a read-only profile.
    """
    from botocore.exceptions import ClientError

    sm = session.client(
        "secretsmanager",
        region_name=target_arn.split(":")[3] if ":" in target_arn else None,
    )
    try:
        resp = sm.describe_secret(SecretId=target_arn)
    except ClientError as e:
        code = e.response.get("Error", {}).get("Code", "Unknown")
        if code == "ResourceNotFoundException":
            return ("missing", "target not found at verify time")
        if code in ("AccessDeniedException", "UnauthorizedOperation"):
            return ("access_denied", code)
        return ("error", f"{code}: {e.response.get('Error', {}).get('Message', '')[:80]}")
    except Exception as e:
        return ("error", f"{type(e).__name__}: {str(e)[:80]}")
    # DeletedDate present means the secret is pending deletion.
    if resp.get("DeletedDate"):
        return (
            "pending_deletion",
            f"scheduled deletion at {resp['DeletedDate'].isoformat()}",
        )
    created = resp.get("CreatedDate")
    return ("live", created.isoformat() if created else "live")


# ---------------------------------------------------------------------------
# Main command
# ---------------------------------------------------------------------------


def cmd_verify(args: Any) -> int:
    """Verify findings against AWS IAM Policy Simulator."""
    import boto3
    from botocore.exceptions import BotoCoreError, ClientError

    findings_path = Path(args.findings)
    if not findings_path.exists():
        logger.error("Findings file not found: %s", findings_path)
        return 2

    try:
        doc = json.loads(findings_path.read_text())
    except json.JSONDecodeError as e:
        logger.error("Invalid JSON in %s: %s", findings_path, e)
        return 2

    findings = doc.get("findings", [])

    # Partition findings into verifiable (supported + validated),
    # multi-hop (explicit inconclusive), and skipped (everything else).
    verifiable = [f for f in findings if f.get("pattern_id") in _SUPPORTED and f.get("verdict") == "validated"]
    multi_hop = [f for f in findings if f.get("pattern_id") in _MULTI_HOP_PATTERNS and f.get("verdict") == "validated"]

    if not verifiable and not multi_hop:
        print("No supported validated findings to verify.")
        return 0

    try:
        session = boto3.Session(profile_name=args.profile)
        iam = session.client("iam")
    except (BotoCoreError, ClientError) as e:
        logger.error("Failed to create AWS session: %s", e)
        return 2

    verification: dict[str, dict[str, Any]] = {}
    agreements = 0
    disagreements = 0
    inconclusive_count = 0
    error_count = 0

    # --- Multi-hop findings: explicit inconclusive, no API call ---
    for f in multi_hop:
        fid = f["finding_id"]
        now = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
        pattern = f["pattern_id"]
        src = f["source"]["provider_id"]
        tgt = f["target"]["provider_id"]
        print(f"  [{fid[:16]}] ⊘ multi-hop ({pattern}) — skipped")

        sim_verdict = SimulatorVerdict(
            result="simulator_inconclusive",
            simulated_action="",
            simulated_resource=tgt,
            simulated_principal=src,
            reason="multi-hop finding requires per-hop simulator chaining — deferred to future session",
            timestamp=now,
        )
        inconclusive_count += 1
        verification[fid] = {
            "conditions_signal": _compute_conditions_signal(f),
            "final_verdict": "inconclusive",
            "simulator_verdict": sim_verdict.to_dict(),
            "target_state": TargetStateCheck().to_dict(),
        }

    # --- Verifiable findings ---
    if verifiable:
        print(f"Verifying {len(verifiable)} validated finding(s) against AWS IAM Policy Simulator...\n")

    for f in verifiable:
        src = f["source"]["provider_id"]
        src_type = f["source"].get("node_type", "")
        tgt = f["target"]["provider_id"]
        fid = f["finding_id"]
        fid_short = fid[:16]
        pattern = f["pattern_id"]
        action = _ACTION_FOR_PATTERN[pattern]
        now = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
        cond_signal = _compute_conditions_signal(f)

        # --- Source type gating (cross_account_trust quirk) ---
        if src_type not in _SIMULATABLE_SOURCE_TYPES:
            print(f"  [{fid_short}] ⊘ source is {src_type} — simulator requires IAMUser or IAMRole")
            sim_verdict = SimulatorVerdict(
                result="simulator_inconclusive",
                simulated_action=action,
                simulated_resource=tgt,
                simulated_principal=src,
                reason=f"source principal is {src_type} — simulator "
                f"requires a specific IAM user or role ARN as "
                f"PolicySourceArn",
                timestamp=now,
            )
            inconclusive_count += 1
            verification[fid] = {
                "conditions_signal": cond_signal,
                "final_verdict": "inconclusive",
                "simulator_verdict": sim_verdict.to_dict(),
                "target_state": TargetStateCheck().to_dict(),
            }
            continue

        # --- Simulator call ---
        try:
            resp = iam.simulate_principal_policy(
                PolicySourceArn=src,
                ActionNames=[action],
                ResourceArns=[tgt],
            )
            raw_digest = hashlib.sha256(json.dumps(resp, sort_keys=True, default=str).encode()).hexdigest()
            decision = resp["EvaluationResults"][0]["EvalDecision"]
        except (BotoCoreError, ClientError) as e:
            print(f"  [{fid_short}] API ERROR: {e}")
            sim_verdict = SimulatorVerdict(
                result="simulator_inconclusive",
                simulated_action=action,
                simulated_resource=tgt,
                simulated_principal=src,
                raw_api_response_digest="",
                reason=f"API error: {type(e).__name__}: {str(e)[:120]}",
                timestamp=now,
            )
            tsc = TargetStateCheck()
            final = _aggregate_final_verdict(sim_verdict, tsc)
            inconclusive_count += 1
            error_count += 1
            verification[fid] = {
                "conditions_signal": cond_signal,
                "final_verdict": final,
                "simulator_verdict": sim_verdict.to_dict(),
                "target_state": tsc.to_dict(),
            }
            continue

        agreed = decision == "allowed"
        marker = "✓" if agreed else "✗"
        print(f"  [{fid_short}] {marker} iamscope=validated  simulator={decision}")

        # --- Build simulator verdict ---
        if agreed:
            sim_verdict = SimulatorVerdict(
                result="simulator_validated",
                simulated_action=action,
                simulated_resource=tgt,
                simulated_principal=src,
                raw_api_response_digest=raw_digest,
                reason=f"simulator EvalDecision={decision} agrees with validated verdict",
                timestamp=now,
            )
        else:
            sim_verdict = SimulatorVerdict(
                result="simulator_disagreement",
                simulated_action=action,
                simulated_resource=tgt,
                simulated_principal=src,
                raw_api_response_digest=raw_digest,
                reason=f"simulator EvalDecision={decision} disagrees with validated verdict",
                timestamp=now,
            )

        # --- Target state check (optional, preserved from v1) ---
        # v0.3.0: liveness check scoped to secrets_blast_radius only.
        # _check_secret_target_state queries SecretsManager and assumes
        # the target ARN is a secret. For non-secret patterns (IAM roles,
        # S3 buckets), the function would crash on empty-region ARNs
        # (IAM is global → arn:aws:iam::... has empty region segment →
        # boto3 constructs "secretsmanager..amazonaws.com"). Generalizing
        # to other resource types (iam:GetRole, s3:HeadBucket, etc.) is
        # deferred to a future session — see post-v0.3.0 roadmap.
        tsc = TargetStateCheck()
        if args.check_target_state:
            tsc_now = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
            if pattern == "secrets_blast_radius":
                target_state, state_reason = _check_secret_target_state(
                    session,
                    tgt,
                )
                tsc = TargetStateCheck(
                    checked=True,
                    state=target_state,
                    reason=state_reason,
                    timestamp=tsc_now,
                )
                state_marker = {
                    "live": "✓",
                    "pending_deletion": "⚠",
                    "missing": "✗",
                    "access_denied": "?",
                    "error": "?",
                }.get(target_state, "?")
                print(f"          {state_marker} target_state={target_state} ({state_reason})")
            else:
                tsc = TargetStateCheck(
                    checked=False,
                    state="not_applicable",
                    reason=f"liveness check not implemented for pattern {pattern} in v0.3.0",
                    timestamp=tsc_now,
                )
                print(f"          ─ target_state=not_applicable (liveness check not implemented for {pattern})")

        print(f"          {src}")
        print(f"          → {tgt}")

        # --- Aggregate final verdict ---
        final = _aggregate_final_verdict(sim_verdict, tsc)

        if final == "agreed":
            agreements += 1
        elif final == "disagreed":
            disagreements += 1
            if tsc.checked and tsc.state in ("missing", "pending_deletion"):
                print(f"          → DEMOTED: target_state={tsc.state} overrides simulator agreement")
        else:
            inconclusive_count += 1

        verification[fid] = {
            "conditions_signal": cond_signal,
            "final_verdict": final,
            "simulator_verdict": sim_verdict.to_dict(),
            "target_state": tsc.to_dict(),
        }

    # --- Summary ---
    print(f"\n{'=' * 60}")
    print("Verification summary")
    print(f"{'=' * 60}")
    print(f"  Findings verified:  {len(verifiable)}")
    print(f"  Agreements:         {agreements}")
    print(f"  Disagreements:      {disagreements}")
    print(f"  Inconclusive:       {inconclusive_count}")
    if error_count:
        print(f"  (of which errors:   {error_count})")
    if disagreements:
        print(
            f"\n  ⚠  {disagreements} finding(s) disagreed with AWS's own "
            f"simulator. These are either iamscope bugs or simulator "
            f"blind spots — investigate each one."
        )

    # --- Output report ---
    if args.output:
        out_path = Path(args.output)
        report: dict[str, Any] = {
            "agreements": agreements,
            "disagreements": disagreements,
            "errors": error_count,
            "findings_verification": verification,
            "inconclusive": inconclusive_count,
            "scenario_hash": doc.get("scenario_hash", ""),
            "total_findings": len(findings),
            "verifiable_findings": len(verifiable),
            "verified_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        }
        out_path.write_text(json.dumps(report, indent=2, sort_keys=True))
        print(f"\n  Wrote detailed report to {out_path}")

    return 1 if disagreements else 0
