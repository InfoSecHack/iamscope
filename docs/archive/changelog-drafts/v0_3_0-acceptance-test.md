# v0.3.0 Real-AWS Acceptance Test Results

> **Archive note:** Historical changelog draft retained as background context.
> It is not current public reviewer guidance and should not be read as an
> instruction to run live AWS.

**Date:** 2026-04-14
**Ship gate:** Option B — v0.3.0 does not ship until real-AWS acceptance passes.

## Infrastructure

Terraform-deployed acceptance test infrastructure in acceptance/step8/main.tf.
Resources created in a dedicated test AWS account:

- iamscope-target-user — IAM user at path /iamscope-test/
- iamscope-target-lambda-role — IAM role with Lambda service trust policy
- iamscope-test/sample-secret — Secrets Manager secret with placeholder value
- Inline policy on target user granting:
  - secretsmanager:GetSecretValue on the test secret
  - iam:PassRole on the Lambda role

Cost incurred: ~$0.40/month for the Secrets Manager secret (deleted after acceptance).

## Test findings

Hand-crafted findings-input.json with 3 validated findings referencing real ARNs.

Finding 1: pattern=secrets_blast_radius, source=target_user, target=test_secret.
  Expected simulator verdict: allowed (simulator_validated)

Finding 2: pattern=passrole_lambda, source=target_user, target=lambda_role.
  Expected simulator verdict: allowed (simulator_validated)

Finding 3: pattern=cross_account_trust, source=target_user, target=fictional cross-account role.
  Expected simulator verdict: implicitDeny (simulator_disagreement)

## Phase 3: Verify against real AWS (no liveness check)

Command:
    python -m iamscope.cli verify \
        --findings acceptance/step8/findings-input.json \
        --profile iamscope-test \
        --output acceptance/step8/findings-annotated.json

Results: All three findings produced verdicts matching prediction.
- Finding 1: simulator=allowed -> simulator_validated -> final_verdict=agreed
- Finding 2: simulator=allowed -> simulator_validated -> final_verdict=agreed
- Finding 3: simulator=implicitDeny -> simulator_disagreement -> final_verdict=disagreed

Summary: 2 agreements, 1 disagreement, 0 inconclusive, 0 errors. Exit code 1.

raw_api_response_digest populated with real SHA-256 of AWS simulator responses
for each finding, proving simulator round-trips worked correctly.

## Phase 5: Bug discovery and fix (Step 7.5)

Initial Phase 5 run with --check-target-state crashed at Finding 2:

    ValueError: Invalid endpoint: https://secretsmanager..amazonaws.com

Root cause: v1 _check_secret_target_state function assumed the target ARN was
always a Secrets Manager ARN (which has a region in the ARN). v1 only supported
the secrets_blast_radius pattern, so this held. Session 5 Step 4 extended pattern
support to 5 patterns including IAM role and S3 bucket targets. IAM ARNs have
empty region segments (IAM is global) — passing them through region-based
endpoint construction produced the malformed URL.

Characterization tests (Step 1), v2 pattern extension unit tests (Step 4), and
moto integration tests (Step 7) did not catch this because none exercised real
boto3 endpoint construction with a non-secret ARN. The defect lived specifically
in the "--check-target-state + non-secret target + real boto3" corner.

Fix (commit 2fd8012, Step 7.5): scoped --check-target-state invocation to
secrets_blast_radius findings only. For other patterns, target_state returns
checked=False, state="not_applicable", reason="liveness check not implemented
for pattern <X> in v0.3.0". _aggregate_final_verdict updated to treat
not_applicable as non-demoting (equivalent to not_checked/live for final
verdict aggregation).

Generalized resource liveness checking (iam:GetRole, s3:HeadBucket, etc.) is
deferred to a future session per the post-v0.3.0 roadmap.

## Phase 5 re-run: liveness check with fix in place

Results:
- Finding 1: simulator=allowed + target_state=live (secret exists)
- Finding 2: simulator=allowed + target_state=not_applicable
- Finding 3: simulator=implicitDeny + target_state=not_applicable
- Summary counts unchanged from Phase 3

No crashes. not_applicable properly distinguishes from live/missing/not_checked.

## Known limitations in v0.3.0

- --check-target-state liveness check applies only to secrets_blast_radius findings.
  For other patterns, target_state reports not_applicable. Generalized liveness
  checking is deferred to a future version.
- Conditional findings (non-empty required_checks) are simulated unconditionally;
  conditions_signal.conditions_present=True is an operator-visible breadcrumb
  for findings whose reasoner evaluated conditions but the simulator did not see
  them.
- Multi-hop patterns (admin_reachability, assume_role_chain,
  iam_group_membership_escalation) return simulator_inconclusive with a
  documented reason; per-hop chaining is deferred to a future session.

## Artifacts retained for reference

- acceptance/step8/main.tf — Terraform for acceptance test infrastructure
- acceptance/step8/findings-input.json — 3-finding test input
- acceptance/step8/findings-annotated.json — Phase 3 output (no liveness check)
- acceptance/step8/findings-annotated-with-target-state.json — Phase 5 output

## Ship approval

Session 5 acceptance test for v0.3.0: PASSED. All predicted verdicts observed,
known limitations documented, one inherited v1 defect surfaced and fixed before
shipping. Option B correctness floor is satisfied.

Next: Step 9 (version bump to 0.3.0, changelog assembly, zip build, tag).
