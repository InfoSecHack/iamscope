# Benchmark Runtime STS Positive Proof Protocol

## Purpose

This protocol defines how to prepare exactly one positive/assumed live STS proof run for IAMScope.

The positive proof is for one specified test principal, one specified test role, one explicit test account/profile context, and one caller-provided output location. It is not broad runtime validation and must remain separate from frozen reasoning benchmarks, synthetic scalability benchmarks, threshold review, and production-readiness claims.

This document is design/protocol only. It does not run live AWS, call STS AssumeRole, require AWS credentials, implement new runtime behavior, change the live STS executor, or change the dry-run validator.

## Non-Goals

This protocol is not:

- Implementation.
- A live run in this PR.
- Terraform.
- Production testing.
- Destructive testing.
- Downstream AWS action testing.
- Broad exploitability proof.
- Production-readiness proof.
- Arbitrary IAMScope correctness proof.
- CI gating.
- Composite scoring.

The protocol must not be framed as broad runtime exploitability, production readiness, broad IAMScope correctness, or benchmark pass/fail behavior.

## Required Pre-Run State

Before any future positive single-case live STS proof run, all of the following must be true:

- Existing live-capable STS executor implementation is merged.
- The denied single-case STS proof is documented.
- `main` is clean and synced to the intended commit.
- `./scripts/check.sh` has passed.
- `./scripts/test_fast.sh` has passed.
- Positive probe plan passes dry-run validation.
- Positive probe simulation passes.
- Operator explicitly confirms the live run.
- Test account/profile assumptions are documented before the run.

A dirty worktree, stale `main`, missing validation, failed simulation, or undocumented account/profile assumptions must stop the protocol.

## Positive Proof-Specific Requirements

Positive proof requirements:

- Test-only source principal.
- Test-only target role.
- Intentional trust relationship allowing the source principal to assume the target role.
- Explicit `sts:AssumeRole` permission for the source principal.
- No production resources.
- No downstream AWS actions.
- One live STS call only.
- Credentials may be returned but must never be printed, written, logged, or reused.
- Output may only record `credentials_obtained=true` as a boolean.
- No `AccessKeyId`.
- No `SecretAccessKey`.
- No `SessionToken`.
- No credentials object.
- No credential-shaped fields.

The positive proof must not use returned credentials for any downstream API call, inspection, enumeration, or validation step.

## Test Account And Profile Assumptions

The positive proof run must document these fields before execution:

- `aws_profile`
- `expected_account_id`
- `source_principal_arn`
- `target_role_arn`
- Target role account.
- `region`, if needed by the environment or runner.
- `session_name_prefix`
- `duration_seconds`
- `external_id`, if needed.
- `expected_outcome`: `assumed`

Required assumptions:

- Test identities only.
- Test roles only.
- Test accounts only.
- No production account by default.
- Production-like markers require explicit allowlist review and are discouraged.
- Account/profile assumptions must be readable by a reviewer before any live command is run.

## Positive Probe Plan Shape

The positive probe plan must contain exactly one probe. This placeholder example is intentionally not runnable as-is and must be replaced with reviewed test-account values before any future live run.

The operator confirmation phrase is included in the allowed top-level `notes` field for review visibility, but the live executor still requires it on the command line as an exact argument.

```json
{
  "schema_version": "0.1",
  "plan_type": "sts_assume_role_probe_plan",
  "mode": "dry_run",
  "notes": "Operator confirmation phrase: I understand this will call sts:AssumeRole once for test IAM resources only",
  "probes": [
    {
      "probe_id": "positive-single-case-sts-assume-role-proof",
      "source_principal_arn": "arn:aws:iam::<TEST_ACCOUNT_ID>:role/iamscope-test-positive-source-role",
      "target_role_arn": "arn:aws:iam::<TEST_ACCOUNT_ID>:role/iamscope-test-positive-target-role",
      "aws_profile": "<TEST_AWS_PROFILE>",
      "expected_account_id": "<TEST_ACCOUNT_ID>",
      "region": "us-east-1",
      "session_name_prefix": "iamscope-positive-proof",
      "duration_seconds": 900,
      "expected_outcome": "assumed",
      "evidence_boundary": "Positive single-case STS proof only; not production readiness or broad exploitability evidence.",
      "safety_notes": "Uses one test source principal, one test target role, one intentional trust relationship, and one test account only."
    }
  ]
}
```

The plan must not include real account IDs in committed documentation, downstream action fields, raw debug logging fields, Terraform fields, credentials, credential-shaped fields, or broad selectors.

## Operator Confirmation

Future live execution requires the canonical exact operator confirmation phrase:

```text
I understand this will call sts:AssumeRole once for test IAM resources only
```

If the executor-enforced confirmation phrase and this protocol phrase differ, abort before any live run and resolve the mismatch in a separately scoped review.

## Pre-Run Validation Sequence

Use this sequence before any future positive live run:

1. Verify the target role trust policy intentionally allows the source principal.
2. Verify the source principal has explicit `sts:AssumeRole` permission for the target role.
3. Validate the probe plan with the dry-run validator.
4. Run the executor in no-call/simulation mode.
5. Inspect JSON and Markdown output boundaries.
6. Verify JSON and Markdown outputs are written only to caller-provided paths.
7. Confirm there are no production markers, or that any marker is explicitly allowlisted for test-only use.
8. Confirm no downstream actions are configured.
9. Confirm no raw debug logging is requested.
10. Confirm the operator confirmation phrase.
11. Confirm exactly one probe is present.
12. Only then allow one `live_probe` execution.

## Abort Conditions

Hard abort conditions:

- Trust relationship is not intentional.
- Source permission is not explicit.
- Dry-run validation fails.
- Simulation fails.
- Target account does not match `expected_account_id`.
- Explicit `aws_profile` is missing.
- Operator confirmation is missing or does not match the required phrase.
- Production marker is present and not explicitly allowlisted.
- Source or target ARN contains a wildcard.
- `duration_seconds` is unsafe or unbounded.
- JSON or Markdown output path is missing.
- Downstream action is configured.
- Raw debug logging is requested.
- More than one probe is present in the plan.
- Worktree is dirty when the protocol requires clean state.

Any abort must happen before an STS client is constructed or an AWS call is attempted.

## Future Live Run Command Shape

Do not run this command in this PR. This is the future command shape for a separately approved positive single-case live proof run:

```bash
bash scripts/run_sts_probe_executor.sh \
  --plan /tmp/iamscope-positive-sts-proof-plan.json \
  --json-out /tmp/iamscope-positive-sts-proof-result.json \
  --markdown-out /tmp/iamscope-positive-sts-proof-result.md \
  --mode live_probe \
  --allow-live-mode \
  --operator-confirmation "I understand this will call sts:AssumeRole once for test IAM resources only"
```

The future live command may be used only after the exact account, profile, source principal, target role, expected outcome, trust relationship, source permission, output paths, and abort conditions are reviewed and explicitly approved by the user.

## Expected Safe Outputs

A future positive proof run should produce safe JSON and Markdown summaries.

Output boundaries:

- `live_aws_used=true` only if the live run executed.
- `aws_calls_made=true` only if STS was attempted.
- `sts_assume_role_called=true` only if STS was attempted.
- `credentials_obtained=true` only as a boolean if AssumeRole succeeds.
- No `AccessKeyId`.
- No `SecretAccessKey`.
- No `SessionToken`.
- No credentials object.
- No raw credential-shaped fields.
- No raw AWS debug logs.
- No raw exception dump.
- No composite score.
- No pass/fail benchmark field.

If the future live run aborts before STS is attempted, live/AWS flags must remain false and the result must use a non-overclaiming refusal or configuration classification.

## Result Interpretation

Interpret result classifications narrowly:

- `assumed` means the specific test principal assumed the specific test role under the explicit test conditions.
- `denied` is unexpected for a positive proof and requires investigation.
- `inconclusive`, `configuration_error`, or `unexpected_account` require investigation before interpretation.
- No result classification implies broad exploitability.
- No result classification proves downstream AWS action authorization.
- No result classification proves production readiness.
- No result classification expands IAMScope's broad semantic correctness claims.

The result must be read with the probe plan, account/profile assumptions, verified trust relationship, verified source permission, safety notes, and evidence boundary.

## Artifact Handling

Artifact rules:

- Outputs go to `/tmp` or another caller-provided path.
- Generated outputs are not committed by default.
- If a redacted summary is ever committed, it requires separate artifact-policy review.
- No raw AWS logs.
- No credentials, tokens, or secrets.
- No Terraform state, cache, provider, or plan artifacts.
- No `collect/` directories.
- No raw `scenario.json`, `findings.json`, `binding_metadata.json`, or `run.log` artifacts.
- Safe JSON/Markdown summaries only.

## Post-Run Checklist

After any future positive single-case live run:

- Inspect JSON and Markdown outputs for secrets.
- Verify no credential-shaped fields are present.
- Verify `credentials_obtained=true` appears only as a boolean.
- Verify classification and caveats.
- Verify no downstream AWS actions happened.
- Verify output was not written into the repository by default.
- Record interpretation boundaries with the result.
- Preserve the distinction between runtime-probe evidence and frozen reasoning benchmark evidence.

## What This Protocol Would Prove

If followed in a separately approved live slice, this protocol could prove only:

- One configured live STS call was attempted under the protocol.
- One specific test principal could assume one specific test role under explicit test conditions.
- Output sanitization and evidence boundaries were preserved.

## What Remains Unproven

This protocol does not prove:

- Production readiness.
- Broad runtime exploitability.
- Arbitrary IAMScope correctness.
- Downstream AWS authorization.
- Resource-policy Deny support.
- Finding-level resource-policy reachability.
- Enterprise coverage.
- Persistence.
- Impact.
- Multi-account stability.
- Multi-day stability.

## Observed Positive Proof Checkpoint

A positive single-case live STS proof was performed manually outside this PR and is recorded here as a sanitized checkpoint only.

Sanitized proof summary:

- Source principal: `arn:aws:iam::<redacted-aws-account-id>:user/iamscope-positive-source`
- Target role: `arn:aws:iam::<redacted-aws-account-id>:role/iamscope-positive-target-role`
- Expected outcome: `assumed`
- Observed result classification: `assumed`
- `live_aws_used=true`
- `aws_calls_made=true`
- `sts_assume_role_called=true`
- `credentials_obtained=true`
- Downstream AWS actions: none
- Raw credentials emitted: no
- Raw credentials committed: no
- Raw `/tmp` proof outputs committed: no

Evidence boundary:

- This proves only that one isolated test source principal could assume one isolated test target role under explicit test conditions.
- This also shows the executor reported `credentials_obtained=true` without emitting raw credential material for this one proof.
- This does not expand the frozen reasoning benchmark evidence, mutation-pair evidence, synthetic scalability evidence, reporting/comparison evidence, or threshold review evidence.

Teardown confirmation:

- Source user missing.
- Target role missing.
- Positive local profile no longer usable.
- No downstream AWS action evidence was collected or needed.

Non-claims:

- No production readiness.
- No broad runtime exploitability.
- No downstream authorization proof.
- No broad IAMScope correctness.
- No arbitrary enterprise graph correctness.
- No resource-policy Deny support.
- No finding-level resource-policy reachability.
- No enterprise coverage.
- No persistence or impact proof.

## Recommended Next Slice

Recommended next slice: final runtime proof maturity checkpoint.

That next slice should be docs/checkpoint only. It should not recommend more live probes by default, add CI gates, add pass/fail benchmark labels, add composite scoring, or broaden runtime-proof claims.
