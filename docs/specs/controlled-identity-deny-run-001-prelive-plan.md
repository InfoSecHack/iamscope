# Controlled Identity Deny Run #1 Pre-Live / Static Plan

## Purpose

Create the pre-live/static plan for Controlled Identity Deny Run #1 using the selected Env03 identity-Deny candidate. This slice represents the selected committed sanitized candidate as a controlled identity Deny validation report under `/tmp` and validates that report shape/safety only.

This slice does not run live AWS, call STS, call `iam:PassRole`, call Lambda APIs, create or modify resources, run Terraform, perform active validation, change IAMScope reasoning logic, or change benchmark logic.

## Selected Candidate

- Validation run ID: `controlled-identity-deny-run-001-static-suppression`
- Environment label: `phase0-env03-sanitized-static`
- Source principal ARN: `arn:aws:iam::<redacted-aws-account-id>:user/iamscope-test/env03-cc1-alice`
- Candidate action: `iam:AddUserToGroup`
- Candidate resource: `arn:aws:iam::<redacted-aws-account-id>:group/iamscope-test/env03-cc1-admins`
- Pattern/finding family: `iam_group_membership_escalation`
- Validation-layer ID: `controlled-identity-deny-run-001-env03-add-user-to-group`
- Native finding/path ID status: no reusable native `finding_id` or `path_id` was identified in the committed sanitized run summaries.
- Source bundle: `benchmarks/snapshots/phase0-20260509-env27/runs/env03-20260424T025701Z`

## Evidence Sources

The report is based on committed sanitized evidence only:

- `docs/specs/controlled-identity-deny-candidate-selection.md`
- `benchmarks/cases/env03_identity_deny_group_escalation.json`
- `benchmarks/snapshots/phase0-20260509-env27/runs/env03-20260424T025701Z/run_manifest.json`
- `benchmarks/snapshots/phase0-20260509-env27/runs/env03-20260424T025701Z/scorer_result.json`
- `benchmarks/snapshots/phase0-20260509-env27/runs/env03-20260424T025701Z/report.md`
- `docs/specs/env16-mutation-benchmark-harness.md`
- `benchmarks/pair-reports/phase0-20260509-env27-mutation-pairs.md`

No raw AWS artifacts or `/tmp` benchmark outputs were copied into the repo.

## Allow Basis Summary

The committed Env03/Env16 evidence documents a structural Allow/path basis:

- Alice has an Allow for `iam:AddUserToGroup` on the target admins group.
- The target admins group is the selected group-escalation target.
- Env16 is the mutation-pair contrast where the explicit identity Deny is removed and the same group-escalation shape is expected to validate.

## Deny Basis Summary

The committed Env03 evidence documents the explicit identity-Deny basis:

- Env03 ground truth states that explicit identity-policy Deny on `iam:AddUserToGroup` overrides Allow for the selected source and target group.
- Env03 semantic assertions require identity-Deny blocker evidence.
- The Env03 scorer result records `identity_deny_blocker_present` and `identity_deny_check_failed` assertions as satisfied.
- The Env03 report summarizes that the exact blocked group-escalation path includes identity-Deny blocker attribution.

## Condition Context

No condition requirement is described in the committed sanitized candidate evidence. The generated report records condition context as absent/not applicable and includes a caveat that no raw policy document was committed or inspected in this slice.

## Predicted And Expected Behavior

- Predicted behavior: `suppressed`
- Expected outcome: `suppressed`
- AWS semantic expectation: the selected action is denied because explicit identity-policy Deny overrides structural Allow.
- IAMScope evidence expectation: the structurally allowed group-escalation path is not emitted as validated and is represented as blocked with identity-Deny blocker evidence in committed benchmark evidence.

## Evidence Method

- Evidence method: `static_policy_corroboration`
- Live AWS used: `false`
- AWS calls made: `false`
- Active action called: `false`
- Destructive action called: `false`
- Resource modified: `false`

No active validation is approved or performed.

## Generated Report And Validation

Generated `/tmp` output paths:

- Report JSON: `/tmp/iamscope-controlled-identity-deny-run-001/controlled-identity-deny-run-001-report.json`
- Validation JSON: `/tmp/iamscope-controlled-identity-deny-run-001/controlled-identity-deny-run-001-validation.json`
- Validation Markdown: not generated; the validator emits JSON to stdout.

Validator command:

```bash
bash scripts/validate_controlled_identity_deny_validation_report.sh \
  --report /tmp/iamscope-controlled-identity-deny-run-001/controlled-identity-deny-run-001-report.json
```

Validation result:

- `valid`: `true`
- `validated_report_type`: `controlled_identity_deny_validation_report`
- `validation_id`: `controlled-identity-deny-run-001-static-suppression`
- `method_type`: `static_policy_corroboration`
- `observed_outcome`: `suppressed`
- `outcome_classification`: `corroborated`
- `live_aws_used`: `false`
- `aws_calls_made`: `false`
- `active_action_called`: `false`
- `destructive_action_called`: `false`
- `resource_modified`: `false`

The generated report and validation summary remain under `/tmp` and are not committed.

## Readiness

- Ready for active validation: no.
- Ready for static checkpoint documentation: yes.

Reasoning: this slice proves only that the selected Env03 candidate can be represented as a controlled identity Deny validation report and pass schema/safety validation from committed sanitized evidence. It does not approve or perform live AWS checks.

## Abort Conditions

Abort any follow-up that would:

- Require live AWS, STS, `iam:PassRole`, Lambda APIs, or resource modification without a separate approved protocol.
- Copy raw AWS artifacts, raw logs, credentials, or `/tmp` outputs into the repo.
- Reinterpret the candidate as SCP Deny, resource-policy Deny, permission-boundary behavior, or generic Deny correctness.
- Treat this static report as active AWS behavior.
- Remove required non-claims or artifact-safety fields.
- Add pass/fail benchmark labels or composite scoring.

## Evidence Boundary

This pre-live/static validation proves only that the selected identity-Deny candidate can be represented as a controlled identity Deny validation report and pass schema/safety validation from committed sanitized evidence.

It does not prove active AWS behavior, generic Deny correctness, resource-policy Deny support, SCP Deny support, production readiness, broad IAMScope correctness, broad runtime exploitability, downstream authorization, all-findings verification, or real-world scalability.

## Non-Claims

This plan and generated `/tmp` report do not claim:

- Production readiness.
- Broad IAMScope correctness.
- Broad runtime exploitability.
- Generic Deny correctness.
- Resource-policy Deny support.
- SCP Deny support.
- Downstream authorization proof.
- All findings verified.
- Real-world scalability.
- Composite benchmark score.

## Recommended Next Slice

Recommend exactly one next slice: document controlled identity Deny Run #1 static validation checkpoint.

That next slice should remain docs/checkpoint only. It must not run live AWS, perform active validation, create or modify resources, add a new benchmark framework, add CI gates, introduce composite scoring, or recommend multiple slices at once.
