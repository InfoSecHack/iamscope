# Controlled Identity Deny Run #1 Static Validation Checkpoint

## Purpose

Record the static validation result for Controlled Identity Deny Run #1.

This is a docs/checkpoint slice only. It does not run live AWS, call STS, call `iam:PassRole`, call Lambda APIs, create or modify AWS resources, run Terraform, perform active validation, generate new reports, commit `/tmp` outputs, change IAMScope reasoning logic, or change benchmark logic.

## Run Summary

- Validation run ID: `controlled-identity-deny-run-001-static-suppression`.
- Selected candidate: Env03 identity-Deny group escalation candidate.
- Source principal: `arn:aws:iam::<redacted-aws-account-id>:user/iamscope-test/env03-cc1-alice`.
- Candidate action: `iam:AddUserToGroup`.
- Candidate resource: `arn:aws:iam::<redacted-aws-account-id>:group/iamscope-test/env03-cc1-admins`.
- Pattern/finding family: `iam_group_membership_escalation`.
- Validation-layer ID: `controlled-identity-deny-run-001-env03-add-user-to-group`.
- Native finding/path ID status: no reusable native `finding_id` or `path_id` was identified in the committed sanitized run summaries.
- Predicted behavior: `suppressed`.
- Expected outcome: `suppressed`.
- Evidence method: `static_policy_corroboration`.
- Outcome classification: `corroborated`.
- Ready for active validation: no.

## Allow Basis Summary

The committed Env03/Env16 evidence records a structural Allow/path basis:

- Alice has an Allow for `iam:AddUserToGroup` on the target admins group.
- The target admins group is the selected group-escalation target.
- Env16 is the mutation-pair contrast where the explicit identity Deny is removed and the same group-escalation shape is expected to validate.

## Deny Basis Summary

The committed Env03 evidence records the explicit identity-Deny basis:

- Env03 ground truth states that explicit identity-policy Deny on `iam:AddUserToGroup` overrides Allow for the selected source and target group.
- Env03 semantic assertions require identity-Deny blocker evidence.
- The Env03 scorer result records `identity_deny_blocker_present` and `identity_deny_check_failed` assertions as satisfied.
- The Env03 report summarizes that the exact blocked group-escalation path includes identity-Deny blocker attribution.

## Condition Context

No condition requirement is described in the committed sanitized candidate evidence.

The static report records condition context as absent/not applicable and caveats that no raw policy document was committed or inspected in the pre-live/static slice.

## Validation Result

The controlled identity Deny report was generated under `/tmp` only and passed the identity Deny report validator.

Generated `/tmp` output paths from the pre-live/static slice:

- Report JSON: `/tmp/iamscope-controlled-identity-deny-run-001/controlled-identity-deny-run-001-report.json`.
- Validation JSON: `/tmp/iamscope-controlled-identity-deny-run-001/controlled-identity-deny-run-001-validation.json`.
- Validation Markdown: not generated; the validator emitted JSON to stdout.

Sanitized validator result:

- `valid=true`.
- `validated_report_type=controlled_identity_deny_validation_report`.
- `validation_id=controlled-identity-deny-run-001-static-suppression`.
- `method_type=static_policy_corroboration`.
- `observed_outcome=suppressed`.
- `outcome_classification=corroborated`.
- `live_aws_used=false`.
- `aws_calls_made=false`.
- `active_action_called=false`.
- `destructive_action_called=false`.
- `resource_modified=false`.

No `/tmp` report or validation outputs were committed.

## Evidence Boundary

This checkpoint proves only that the selected identity-Deny candidate can be represented as a controlled identity Deny validation report and pass schema/safety validation using committed sanitized evidence.

It does not prove active AWS behavior, live identity Deny validation, generic Deny correctness, resource-policy Deny support, SCP Deny support, production readiness, broad IAMScope correctness, broad runtime exploitability, downstream authorization, all-findings verification, or real-world scalability.

## Non-Claims

This checkpoint does not claim:

- Live identity Deny validation.
- Active AWS call execution.
- Production readiness.
- Broad IAMScope correctness.
- Generic Deny correctness.
- Resource-policy Deny support.
- SCP Deny support.
- Downstream authorization proof.
- Broad runtime exploitability.
- All findings verified.
- Real-world scalability.
- Composite benchmark score.

## Artifact Safety

Artifact safety status:

- No credentials committed.
- No raw AWS logs committed.
- No raw `/tmp` outputs committed.
- No Terraform state committed.
- No composite score.
- No pass/fail label.
- No generated report committed by default.

## Relationship To Evidence Program

This checkpoint adds static controlled evidence for identity-Deny suppression.

It complements the controlled STS and PassRole validation evidence by documenting a false-positive-control boundary for one selected explicit identity-Deny suppression case. It does not replace active Deny validation if that is later designed and separately approved.

## Recommended Next Slice

Recommend exactly one next slice: decide whether to design active harmless identity Deny validation or update evidence matrix with static Deny result.

That next slice should remain a bounded docs/decision or docs/update slice. It must not recommend immediate active validation, live AWS, resource creation/modification, a new benchmark framework, CI gates, composite scoring, or multiple slices at once.
