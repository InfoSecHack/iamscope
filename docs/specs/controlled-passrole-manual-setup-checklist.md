# Controlled PassRole Manual Setup Checklist

## Purpose

Provide a human-executable manual checklist for later creating an isolated test-only PassRole source, target role, and service-principal setup.

This is a docs/checklist slice only. It does not perform setup, run live AWS, call `iam:PassRole`, launch services, create or modify AWS resources, create credentials, run Terraform, or change IAMScope behavior.

## Non-Goals

This checklist is not:

- Implementation.
- Live AWS execution in this PR.
- `iam:PassRole` execution.
- Service launch.
- AWS resource creation in this PR.
- Credential creation in this PR.
- Terraform.
- Production testing.
- Broad exploitability proof.
- Production readiness.
- Composite scoring.

## Proposed Test-Only Names

Use these placeholder/example names for the future isolated setup:

- Source principal: `iamscope-passrole-positive-source`.
- Target role: `iamscope-passrole-target-role`.
- Local profile: `iamscope-passrole-positive-source`.
- Service principal: `lambda.amazonaws.com` by default, or `ecs-tasks.amazonaws.com` only if separately selected and documented.
- Session/report prefix: `iamscope-passrole-run001`.

These names are examples for a controlled test account. They are not production names and do not authorize resource creation in this PR.

## Pre-Setup Checks

Before any future setup is performed, confirm:

- [ ] Test account ID is known and recorded in a safe local note outside committed raw artifacts.
- [ ] Account is non-production/test-only.
- [ ] Selected service principal is explicit: `lambda.amazonaws.com` or `ecs-tasks.amazonaws.com`.
- [ ] Operator has permission to create the test IAM source principal and target role if setup is later performed.
- [ ] No production account, production profile, production role, or production service marker is in scope.
- [ ] Teardown and credential-rotation plan is written before setup.
- [ ] No Terraform state/cache/provider artifact will be generated.
- [ ] No credentials, tokens, access keys, or secret values will be committed.
- [ ] No service will be launched as part of this setup checklist.

## Manual Setup Steps

These are future human checklist steps only; this PR does not execute them:

- [ ] Create the test source principal, or choose an existing explicitly test-only source principal.
- [ ] Create the target role, or choose an existing explicitly test-only target role.
- [ ] Set the target role trust policy to trust exactly the selected service principal.
- [ ] Attach minimal source permission allowing `iam:PassRole` only on the selected target role.
- [ ] Keep target role permissions empty, inert, or minimally scoped for static validation needs.
- [ ] Create a local AWS profile only if needed for a later separately approved validation slice.
- [ ] Record only safe metadata: account ID, source principal ARN, target role ARN, selected service principal, and policy/trust summaries.
- [ ] Do not record credentials, raw AWS logs, raw command output, or `/tmp` artifacts in the repository.

## Example Source Permission Policy

Placeholder policy shape for a future test-only source principal:

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "AllowPassOnlySelectedTestRole",
      "Effect": "Allow",
      "Action": "iam:PassRole",
      "Resource": "arn:aws:iam::<test-account-id>:role/iamscope-passrole-target-role",
      "Condition": {
        "StringEquals": {
          "iam:PassedToService": "lambda.amazonaws.com"
        }
      }
    }
  ]
}
```

Checklist constraints for this policy:

- [ ] Replace `<test-account-id>` only in a future setup slice after account selection is reviewed.
- [ ] Use exactly one target role ARN.
- [ ] Do not use wildcard resources.
- [ ] Keep `iam:PassedToService` only if the selected service principal is explicit and the condition is part of the reviewed setup.
- [ ] Do not add admin, service launch, or downstream action permissions.

## Example Target Role Trust Policy

Placeholder trust policy shape for the future test-only target role:

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "TrustOnlySelectedServicePrincipal",
      "Effect": "Allow",
      "Principal": {
        "Service": "lambda.amazonaws.com"
      },
      "Action": "sts:AssumeRole"
    }
  ]
}
```

Checklist constraints for this trust policy:

- [ ] Trust exactly one selected service principal.
- [ ] Do not use wildcard principals.
- [ ] Do not trust account root.
- [ ] Do not trust production principals.
- [ ] Do not add unrelated service principals.

## Credential Handling

Any future credential/profile setup must follow this checklist:

- [ ] Create or access credentials only outside the repository.
- [ ] Never paste credentials into docs, prompts, logs, JSON, Markdown outputs, commits, or PR comments.
- [ ] Store credentials only in the AWS CLI config/credential store or an approved secret store.
- [ ] Use a dedicated local profile, not a production profile.
- [ ] Rotate or delete credentials after proof if credentials are temporary.
- [ ] Do not include credential-shaped values in generated reports or sanitized summaries.

## Teardown Checklist

Before setup is performed, ensure the teardown steps are known:

- [ ] Delete or disable source access keys if any are created.
- [ ] Remove the source principal if it is temporary.
- [ ] Remove the target role if it is temporary.
- [ ] Remove the local profile if it is temporary.
- [ ] Verify no lingering broad permissions remain.
- [ ] Record only a safe teardown summary.
- [ ] Do not commit raw deletion logs, credentials, or `/tmp` outputs.

## Artifact Handling

Future setup artifacts must preserve these boundaries:

- [ ] Setup outputs, if any, go to `/tmp` or another caller-provided path outside committed source.
- [ ] No raw AWS logs are committed.
- [ ] No access keys, secrets, session tokens, or credential-shaped values are committed.
- [ ] No Terraform state/cache/provider artifacts are created or committed.
- [ ] No collect directories are committed.
- [ ] No generated outputs are committed by default.
- [ ] Only a safe summary may be committed later, and only after explicit review.

## Future Pre-Live Validation

After any future setup is completed, a separate future slice must:

- [ ] Collect exact source principal ARN, target role ARN, service principal, account ID, and profile name.
- [ ] Create a controlled PassRole report or pre-live plan under `/tmp`.
- [ ] Run the controlled PassRole report/schema validator.
- [ ] Confirm no AWS calls were made during report validation.
- [ ] Confirm no `iam:PassRole` call was made.
- [ ] Confirm no service launch occurred.
- [ ] Confirm `ready_for_live_or_static_validation` is `yes` or `no` with explicit abort reasons.
- [ ] Avoid live PassRole validation unless a separately approved protocol authorizes it.

## What This Checklist Enables

This checklist enables only:

- Safer manual preparation of a test-only PassRole setup later.
- Repeatable human review before any validation.
- Reduced credential and artifact leakage risk.
- A narrow bridge from no-candidate selection to a reviewed setup decision.

## What This Checklist Does Not Prove

This checklist does not prove:

- PassRole validation.
- `iam:PassRole` execution.
- Service launch.
- Production readiness.
- Broad runtime exploitability.
- Downstream authorization.
- Arbitrary IAMScope correctness.
- Resource-policy Deny support.
- Finding-level reachability.

## Recommended Next Slice

Recommend exactly one next slice: decide whether to perform the manual PassRole setup outside IAMScope, or stop PassRole controlled validation for this phase.

That next slice should be a docs/decision slice. It must not recommend immediate live PassRole, service launch, Terraform apply, production account testing, downstream AWS actions, broad runtime validation, CI gating, composite scoring, or multiple slices at once.