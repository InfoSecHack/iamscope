# Prod-Like AWS Sandbox Phase 4 Live-Approval Runbook

## Purpose

This runbook defines the approval boundary and future controlled live workflow
for IAMScope's prod-like AWS accuracy sandbox.

It exists before any live AWS execution. It describes approval gates, allowed
future command shapes, redaction rules, cleanup proof, and stop conditions. This
PR does not run Terraform, call AWS, or add live evidence.

## Current Phase State

- Phase 0 public demo baseline: done.
- Phase 1 roadmap: done.
- Phase 2 local oracle fixture: done.
- Phase 3 Terraform design: done.
- Phase 3 Terraform source files: done.
- Phase 4 live execution: not approved yet.

## Required Approval Boundary

- No one should run Terraform init/plan/apply/destroy from this PR.
- Live execution requires explicit Phase 4 approval.
- Dedicated sandbox only.
- Never production or work account.
- No broad correctness claim from a live run.
- Live execution is for bounded artifact generation only.

## Future Live Workflow Overview

The future workflow, after explicit Phase 4 approval, is:

1. Step 0: confirm repo state and tag.
2. Step 1: verify dedicated sandbox AWS profile and region.
3. Step 2: verify expected account ID out-of-band.
4. Step 3: run Terraform init only after approval.
5. Step 4: run Terraform plan to a local `.tfplan` under `/tmp`.
6. Step 5: inspect plan text for IAM-only resources and no unsupported resource families.
7. Step 6: apply only the reviewed plan.
8. Step 7: collect sanitized Terraform outputs.
9. Step 8: run IAMScope collection/reasoning only if separately approved.
10. Step 9: run maximum approved live probes, if any.
11. Step 10: destroy sandbox.
12. Step 11: verify cleanup.
13. Step 12: write sanitized checkpoint.
14. Step 13: feed sanitized artifacts into Phase 5 comparison.

## Hard Safety Gates

- `AWS_PROFILE` must be explicit.
- `AWS_REGION` must be explicit.
- `expected_account_id` must be explicit.
- `live_ack` must equal `I_UNDERSTAND_THIS_IS_A_DEDICATED_IAMSCOPE_SANDBOX`.
- `resource_prefix` must start with `iamscope-prodlike-v1-`.
- Account guard must pass.
- Plan must be reviewed before apply.
- No apply from an unreviewed plan.
- No production/work account.
- No cross-account unless explicitly approved.
- no Lambda invocation.
- No public networking.
- No persistent data stores.
- No destructive service actions.
- No live probe beyond maximum 4.
- Stop immediately on guard failure or unexpected resource family.

## Allowed Future Terraform Commands

DO NOT RUN UNTIL PHASE 4 APPROVAL.

These commands are examples only. None of these are run in this PR.

```bash
cd tests/live/aws/prod_like_accuracy_sandbox/terraform

terraform init

terraform plan \
  -var "aws_profile=<sandbox-profile>" \
  -var "aws_region=<sandbox-region>" \
  -var "expected_account_id=<redacted-sandbox-account-id>" \
  -var "live_ack=I_UNDERSTAND_THIS_IS_A_DEDICATED_IAMSCOPE_SANDBOX" \
  -out /tmp/iamscope-prodlike-v1/plan.tfplan

terraform show -no-color /tmp/iamscope-prodlike-v1/plan.tfplan \
  > /tmp/iamscope-prodlike-v1/plan.txt

terraform apply /tmp/iamscope-prodlike-v1/plan.tfplan

terraform output -json > /tmp/iamscope-prodlike-v1/terraform-outputs.raw.json

terraform destroy
```

## Plan Review Checklist

The plan review checklist must confirm:

- IAM-only resources.
- Expected resource prefix.
- Expected number of principals/roles within max limits.
- No Lambda function.
- No Lambda invocation capability beyond IAM policy shape.
- No VPC/subnet/internet gateway/security group.
- No Organizations/SCP resource.
- No persistent datastore.
- No external access.
- No secrets.
- No production identifiers.

## Allowed Future Live Probes

Maximum 4 future live probes:

- PassRole-to-Lambda allowed CreateFunction attempt without invoke.
- Missing-PassRole denied CreateFunction attempt.
- AssumeRole allowed or denied probe if safe.
- One boundary/SCP-like blocked probe if safe.

Probe boundaries:

- probes are optional;
- each probe requires its own explicit approval;
- no Lambda invocation;
- no exploitability proof;
- no downstream authorization proof;
- no broad correctness claim.

## Sanitization Rules

Redact before commit:

- raw account IDs;
- IAM ARNs;
- Terraform output JSON;
- raw AWS CLI output;
- raw IAMScope collection archives;
- STS identity output;
- provider/cache/state/lock/plan files;
- logs;
- secrets.

Sanitized outputs may preserve:

- resource type class;
- action class;
- result class such as `created`, `access_denied`, `cleanup_verified`;
- counts;
- oracle row ids;
- redacted resource labels;
- evidence category.

## Cleanup Proof

Cleanup proof is required before any public claim:

- Terraform destroy output summarized.
- Verification that IAM users, roles, policies, attachments, and boundaries are gone.
- No orphaned resources.
- Cleanup checkpoint must use sanitized identifiers only.
- Cleanup failure blocks any public claim.

## Phase 5 Handoff

Phase 5 may consume:

- sanitized collection manifest;
- sanitized IAMScope findings;
- sanitized Terraform output summary;
- sanitized cleanup checkpoint;
- oracle fixture row ids;
- comparison input file.

Phase 5 compares against the oracle. Counts by category are allowed. There must
be no composite score and no pass/fail benchmark label.

## Stop Conditions

Stop immediately if:

- account guard fails;
- plan includes unexpected resource families;
- plan exceeds max v1 limits;
- plan includes production/work identifiers;
- raw identifiers would need to be committed;
- cleanup cannot be verified;
- any live probe creates unexpected resources;
- any result would require overclaiming beyond the oracle.

## Non-Claims

- not broad IAMScope correctness;
- not production readiness;
- not real production AWS;
- not exploitability proof;
- not downstream authorization proof;
- not Lambda invocation behavior;
- not generic Deny correctness;
- not resource-policy Deny support except unsupported/static-only row labeling;
- not SCP Deny support beyond selected benchmark behavior;
- no composite benchmark score;
- no pass/fail benchmark label.

## Exact Next Implementation Slice

Recommended next slice: review Terraform source and prepare Phase 4 plan-only command packet.
