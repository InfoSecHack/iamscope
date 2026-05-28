# Benchmark Runtime STS Positive Manual Setup Checklist

## Purpose

This checklist provides a human-executable path for manually creating a test-only positive STS source principal and target role in a later, separately approved setup activity.

It is Terraform-free by design. It documents what a future operator must verify before setup, what safe setup shape should look like, how credentials and artifacts must be handled, and what must happen before any future positive live proof.

This checklist does not perform the setup. It does not run live AWS, call STS AssumeRole, create IAM users, create IAM roles, modify trust policies, modify permission policies, create credentials, run Terraform apply, add live AWS environments, implement setup logic, change executor logic, change the dry-run validator, add raw artifacts, commit `/tmp` outputs, add CI gates, add pass/fail benchmark labels, add composite scoring, claim production readiness, claim broad IAMScope correctness, or claim broad runtime exploitability.

## Non-Goals

This checklist is not:

- Implementation.
- Live AWS execution in this PR.
- IAM creation in this PR.
- Credential creation in this PR.
- Terraform.
- Production testing.
- Downstream AWS action testing.
- Broad exploitability proof.
- Production-readiness proof.
- Arbitrary IAMScope correctness proof.
- CI gating.
- Composite scoring.

The checklist must not be treated as approval to create resources, create credentials, change IAM, or run a live proof.

## Proposed Test-Only Names

Placeholder names for a future isolated setup:

- Source principal: `iamscope-positive-source`
- Target role: `iamscope-positive-target-role`
- Local profile: `iamscope-positive-source`
- Session prefix: `iamscope-positive-proof`

These names are examples only. A future setup activity must confirm the exact test account, final names, source principal ARN, target role ARN, local profile name, and teardown plan before any IAM change occurs.

## Pre-Setup Checks

Before any future manual setup, confirm:

- [ ] Test account ID is documented.
- [ ] Account is explicitly non-production/test.
- [ ] Account, role, principal, and profile names do not contain production markers.
- [ ] Operator has permission to create a test IAM principal and role if setup is later performed.
- [ ] Operator understands this checklist is not approval to run live AWS in this PR.
- [ ] Teardown or credential-rotation plan is documented before setup.
- [ ] No Terraform will be used.
- [ ] No Terraform state, cache, provider, or plan artifacts will be generated.
- [ ] No credentials will be committed.
- [ ] No raw AWS outputs will be committed.
- [ ] Safe output paths, if any, are caller-provided and outside the repo by default.

If any item is not true, stop before setup.

## Manual Setup Steps

The following are future manual setup checklist steps. They are not commands to run in this PR.

- [ ] Create a test source principal, or choose an existing test-only principal.
- [ ] Create a test target role, or choose an existing test-only role.
- [ ] Record the source principal ARN as safe metadata.
- [ ] Record the target role ARN as safe metadata.
- [ ] Set the target role trust policy to trust exactly the source principal.
- [ ] Confirm the target role trust policy has no wildcard principal.
- [ ] Confirm the target role trust policy has no production principal.
- [ ] Confirm the target role trust policy does not trust account root.
- [ ] Attach the minimal source permission that allows `sts:AssumeRole` only on the target role.
- [ ] Confirm the source permission has no wildcard resource.
- [ ] Confirm the source principal has no admin permissions.
- [ ] Confirm the source principal has no broad IAM permissions.
- [ ] Keep the target role permission policy empty if possible.
- [ ] If a target role permission policy is required, keep it inert/minimal and non-destructive.
- [ ] Confirm no downstream AWS action permissions are needed for the proof.
- [ ] Create a dedicated local AWS profile only if needed.
- [ ] Record only safe metadata, not credentials.
- [ ] Store credentials only outside the IAMScope repository.
- [ ] Re-check the teardown or rotation plan before leaving setup complete.

## Example Trust Policy

Placeholder target role trust policy:

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Principal": {
        "AWS": "arn:aws:iam::<TEST_ACCOUNT_ID>:user/iamscope-positive-source"
      },
      "Action": "sts:AssumeRole"
    }
  ]
}
```

Trust policy requirements:

- No real account ID in committed documentation.
- No wildcard principal.
- Exactly one source principal.
- `sts:AssumeRole` only.
- No broad account-root trust.
- No production principal.

If the source principal is a role instead of a user, replace the placeholder user ARN with the exact test role ARN.

## Example Source Permission Policy

Placeholder source-side permission policy:

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": "sts:AssumeRole",
      "Resource": "arn:aws:iam::<TEST_ACCOUNT_ID>:role/iamscope-positive-target-role"
    }
  ]
}
```

Source permission requirements:

- No real account ID in committed documentation.
- One target role ARN.
- `sts:AssumeRole` only.
- No wildcard resource.
- No admin permission.
- No broad IAM permission.
- No downstream AWS action permission required for the proof.

## Credential Handling

Credential checklist:

- [ ] Create or access credentials only outside the IAMScope repository.
- [ ] Never paste credentials into docs.
- [ ] Never paste credentials into prompts.
- [ ] Never paste credentials into logs.
- [ ] Never paste credentials into JSON outputs.
- [ ] Never paste credentials into Markdown outputs.
- [ ] Never commit credentials.
- [ ] Store credentials only in AWS CLI config/credential store or an approved secret store.
- [ ] Use a dedicated local profile, such as `iamscope-positive-source`.
- [ ] Do not use production profiles.
- [ ] Do not reuse unrelated admin profiles.
- [ ] Rotate or delete credentials after proof if temporary.
- [ ] Record only safe metadata and rotation status.

Forbidden credential material:

- Access keys.
- Secret access keys.
- Session tokens.
- Credential objects.
- Credential-shaped fields.

## Teardown Checklist

After any future setup and proof, or if the setup is abandoned, confirm:

- [ ] Source access keys are deleted or disabled if they were created.
- [ ] Temporary source principal is removed if no longer needed.
- [ ] Temporary target role is removed if no longer needed.
- [ ] Trust relationship is removed if it was temporary.
- [ ] Local profile is removed if temporary.
- [ ] No lingering broad permissions remain.
- [ ] No production principal was introduced.
- [ ] No downstream permissions remain solely for the proof.
- [ ] Only a safe teardown summary is recorded.
- [ ] No raw AWS logs are committed.
- [ ] No credential material is committed.

If any teardown item cannot be completed, record the gap as safe metadata and do not proceed to additional live proofing until it is resolved or explicitly accepted.

## Artifact Handling

Artifact rules:

- Setup outputs, if any, go to `/tmp` or another caller-provided path.
- No raw AWS logs.
- No access keys.
- No secrets.
- No tokens.
- No credential objects.
- No Terraform state, cache, provider, or plan artifacts.
- No `collect/` directories.
- No generated outputs committed by default.
- Safe summaries only if later explicitly reviewed.

Safe summary examples, if later approved:

- `setup_summary.json`
- `setup_report.md`

Safe summaries may contain only non-secret metadata such as test account ID, source principal ARN, target role ARN, high-level trust summary, high-level permission summary, teardown status, and evidence-boundary caveats.

## Future Pre-Live Validation

After the manual setup exists, a future pre-live slice must:

- [ ] Collect exact test account ID.
- [ ] Collect exact source principal ARN.
- [ ] Collect exact target role ARN.
- [ ] Collect exact local profile name.
- [ ] Confirm expected outcome is `assumed`.
- [ ] Confirm session duration is `900` seconds or less.
- [ ] Confirm no downstream actions are configured.
- [ ] Confirm no raw debug logging is requested.
- [ ] Create the positive proof plan under `/tmp`.
- [ ] Run the dry-run STS probe plan validator.
- [ ] Run the STS executor in `simulate` mode.
- [ ] Confirm dry-run validation produced no AWS calls.
- [ ] Confirm simulation produced no AWS calls.
- [ ] Confirm generated validation and simulation outputs are under `/tmp` or another caller-provided path.
- [ ] Confirm no credentials or credential-shaped fields appear in outputs.
- [ ] Confirm `ready_for_live_proof` as yes or no.
- [ ] Do not run `live_probe` until separately approved.

## What This Checklist Enables

This checklist enables only:

- Safer manual creation of a test-only positive STS setup later.
- Repeatable human review before a positive proof.
- Reduced credential leakage risk.
- Reduced raw artifact leakage risk.
- Clear separation between setup, pre-live validation, and any future live proof.

## What This Checklist Does Not Prove

This checklist does not prove:

- A positive proof.
- Successful AssumeRole.
- Production readiness.
- Broad runtime exploitability.
- Downstream authorization.
- Arbitrary IAMScope correctness.
- Resource-policy Deny support.
- Finding-level resource-policy reachability.
- Enterprise coverage.
- Persistence.
- Impact.

The current runtime evidence remains the documented denied single-case proof only.

## Recommended Next Slice

Recommended next slice: decide whether to perform the manual setup outside IAMScope, or stop runtime proofing after the denied proof.

That next slice should be a decision/review slice. It must not recommend immediate live proof, Terraform apply, production account testing, downstream AWS actions, broad runtime validation, CI gating, composite scoring, or multiple slices at once.
