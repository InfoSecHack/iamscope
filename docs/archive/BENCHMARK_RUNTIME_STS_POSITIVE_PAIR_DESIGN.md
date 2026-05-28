# Benchmark Runtime STS Positive Pair Design

## Purpose

This document designs a minimal isolated test-only IAM setup that could support one future positive/assumed STS proof.

The design exists because the current positive proof path is blocked: no local profile maps to `arn:aws:iam::516525145310:user/arf-rt-attacker`, and IAMScope should not force live evidence through ad hoc changes to existing roles, trust policies, or credentials.

This is docs/design only. It does not run live AWS, call STS AssumeRole, create IAM users, create IAM roles, modify trust policies, modify permission policies, run Terraform apply, add live AWS environments, create credentials, change executor logic, change the dry-run validator, add raw artifacts, commit `/tmp` outputs, add CI gates, add pass/fail benchmark labels, add composite scoring, claim production readiness, claim broad IAMScope correctness, or claim broad runtime exploitability.

## Non-Goals

This design is not:

- Implementation.
- Terraform apply.
- Live AWS execution.
- IAM mutation in this PR.
- Credential creation.
- Production testing.
- Downstream AWS action testing.
- Broad exploitability proof.
- Production-readiness proof.
- Arbitrary IAMScope correctness proof.
- CI gating.
- Composite scoring.

The design must not be treated as approval to create resources, change IAM, or run a live proof.

## Proposed Isolated Pair

Placeholder setup:

- Source principal: `iamscope-positive-source`
- Target role: `iamscope-positive-target-role`
- Account: test account only
- Expected outcome: `assumed`
- Session duration: `900` seconds or less
- Downstream action permissions: none required beyond the STS proof path

These names are placeholders, not evidence that the resources exist. A future implementation slice must choose final names, confirm the test account, and keep the setup isolated from production identities and production resources.

The intended future proof would attempt exactly one `sts:AssumeRole` call from `iamscope-positive-source` to `iamscope-positive-target-role`, then record only safe summary fields such as `credentials_obtained=true` as a boolean if the call succeeds.

## Trust Policy Design

The target role trust policy should be minimal and explicit.

Required properties:

- Target role trusts exactly the source principal.
- No wildcard principal.
- No production principals.
- No broad account root trust.
- No service principal unless separately designed and justified.
- No cross-account trust unless separately designed and justified.
- Optional `ExternalId` only if separately justified by the test setup.

Illustrative placeholder trust shape:

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

If the source is designed as a role instead of a user, the principal ARN should be the exact role ARN. The trust policy must not use `arn:aws:iam::<TEST_ACCOUNT_ID>:root` as a shortcut because account-root trust is broader than the intended single-principal proof.

## Source Permission Design

The source principal should have only the permission needed for the proof.

Required properties:

- Source principal may call `sts:AssumeRole` only on the single target role.
- No wildcard resources.
- No admin permissions.
- No broad IAM permissions.
- No permission to modify users, roles, policies, or trust relationships.
- No downstream AWS permissions are required for the proof.

Illustrative placeholder source permission shape:

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

No broader resource pattern should be used for this proof.

## Target Role Permission Design

The target role should have the safest possible permission posture.

Preferred target role permissions:

- No permissions attached if AWS and the chosen creation path allow the role to exist without permissions.
- Otherwise, only minimal inert permissions if a future setup mechanism requires a policy attachment.
- No admin permissions.
- No destructive permissions.
- No data-plane access.
- No IAM mutation permissions.
- No list/get/describe permissions for downstream validation.
- No downstream action testing.

The future live proof must not use returned credentials for any downstream AWS action, even if the target role has permissions for unrelated reasons.

## Credential And Profile Handling

Credential handling requirements:

- Dedicated local profile name, such as `iamscope-positive-source`.
- Credential material must never be committed.
- No credentials in JSON outputs.
- No credentials in Markdown outputs.
- No credentials in setup summaries.
- No credentials in logs.
- Credential setup, storage, and rotation are handled outside the IAMScope repository.
- Profile is used only for this test.
- Production profiles must not be reused.
- The profile must be explicitly supplied to the validator and executor.
- If credentials are created, they must have a documented teardown or rotation plan.

The setup should prefer the shortest practical credential lifetime and should avoid long-lived access keys unless a separate design justifies them.

## Setup Artifact Policy

If future implementation creates setup summaries, safe outputs should be limited to:

- `setup_summary.json`
- `setup_report.md`

Safe setup summaries may contain:

- Test account ID.
- Source principal ARN.
- Target role ARN.
- Trust relationship summary.
- Source permission summary.
- Target permission summary.
- Teardown or rotation plan status.
- Evidence-boundary caveats.

Forbidden artifacts:

- Raw access keys.
- Secret access keys.
- Session tokens.
- Credential objects.
- Credential-shaped fields.
- Raw AWS logs.
- Raw AWS CLI outputs with sensitive material.
- Terraform state.
- Terraform cache.
- Terraform providers.
- Terraform plans.
- `collect/` directories.
- Generated outputs committed by default.

Outputs should go to `/tmp` or another caller-provided path by default. If a redacted setup summary is ever committed, it requires a separate artifact-policy review.

## Teardown And Rotation Plan

Any future setup must define teardown and rotation before resources or credentials are created.

Required teardown or rotation controls:

- Delete or disable source credentials after the proof if credentials are created.
- Remove the test source principal if it is no longer needed.
- Remove the test target role if it is no longer needed.
- Verify the target role trust relationship is removed if the setup was temporary.
- Verify no lingering broad permissions remain.
- Record teardown evidence as a safe summary only.
- Do not commit raw AWS logs or credential material.

If the setup is intentionally retained for future bounded tests, retention must be separately justified, time-bounded where possible, and reviewed before reuse.

## Future Implementation Options

### A. Manual Console Or CLI Setup Outside Repo

Safety: moderate. Manual setup can be precise, but it depends on operator discipline and review.

Reproducibility: lower than a codified design because manual steps can drift.

Artifact risk: low if no raw outputs are committed and summaries are manually redacted.

Credential risk: moderate, especially if access keys are created.

Engineering cost: low.

Evidence value: sufficient for one positive proof if the setup is documented before the live run.

Use when: the project wants the smallest setup path and accepts manual review over repeatability.

### B. Terraform Design In A Later PR, Without Apply

Safety: moderate to high if the Terraform is reviewed but never applied in the design slice.

Reproducibility: highest.

Artifact risk: higher because Terraform state/cache/provider/plan artifacts must remain forbidden and uncommitted.

Credential risk: depends on how the source principal is represented and whether credential creation is included.

Engineering cost: moderate to high.

Evidence value: strong setup clarity, but still no runtime proof until a separate live run.

Use when: repeatability and reviewability matter more than keeping the setup lightweight.

### C. Existing Lab Role/User Reuse If Already Test-Only And Intentionally Configured

Safety: variable. It can be safe if the existing resources are test-only, minimal, and intentionally configured for this proof.

Reproducibility: moderate if the existing setup is documented.

Artifact risk: low if no raw outputs or credentials are committed.

Credential risk: moderate if local credentials must be configured.

Engineering cost: low.

Evidence value: useful if the reused pair exactly matches the intended proof boundary.

Use when: the source and target already exist, are test-only, have explicit trust and permission, and do not require ad hoc IAM changes.

Reject when: reuse would blur existing benchmark semantics, require production profiles, require broad permissions, or reinterpret the previous denied proof.

## Recommendation

Recommended next slice: create a Terraform-free manual setup checklist for the isolated positive pair.

That next slice must be docs/checklist only. It must not create resources, create credentials, modify trust policies, attach permissions, run Terraform, run live AWS, call STS, perform downstream AWS actions, add CI gates, add pass/fail benchmark labels, add composite scoring, or recommend broad runtime validation.

Rationale:

- A checklist is the smallest next step that can make the future setup reviewable without performing it.
- Manual setup keeps Terraform artifacts out of scope while the team decides whether the positive proof is worth the setup cost.
- The checklist can force explicit names, account/profile assumptions, trust policy, source permission, credential handling, output paths, and teardown before any live action.
- It preserves the denied proof and avoids mutating existing `arf-rt-DevRole` semantics.

## Relationship To The Denied Proof

The denied proof remains valid and must not be weakened or reinterpreted.

The isolated positive pair would add only `credentials_obtained=true` path evidence for one isolated test pair under explicit conditions.

It would not replace the denied proof, mutation-pair evidence, frozen reasoning evidence, synthetic scalability evidence, reporting/comparison evidence, or threshold review evidence.

## Future Positive Proof Boundary

A future live positive proof using this pair could prove only:

- One test source principal can assume one test target role under explicit conditions.
- Credential sanitization preserved `credentials_obtained=true` as a boolean only.

It would not prove:

- Production readiness.
- Broad runtime exploitability.
- Downstream authorization.
- Arbitrary IAMScope correctness.
- Resource-policy Deny support.
- Finding-level resource-policy reachability.
- Enterprise coverage.
- Persistence.
- Impact.
- Multi-account stability.
- Multi-day stability.

## Non-Claims

This design does not claim:

- The isolated source principal exists.
- The isolated target role exists.
- Credentials were created.
- IAM resources were changed.
- A positive proof was run.
- Broad exploitability.
- Production readiness.
- Broad IAMScope correctness.

The current runtime evidence remains the documented denied single-case proof only.
