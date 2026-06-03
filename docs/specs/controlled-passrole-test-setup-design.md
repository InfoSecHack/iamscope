# Controlled PassRole Test Setup Design

## Purpose

Define the minimal test-only setup path needed for a future controlled PassRole validation using either a current live profile or a new explicitly test-only principal.

This is a docs/design slice only. It does not run live AWS, call `iam:PassRole`, launch services, create or modify AWS resources, run Terraform, create credentials, or change IAMScope behavior.

## Current Blocker

Controlled PassRole candidate selection found no ready live-profile-matched candidate:

- Env18 and Env20 are the strongest committed sanitized PassRole candidates.
- Env18 source principal is `arn:aws:iam::<redacted-aws-account-id>:user/iamscope-test/env18-alice`.
- Env20 source principal is `arn:aws:iam::<redacted-aws-account-id>:user/iamscope-test/env20-alice`.
- Current available `iamscope-test` profile resolves to `arn:aws:iam::<redacted-aws-account-id>:user/iamscope-verify`, not either Alice principal.
- No committed sanitized PassRole evidence currently maps to `iamscope-admin`, `iamscope-verify`, or the known assumed-role profiles.

Source: `docs/specs/controlled-passrole-candidate-selection.md`.

## Non-Goals

This design is not:

- Implementation.
- Live AWS execution in this PR.
- `iam:PassRole` execution.
- Service launch.
- AWS resource creation in this PR.
- Terraform apply.
- Production testing.
- Broad exploitability proof.
- Production readiness.
- Composite scoring.
- A change to Env18 or Env20 benchmark semantics.

## Setup Options

| Option | Safety | Evidence Value | Setup Cost | Artifact Risk | Credential Risk | Overclaim Risk | Env18/Env20 Preservation |
| --- | --- | --- | --- | --- | --- | --- | --- |
| A. Map/create local profile for existing Env18/Env20 Alice principal | Medium; safe only if the principal already exists and is explicitly test-only | High continuity with existing sanitized benchmark evidence | Medium; requires identity/profile verification and possible credential handling | Medium; profile setup and read-only summaries must remain outside repo | Medium; access keys or SSO/profile state may be needed | Medium; could be mistaken as validating all Env18/Env20 behavior | Preserves benchmark evidence if no policies/trust are changed |
| B. Design new isolated test-only PassRole source principal and target role/service principal pair | Highest if scoped narrowly and created only in a controlled lab | High for one new controlled PassRole validation path; lower continuity with Env18/Env20 | Medium; requires setup checklist and later reviewed resource creation | Low to medium; setup summaries can be sanitized and kept out of repo | Medium; credentials must be created outside repo if needed | Low if docs clearly state one test-only path only | Fully preserves Env18/Env20 because it does not mutate them |
| C. Modify Env18/Env20 evidence or trust/policy to match `iamscope-verify` or `iamscope-admin` | Low; mutates benchmark semantics to fit current profiles | Ambiguous; may invalidate historical benchmark meaning | Medium to high; requires careful evidence regeneration | High; risks stale or misleading committed summaries | Medium | High; makes benchmark changes look like validation evidence | Does not preserve existing Env18/Env20 semantics |
| D. Stop PassRole controlled validation for now | Highest operational safety | Low; avoids new PassRole runtime evidence | Low | Lowest | Lowest | Low | Preserves Env18/Env20, but leaves live-profile validation unresolved |

## Recommended Setup Path

Recommend exactly one setup path: design a new isolated test-only PassRole source principal and target role/service-principal pair.

This is more conservative than mutating Env18 or Env20 to match current live profiles. It preserves existing benchmark semantics and creates a deliberately bounded future validation target with explicit non-claims.

## Proposed Isolated Setup

Placeholder/test-only names for the future setup:

- Source principal: `iamscope-passrole-positive-source`.
- Target role: `iamscope-passrole-target-role`.
- Service principal: `lambda.amazonaws.com`.
- Local profile: `iamscope-passrole-positive-source`.
- Expected behavior: `allowed`.

`lambda.amazonaws.com` is the preferred first service principal because it is explicit and already appears in the Env18 sanitized benchmark pattern. This design does not authorize Lambda creation or invocation.

## Permission and Trust Design

The future test-only setup should satisfy these constraints:

- The source principal has `iam:PassRole` only on the selected target role.
- The target role trust policy allows exactly the selected service principal.
- No admin permissions are attached to the source principal.
- No broad wildcard role or resource is used unless explicitly reviewed in a later design.
- No downstream service execution is part of the validation by default.
- No service launch is attempted unless separately designed and approved in a future slice.
- Any account, region, and naming choices are documented before setup execution.

## Future Evidence Method

Recommended future evidence method:

1. Static source permission and target trust corroboration first.
2. Optional IAM simulation only if separately designed, scoped, and approved.
3. No service launch by default.

The initial goal is to produce one controlled PassRole validation report from bounded evidence, not to prove downstream service execution.

## Credential and Profile Handling

Any future credential/profile setup must follow these requirements:

- Credentials are created only outside the repository if needed.
- No credentials appear in docs, prompts, logs, commits, generated reports, or `/tmp` artifacts intended for review.
- A dedicated local profile is used for the test-only source principal.
- Production profiles are not used.
- A rotation and teardown plan is defined before credentials are created.
- Profile names and account identifiers are recorded only as sanitized summary metadata unless separately approved.

## Artifact Handling

Future setup and validation artifacts must follow these boundaries:

- Setup summaries go to `/tmp` or a caller-provided path by default.
- Raw AWS logs are not committed.
- Credentials and credential-shaped values are not committed.
- Terraform state/cache/provider artifacts are not created for this design and must not be committed.
- Generated outputs are not committed by default.
- Any committed checkpoint must be a sanitized summary only.

## Teardown Plan

A future setup checklist must include teardown before any resources are created:

- Delete or disable source access keys if any are created.
- Remove the temporary source principal.
- Remove the temporary target role.
- Remove or unset the temporary local profile if it was created only for validation.
- Record a sanitized teardown summary only.
- Do not commit raw deletion logs, credentials, or `/tmp` outputs.

## What Future Validation Would Prove

A future validation using this setup would prove only that one selected test source, target role, and service-principal PassRole prediction was corroborated, refuted, or left inconclusive under explicit controlled conditions.

It would not prove arbitrary PassRole behavior, downstream service execution, or production exploitability.

## What Remains Unproven

Even if the future isolated setup succeeds, these remain unproven:

- Production readiness.
- Broad exploitability.
- Downstream service execution.
- Broad IAMScope correctness.
- All findings verified.
- Real-world scalability.
- Arbitrary enterprise graph correctness.
- Generic resource-policy Deny support.
- Finding-level reachability.

## Recommended Next Slice

Recommend exactly one next slice: create Terraform-free manual setup checklist for isolated controlled PassRole setup.

That next slice must remain docs/checklist only. It must not create resources, run live AWS, call `iam:PassRole`, launch services, create credentials, add CI gates, add pass/fail labels, add composite scoring, or broaden claims.