# Benchmark Runtime STS Positive Setup Plan

## Purpose

This plan designs the safest test-only setup path for a future positive/assumed single-case STS proof.

The plan exists because the positive proof protocol requires a source principal that is trusted by the target role and explicitly allowed to call `sts:AssumeRole`, but the current local AWS profiles do not resolve to the principal trusted by `arn:aws:iam::<redacted-aws-account-id>:role/arf-rt-DevRole`.

This is design/planning only. It does not run live AWS, call STS AssumeRole, create IAM users, create IAM roles, modify trust policies, modify permission policies, run Terraform, add live AWS environments, implement setup logic, change the STS executor, change the dry-run validator, add raw artifacts, commit `/tmp` outputs, add CI gates, add pass/fail benchmark labels, add composite scoring, claim production readiness, claim broad IAMScope correctness, or claim broad runtime exploitability.

## Non-Goals

This plan is not:

- Implementation.
- Live AWS execution.
- Terraform apply.
- IAM mutation in this PR.
- Credential creation in this PR.
- Production account testing.
- Broad exploitability proof.
- Production-readiness proof.
- Downstream AWS action proof.
- Arbitrary IAMScope correctness proof.
- CI gating.
- Composite scoring.

The setup plan must not be used as permission to make ad hoc IAM or credential changes. Any future setup action requires a separately reviewed implementation slice.

## Current Positive Proof Blocker

Existing target role:

- `arn:aws:iam::<redacted-aws-account-id>:role/arf-rt-DevRole`

Existing target trust policy allows:

- `arn:aws:iam::<redacted-aws-account-id>:user/arf-rt-attacker`

Observed same-account local profiles resolve to:

- `iamscope-test` -> `arn:aws:iam::<redacted-aws-account-id>:user/iamscope-verify`
- `iamscope-admin` -> `arn:aws:iam::<redacted-aws-account-id>:user/iamscope-admin`

No local AWS profile currently resolves to `arn:aws:iam::<redacted-aws-account-id>:user/arf-rt-attacker`, so a positive proof against `arf-rt-DevRole` is not ready.

## Candidate Setup Options

### A. Configure Local AWS Profile For Existing Trusted User `arf-rt-attacker`

This option uses the already trusted source principal for the existing target role.

Requirements:

- `arn:aws:iam::<redacted-aws-account-id>:user/arf-rt-attacker` already exists.
- Credentials for that user are already intended for this test.
- The user has explicit `sts:AssumeRole` permission for `arn:aws:iam::<redacted-aws-account-id>:role/arf-rt-DevRole`.
- No IAM policy changes are required.
- No trust policy changes are required.
- The local profile name is dedicated and clearly test-only.

Evidence value: direct positive test against the existing `arf-rt-DevRole` trust relationship.

Safety risk: moderate, mostly from credential handling and local profile management.

Infrastructure change: lowest if the user and intended test credentials already exist.

Artifact risk: manageable if no credentials, raw AWS logs, or profile material are committed.

Overclaim risk: moderate. The result would still prove only one source principal and one target role under explicit conditions.

Reason to choose: safest only if the trusted user already exists, the credentials are already intended for this test, and no IAM or trust changes are needed.

Reason to reject or defer: unsafe if credentials would need to be created ad hoc, if the user is not clearly test-only, or if policy/trust changes would be needed.

### B. Create Or Design A New Test-Only Positive Principal And Role Pair

This option designs a fresh isolated pair for positive proofing.

Intended shape:

- Source: a new test-only user or role.
- Target: a new test-only role.
- Target trust policy explicitly trusts only the source.
- Source has explicit `sts:AssumeRole` permission only for the target role.
- No production resources.
- No downstream actions.
- One live STS call only in the eventual proof.

Evidence value: cleanest positive proof because the setup can be deliberately minimal, isolated, and reviewable.

Safety risk: moderate. Any future IAM creation or policy attachment must be separately designed, built, frozen, and reviewed.

Infrastructure change: higher than option A because it requires a future build/freeze slice if implemented.

Artifact risk: moderate unless safe setup summaries are the only committed artifacts.

Overclaim risk: moderate. The proof would exercise the credentials-obtained path, but only for one deliberately constructed test pair.

Reason to choose: best default when existing trusted credentials are not already available, because it avoids mutating the semantics of the existing denied proof target.

Reason to reject or defer: if the project wants to stop runtime proofing after the denied proof, or if any IAM creation is not worth the added evidence.

### C. Modify Existing `arf-rt-DevRole` Trust To Include `iamscope-verify` Or `iamscope-admin`

This option would make one currently available profile trusted by the existing target role.

Evaluation: reject or defer.

Reason:

- It mutates existing benchmark/lab semantics.
- It could blur the already documented denied proof for `iamscope-admin`.
- It risks making the positive proof look like evidence about the original trusted principal when it is actually evidence about a modified trust relationship.
- It encourages ad hoc live-evidence chasing rather than a deliberate frozen setup.

Safety risk: higher than options A or B because it changes an existing role relationship.

Infrastructure change: direct IAM/trust mutation, out of scope for this planning slice.

Overclaim risk: high.

This should not be done ad hoc.

### D. Stop Runtime Proofing After The Denied Proof

This option accepts the current denied single-case live proof as sufficient runtime evidence for this phase.

Evidence value: preserves the denied-path live classification evidence already collected.

Safety risk: lowest.

Engineering cost: lowest.

Artifact risk: lowest.

Overclaim risk: lowest if the denied proof remains described narrowly.

What remains unproven: positive AssumeRole behavior, credentials-obtained output sanitization on success, and live positive classification for a test principal/role pair.

Reason to choose: appropriate if the additional evidence from a positive proof is not worth IAM or credential setup risk.

## Recommendation

Recommended path: design a new isolated test-only positive principal/role pair in a separate future design, unless existing `arf-rt-attacker` credentials are already intentionally available and require no IAM or trust-policy changes.

Recommended next slice: design isolated positive STS principal/role pair.

Rationale:

- The current blocker is the absence of a local profile for the principal already trusted by `arf-rt-DevRole`.
- Modifying `arf-rt-DevRole` to trust an available profile would blur the denied proof and mutate existing lab semantics.
- A new isolated pair lets reviewers reason about the positive proof without reinterpreting the denied proof.
- If `arf-rt-attacker` credentials already exist and are intentionally available for this test, option A may be safer than creating new IAM resources, but that requires a separate checklist/review before use.

The next slice must remain design-only. It must not run live AWS, call STS, create users, create roles, modify trust policies, attach permissions, run Terraform, perform downstream action testing, add CI gates, add pass/fail labels, add composite scoring, or recommend broad runtime validation.

## Required Controls For Any Future Positive Setup

Any future positive setup must require:

- Test account only.
- Test principal only.
- Test role only.
- Explicit target trust for the source principal.
- Explicit `sts:AssumeRole` permission for the source principal.
- No admin permissions required for the proof principal.
- No production markers by default.
- No downstream AWS actions.
- Short session duration.
- Dedicated local profile name.
- No credential material committed.
- No raw AWS outputs committed.
- Clear teardown or credential-rotation plan if credentials are created.
- Exact operator confirmation before any live proof.
- Dry-run validation and no-call simulation before any live proof.

## Minimal Future Setup Artifact Model

If a future design/build creates setup artifacts, allowed safe outputs should be limited to:

- `setup_summary.json`
- `setup_report.md`

Safe setup summaries may include:

- Test account ID.
- Source principal ARN.
- Target role ARN.
- High-level trust relationship summary.
- High-level permission summary.
- Teardown or rotation status.
- Evidence-boundary caveats.

Forbidden setup artifacts:

- Raw access keys.
- Secret access keys.
- Session tokens.
- Credentials objects.
- Credential-shaped fields.
- Raw AWS debug logs.
- Terraform state, cache, providers, or plans.
- Raw AWS CLI output containing sensitive material.
- Generated outputs committed by default.

If a redacted setup summary is ever committed, it requires a separate artifact-policy review.

## Relationship To The Previous Denied Proof

The denied proof remains valid and must not be weakened or reinterpreted.

The denied proof showed only that `arn:aws:iam::<redacted-aws-account-id>:user/iamscope-admin` could not assume `arn:aws:iam::<redacted-aws-account-id>:role/arf-rt-DevRole` under the exact tested conditions.

A future positive proof would add only credentials-obtained path evidence for one test principal and one test role under explicit conditions.

A future positive proof would not replace mutation-pair evidence, static benchmark evidence, frozen reasoning evidence, synthetic scalability evidence, reporting/comparison evidence, or threshold review evidence.

## What A Future Positive Proof Would Prove

If a future positive setup is designed, implemented, validated, simulated, and then used in a separately approved live proof, it could prove only:

- One specific test principal could assume one specific test role under explicit conditions.
- The executor's `credentials_obtained=true` boolean path works without emitting credentials.
- Output sanitization remains intact for one successful STS AssumeRole result.

## What Remains Unproven

A future positive proof would not prove:

- Production readiness.
- Broad runtime exploitability.
- Downstream AWS authorization.
- Arbitrary IAMScope correctness.
- Resource-policy Deny support.
- Finding-level resource-policy reachability.
- Enterprise coverage.
- Persistence.
- Impact.
- Multi-account stability.
- Multi-day stability.

## Non-Claims

This setup plan does not claim:

- A positive proof was run.
- IAM resources were created.
- IAM policies were changed.
- Trust policies were changed.
- Credentials were created.
- Existing `arf-rt-attacker` credentials are available.
- Broad exploitability.
- Production readiness.
- Broad IAMScope correctness.

The current runtime evidence remains the documented denied single-case proof only.
