# Benchmark Runtime STS Proof Next-Step Review

## Purpose

This review decides whether IAMScope should pursue more runtime STS proofing after the first single-case live STS proof returned `denied`.

Candidate next directions:

- Stop runtime proofing for now.
- Design a positive/assumed single-case proof.
- Perform another denied proof.
- Defer runtime proofing and return to non-live benchmark work.

This is docs/review only. It does not run live AWS, call STS AssumeRole, implement new runtime behavior, modify the executor, modify the dry-run validator, add Terraform, create or modify IAM roles or policies, run a second live probe, add raw artifacts, commit `/tmp` outputs, add CI gates, add pass/fail benchmark labels, add composite scoring, claim production readiness, claim broad IAMScope correctness, or claim broad runtime exploitability.

## Current Proof Summary

The first single-case live STS proof produced a denied result:

- One live STS AssumeRole call was attempted.
- Source principal: `arn:aws:iam::516525145310:user/iamscope-admin`.
- Target role: `arn:aws:iam::516525145310:role/arf-rt-DevRole`.
- Expected outcome: `denied`.
- Observed result: `denied`.
- Safe error category: `access_denied`.
- `credentials_obtained=false`.
- No downstream AWS actions were performed.
- No raw credentials were emitted.
- Output was summarized in documentation; raw `/tmp` artifacts were not committed.

Evidence boundary: this proves only that this one source principal could not assume this one target role under this exact test condition.

## What The Denied Proof Adds

The denied proof adds bounded runtime evidence:

- The executor can perform one bounded STS call under explicit operator control.
- `AccessDenied` can be safely classified as `denied`.
- Credential sanitization was preserved because no credentials were obtained or emitted.
- No downstream AWS actions were needed.
- The live runtime track can produce bounded, reviewable evidence without becoming a benchmark gate.

This is useful evidence for the runtime-probe track, but it is intentionally narrow.

## What The Denied Proof Does Not Add

The denied proof does not add:

- Positive AssumeRole proof.
- Credentials-obtained path proof.
- Downstream authorization proof.
- Production readiness.
- Broad exploitability.
- Arbitrary IAMScope correctness.
- Resource-policy Deny support.
- Finding-level reachability.

It also does not validate broader account layouts, multi-account stability, multi-day stability, downstream action behavior, or general enterprise coverage.

## Candidate Next Options

### A. Stop Runtime Proofing For Now

Evidence value: preserves the denied proof as the only live runtime checkpoint for this phase and avoids accumulating live probes for their own sake.

Safety risk: lowest, because no additional live AWS calls would be made.

Engineering cost: low.

Artifact risk: low; no new live outputs.

Overclaim risk: low, as long as the denied proof remains described as one exact test condition.

Design required first: no implementation design is required, but a final runtime-proof checkpoint would be useful if the project stops here.

What it would still not prove: positive AssumeRole behavior, credentials-obtained sanitization on success, downstream authorization, production readiness, broad runtime exploitability, or broad IAMScope correctness.

### B. Design A Positive/Assumed Single-Case Proof

Evidence value: high for completing the minimal runtime-result pair. It would exercise the `assumed` classification and the `credentials_obtained=true` boolean path without printing credentials.

Safety risk: moderate, because the next live run would intentionally obtain temporary credentials. The protocol must ensure those credentials are never printed, stored, or used downstream.

Engineering cost: moderate. It needs a separate positive-proof protocol before any live run.

Artifact risk: moderate. The live output must remain sanitized, and raw `/tmp` artifacts should not be committed.

Overclaim risk: moderate. A positive AssumeRole result is easier to overstate as exploitability, so the evidence boundary must be especially explicit.

Design required first: yes. A separate positive-proof protocol should define the trust relationship, permission expectation, output handling, abort conditions, and post-run secret inspection before any live call.

What it would still not prove: downstream authorization, production readiness, broad exploitability, arbitrary IAMScope correctness, resource-policy Deny support, finding-level reachability, enterprise coverage, persistence, or impact.

### C. Run Another Denied Proof

Evidence value: low. Another denied proof would mostly repeat the first result unless it targets a deliberately different hypothesis.

Safety risk: low to moderate. A denied proof should not obtain credentials, but it is still another live AWS call.

Engineering cost: low to moderate.

Artifact risk: low to moderate, depending on output handling.

Overclaim risk: moderate if repeated denied proofs start looking like broader negative coverage.

Design required first: yes, if the new denied proof targets a different hypothesis. Otherwise it should be avoided.

What it would still not prove: positive AssumeRole behavior, credentials-obtained sanitization on success, downstream authorization, production readiness, broad exploitability, arbitrary IAMScope correctness, or enterprise coverage.

### D. Return To Non-Live Benchmark Work

Evidence value: potentially high for benchmark maturity, but not for the runtime proof track.

Safety risk: low, because it avoids live AWS.

Engineering cost: variable by benchmark scope.

Artifact risk: lower than live proofing if artifact hygiene remains enforced.

Overclaim risk: moderate if non-live benchmark work is framed as runtime proof. The evidence tracks must remain separate.

Design required first: depends on the selected non-live benchmark slice.

What it would still not prove: positive runtime STS behavior, denied/assumed runtime coverage beyond the single proof already collected, downstream authorization, production readiness, or broad runtime exploitability.

## Positive Proof Criteria

If IAMScope considers a positive/assumed proof, these criteria must be met before any live run:

- Test-only source principal.
- Test-only target role.
- Intentional trust relationship.
- Explicit `sts:AssumeRole` permission.
- No production resources.
- No downstream actions.
- Returned credentials are never printed.
- `credentials_obtained` is recorded as a boolean only.
- No raw credential material appears in JSON or Markdown.
- Separate proof protocol is written before the live run.
- Exact operator confirmation is required.
- Dry-run validation and no-call simulation run first.
- Outputs go to `/tmp` or another caller-provided path and are not committed by default.
- Post-run output inspection checks for credential-shaped fields.

Any positive proof must remain a single-case proof, not broad runtime validation.

## Recommendation

Recommended next slice: design a positive/assumed single-case proof protocol, but do not run it yet.

Rationale:

- The denied proof validated the `denied` runtime path and access-denied sanitization.
- The only runtime path not yet covered by live evidence is the `assumed` classification and `credentials_obtained=true` boolean path.
- A positive proof has higher safety and overclaim risk than another denied proof, so it should be designed separately before any live call.
- Another denied proof would add little evidence relative to its live-call cost.
- Returning to non-live benchmark work is reasonable after the positive-proof decision, but it would leave the live runtime track asymmetrical.

The next slice must be design/protocol only. It must not run live AWS, call STS, add Terraform, create or mutate resources, perform downstream AWS actions, add CI gates, introduce pass/fail benchmark labels, add composite scoring, or broaden runtime-proof claims.

## Non-Claims

This review does not claim:

- Production readiness.
- Broad exploitability.
- Downstream authorization.
- Broad IAMScope correctness.
- Composite scoring.
- CI gate readiness.

The current runtime evidence remains one denied STS proof under one exact test condition.
