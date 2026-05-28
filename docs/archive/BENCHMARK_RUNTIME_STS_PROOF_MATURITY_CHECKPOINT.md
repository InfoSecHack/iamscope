# Benchmark Runtime STS Proof Maturity Checkpoint

## Current Runtime Proof Maturity Summary

The runtime STS proof phase is complete enough for this phase.

IAMScope now has one denied single-case live STS proof and one assumed single-case live STS proof, both documented as bounded runtime-probe evidence. The phase demonstrates that the runtime STS proof track can exercise the live executor in narrowly scoped test conditions while preserving credential sanitization and keeping runtime evidence separate from broader benchmark claims.

This is docs/checkpoint only. It does not run live AWS, call STS AssumeRole, create or modify IAM resources, change executor logic, change validator logic, change collector/reasoner/scorer/scenario-validation logic, change benchmark logic, change threshold/comparator/reporting/harness logic, add raw artifacts, commit `/tmp` outputs, commit credentials, add CI gates, add pass/fail benchmark labels, add composite scoring, claim production readiness, claim broad IAMScope correctness, or claim broad runtime exploitability.

## Proofs Completed

### Denied Single-Case Proof

Sanitized denied proof summary:

- Source principal: `arn:aws:iam::516525145310:user/iamscope-admin`
- Target role: `arn:aws:iam::516525145310:role/arf-rt-DevRole`
- Expected outcome: `denied`
- Observed result: `denied`
- `credentials_obtained=false`
- Downstream AWS actions: none

Evidence boundary:

- This proves only that this one source principal could not assume this one target role under the exact tested conditions.
- It does not prove production readiness, broad runtime exploitability, downstream authorization, broad IAMScope correctness, generic resource-policy Deny support, or finding-level resource-policy reachability.

### Positive Single-Case Proof

Sanitized positive proof summary:

- Source principal: `arn:aws:iam::516525145310:user/iamscope-positive-source`
- Target role: `arn:aws:iam::516525145310:role/iamscope-positive-target-role`
- Expected outcome: `assumed`
- Observed result: `assumed`
- `credentials_obtained=true`
- Raw credentials emitted: no
- Downstream AWS actions: none
- Positive test resources torn down

Evidence boundary:

- This proves only that this one isolated test source principal could assume this one isolated test target role under explicit test conditions.
- It also shows the executor reported `credentials_obtained=true` without emitting raw credential material for this one proof.
- It does not prove downstream AWS authorization, production readiness, broad runtime exploitability, arbitrary IAMScope correctness, generic resource-policy Deny support, or finding-level resource-policy reachability.

## What The Runtime Proof Phase Proves

The completed runtime STS proof phase proves only:

- IAMScope can perform one bounded STS AssumeRole runtime probe under explicit test conditions.
- IAMScope can classify a denied live STS result.
- IAMScope can classify an assumed live STS result.
- IAMScope can preserve credential sanitization when credentials are obtained.
- IAMScope can keep runtime probe evidence separate from broad benchmark claims.

These are runtime-probe evidence points, not broad correctness or production-readiness claims.

## What Remains Unproven

The runtime STS proof phase does not prove:

- Production readiness.
- Broad runtime exploitability.
- Downstream authorization.
- Arbitrary IAMScope correctness.
- Generic resource-policy Deny support.
- Finding-level resource-policy reachability.
- Enterprise coverage.
- Persistence.
- Impact.
- Multi-account runtime stability.
- Multi-day runtime stability.
- CI gating validity.

## Artifact And Safety Summary

Artifact and safety status:

- No raw credentials committed.
- No `/tmp` proof outputs committed.
- No downstream AWS actions were performed.
- Positive test resources were torn down.
- No composite score was introduced.
- No pass/fail benchmark labels were introduced.

The recorded proof results are sanitized summaries only. They intentionally omit raw JSON/Markdown proof outputs, raw AWS logs, raw credentials, tokens, secrets, and credential-shaped fields.

## Relationship To The Benchmark Program

Runtime proofs are a separate evidence track from the benchmark program.

They complement but do not replace:

- Live frozen semantic benchmarks.
- Mutation-pair evidence.
- Synthetic scalability fixtures.
- Offline reporting and comparison.
- Report-only threshold review.

Runtime STS proofs do not expand broad semantic correctness claims. They show that one denied and one assumed STS runtime path can be exercised under explicit test conditions while preserving the runtime evidence boundary.

## Recommended Next Phase

Recommended next phase: stop runtime proof expansion and perform a research-readiness / external presentation review.

Do not recommend more live STS probes by default, CI gates, production testing, downstream AWS actions, Terraform expansion, broad runtime validation, composite scoring, or multiple next phases.

Reason:

- The runtime proof phase now has both denied and assumed single-case proofs.
- The next risk is overbuilding or overclaiming, not lack of one more probe.
- A research-readiness / external presentation review can decide how to present runtime evidence without inflating it into production-readiness or broad exploitability claims.
