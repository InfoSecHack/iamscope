# Benchmark Milestone Review

## Current Milestone

- Latest frozen snapshot: `benchmarks/snapshots/phase0-20260509-env27`
- Evaluated cases: `24`
- Result: `24` passed / `0` failed / `0` blocked promotions
- Corpus decision: `hold_review`
- Validation baseline on current main: `./scripts/check.sh` passes and `./scripts/test_fast.sh` passes with `1538` tests.

This milestone is bounded benchmark evidence. It does not claim broad IAMScope correctness, broad AWS production readiness, complete IAM/SCP/trust-condition/PassRole/cross-account trust coverage, or a composite score.

## What Changed Since The Original Phase 0 Corpus

The corpus now includes ten bounded mutation-style pairs:

- Env03 -> Env16: identity Deny removed.
- Env05 -> Env09: permission boundary removed.
- Env08 -> Env10: trust condition removed.
- Env14 -> Env15: permission condition removed.
- Env13 -> Env17: SCP removed.
- Env18 -> Env19: Lambda PassRole validates when `iam:PassRole` can be used for Lambda; it remains non-validated and becomes precondition-only when `iam:PassedToService` is scoped away to `ec2.amazonaws.com`.
- Env20 -> Env21: ECS PassRole validates when `iam:PassRole` can be used for ECS tasks; it remains non-validated and becomes precondition-only when `iam:PassedToService` is scoped away to `ec2.amazonaws.com`.
- Env22 -> Env23: cross-account AssumeRole validates when target trust allows Alice; it remains non-validated for Alice when target trust is scoped to `env23-decoy`.
- Env24 -> Env25: S3 resource-policy Allow to the reader emits a scenario-edge-level resource-policy edge; when the Allow is scoped to `env25-decoy`, the reader edge is absent and the decoy edge remains present.
- Env26 -> Env27: same-account 3-hop AssumeRole validates; when the middle trust is scoped to `env27-decoy`, the Alice-to-admin path remains non-validated.

It also includes Env22, a validated cross-account AssumeRole / `cross_account_trust` case where caller-side permission, target-side exact trust, same-org evidence, and admin-equivalent target role evidence align. Env23 is the scoped-away trust mutation: Alice retains caller-side permission, but the target role trusts a decoy principal, so Alice has no validated cross-account admin path.

It also includes Env24/Env25, a scenario-edge-level S3 resource-policy Allow pair. Env24 records the reader resource-policy edge. Env25 scopes the Allow to a decoy principal and records the reader edge absent with the decoy edge present. This pair does not claim finding-level resource-policy reachability or generic resource-policy Deny support.

It also includes Env26/Env27, a controlled same-account multihop pair. Env26 records a validated 3-hop Alice-to-admin AssumeRole chain. Env27 preserves the same shape but scopes the middle trust to `env27-decoy`, so the Alice path does not validate. This pair does not claim arbitrary enterprise graph correctness, deeper-chain behavior, or cross-account multihop behavior.

It also includes stability evidence snapshots for Env03, Env05, Env06, Env07, Env18, Env19, Env20, and Env21. Stability evidence is per-case and per-recorded run count only; it is not a global stability claim.

The mutation-pair report at `benchmarks/pair-reports/phase0-20260509-env27-mutation-pairs.md` summarizes expected vs observed deltas for all ten pairs. It emits no composite score and is bounded evidence only, not a broad IAMScope correctness or production-readiness claim.

The synthetic degradation benchmark family is tracked in `docs/specs/benchmark-degradation-family-design.md`. Implemented cases DEG07, DEG01, DEG02, DEG03, DEG04, DEG05, and DEG06 complement the live corpus by proving missing artifacts, missing witness edges, stripped blocker evidence, stripped condition evidence, malformed/partial policy parse evidence, and skipped-account partial collection are explicit benchmark failures or non-promotable states. These cases are not live AWS corpus cases, emit no composite score, and remain bounded evidence only.

## Review Position

The current benchmark set is coherent as a controlled live AWS benchmark milestone. It demonstrates that IAMScope can avoid overclaiming on selected blocked/conditioned paths, can validate the matching positive mutation paths when the guardrail is removed, can avoid validating Lambda and ECS PassRole paths when `iam:PassedToService` excludes the target service, can validate one narrow cross-account AssumeRole path when the required evidence aligns, can preserve scenario-edge-level S3 resource-policy Allow principal scoping without claiming finding-level resource-policy reachability, and can distinguish one controlled same-account multihop chain from its middle-trust-scoped-away mutation.

The correct review posture remains bounded:

- Treat these as narrow benchmark cases, not a full product-readiness suite.
- Keep future corpus additions as separate slices with live evidence and frozen summaries.
- Do not infer broad SCP, permission-boundary, identity-Deny, trust-condition, permission-condition, PassRole, cross-account trust, multihop-chain, resource-policy Allow, or resource-policy Deny correctness from these cases alone.
