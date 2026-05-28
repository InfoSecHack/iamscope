# Benchmark Roadmap / Research-Readiness Review

## Purpose

This review decides what kind of benchmark work is ready to start after the current benchmark/scalability/reporting/comparison/threshold phase.

It is documentation-only. It does not implement benchmark logic, add fixtures, run live AWS, add runtime probes, add CI gates, add pass/fail benchmark labels, add composite scoring, change threshold evaluator logic, change threshold parser logic, change comparator logic, change reporting logic, change scalability harness logic, change collector/scoring/scenario-validation/reasoner logic, copy raw artifacts, or add Terraform artifacts.

Truth before breadth remains the controlling principle. The review separates what IAMScope can currently claim, what the benchmark program proves, what is implied, and what remains unknown. It does not claim production readiness, broad IAMScope correctness, arbitrary enterprise graph correctness, or real-world scalability.

## Current Maturity Assessment

The current benchmark/scalability/reporting/comparison/threshold scaffold is complete enough to pause implementation for this phase.

Current evidence layers:

- Live semantic evidence: `24` evaluated / `24` passed frozen live AWS cases exist in `benchmarks/snapshots/phase0-20260509-env27`.
- Mutation-pair evidence: `10` complete passing mutation pairs provide the strongest live semantic signal because each pair tests a controlled expected delta rather than an isolated result.
- Degradation guardrails: DEG07 and DEG01-DEG06 cover benchmark-framework degradation modes such as missing artifacts, missing edges, missing blocker/condition evidence, malformed policy evidence, and partial/skipped collection.
- Synthetic scalability matrix: `small`, `medium`, `constraint_heavy`, `dense_trust`, `multihop_stress`, and `negative_no_valid_path` cover bounded synthetic baseline, constraint, trust-density, path-depth, and no-valid-path/rejection pressure dimensions.
- Reporting/comparison scaffold: synthetic scalability reports, offline frozen-corpus batch reports, synthetic baseline comparison, and frozen-corpus baseline comparison emit JSON and Markdown in report-only modes.
- Artifact hygiene: `./scripts/check.sh` enforces benchmark artifact hygiene, baseline/golden-output policy exists, and output-path checks cover the reporting/comparator scripts.
- Threshold review layer: threshold policy, threshold config schema, threshold config parser, synthetic threshold evaluator, and frozen-corpus threshold evaluator exist in report-only/advisory form with no gates, pass/fail labels, or composite score.

This maturity is meaningful, but bounded. It supports disciplined regression review and future benchmark planning. It does not support broader claims about production readiness, arbitrary enterprise environments, runtime exploitability, or real-world scalability.

## Evidence Boundaries

What IAMScope can currently claim:

- The named frozen live AWS benchmark cases behave as recorded in the current frozen corpus.
- The implemented mutation pairs demonstrate controlled semantic sensitivity for the named benchmark dimensions.
- The synthetic scalability harness can exercise the implemented bounded fixtures and emit per-fixture JSON/Markdown reports.
- Offline frozen-corpus reporting and baseline comparison can summarize already-frozen safe artifacts without creating new live AWS evidence.
- Threshold configs can be validated and applied to comparison reports in report-only/advisory modes.
- Artifact hygiene and output-path expectations are encoded in checks and tests for the implemented scripts.

What the benchmark program currently proves:

- Specific live semantic mutation-pair deltas are captured for the current phase.
- Bounded stability snapshots exist for the named environments.
- Degradation guardrails catch selected benchmark-framework failure modes.
- Synthetic fixture generation/reporting is deterministic and bounded for the implemented fixture matrix.
- Reporting, comparison, and threshold review outputs can be generated without composite scoring or pass/fail benchmark labels.
- The current artifact hygiene checks prevent tracked raw live artifacts and Terraform state/cache/provider artifacts.

What is implied but not proven:

- The scaffold gives a credible path toward future regression review.
- The mutation-pair pattern is a good foundation for future live semantic benchmark additions.
- Threshold review may become useful for humans reviewing comparison reports, if future thresholds stay explicit and per-metric.
- Runtime validation could add a different kind of evidence, but only if designed with strict safety and evidence boundaries.

What remains unknown:

- Production readiness.
- Broad IAMScope semantic correctness.
- Arbitrary enterprise graph correctness.
- Real-world scalability.
- Runtime exploitability.
- Generic resource-policy Deny support.
- Finding-level resource-policy reachability.
- Broader cross-account variants.
- Multi-day and multi-region stability.
- CI threshold gate validity.
- Runtime validation/probe behavior.

## Stop / Continue Decision

The current phase should stop adding implementation slices. The benchmark program has enough live semantic evidence, synthetic scalability coverage, reporting, comparison, artifact discipline, and report-only threshold review tooling for this phase.

Continuing immediately into more implementation would increase the risk of overbuilding or overclaiming. The next phase should begin with design/research-readiness work, not live AWS implementation, runtime probes, new fixtures, CI gates, or larger synthetic graphs.

## Candidate Next Phases

### Runtime Validation / Probe Design

- Research value: High. Runtime probes would test whether selected assumed paths are operationally usable, which is a distinct evidence type from static reasoning and frozen report comparison.
- Engineering cost: Medium to high. Even non-destructive probes need careful account/profile assumptions, identity scoping, script ergonomics, logging, rollback expectations, and review discipline.
- Risk of overclaiming: High unless explicitly framed as bounded runtime evidence for test identities/resources only.
- Safety risk: High relative to other candidates because probes interact with live AWS. The first design must be non-destructive and must avoid persistence, privilege changes, and production resources.
- Artifact-hygiene risk: Medium. Probe results must avoid raw artifact dumps, credentials, account secrets, and uncontrolled run directories.
- Design needed before implementation: Yes. Runtime validation should not start as code.
- Evidence it would add: Bounded operational evidence that selected STS AssumeRole paths can or cannot be exercised under tightly controlled test conditions.
- What it still would not prove: Production readiness, broad exploitability, arbitrary enterprise graph correctness, real-world scalability, generic resource-policy Deny support, or finding-level resource-policy reachability.

### Multi-Day / Multi-Region Stability Design

- Research value: Medium to high. This would address an explicitly unproven stability boundary.
- Engineering cost: Medium. It needs scheduling, environment consistency, account/region selection, artifact hygiene, and noise handling.
- Risk of overclaiming: Medium. Stability runs can be mistaken for semantic breadth unless the design stays narrow.
- Safety risk: Medium. It may use live AWS repeatedly, but it can stay close to existing read-only/frozen-corpus practices if designed carefully.
- Artifact-hygiene risk: Medium. Repeated run outputs increase the chance of uncontrolled artifacts unless output policy is strict.
- Design needed before implementation: Yes.
- Evidence it would add: Better bounded evidence about repeatability across time and possibly region context.
- What it still would not prove: Production readiness, arbitrary enterprise graph correctness, broad IAMScope correctness, or real-world scalability.

### Broader Cross-Account Variant Design

- Research value: Medium to high. Cross-account behavior is important and current coverage is bounded.
- Engineering cost: Medium to high. It requires careful environment construction, account assumptions, cleanup, and mutation-pair design.
- Risk of overclaiming: High. A few variants could be mistaken for broad cross-account correctness.
- Safety risk: Medium to high because cross-account trust changes and identity assumptions need strict scoping.
- Artifact-hygiene risk: Medium. New live cases must preserve the current snapshot discipline.
- Design needed before implementation: Yes.
- Evidence it would add: Additional bounded mutation-pair evidence for selected cross-account variants.
- What it still would not prove: Arbitrary enterprise graph correctness, broad cross-account correctness, or production readiness.

### Larger Synthetic / Replayed Scalability Design

- Research value: Medium. Larger or replayed workloads could expand performance/regression signals.
- Engineering cost: Medium. Design must define bounded sizes, deterministic generation/replay, report shape, and artifact policy.
- Risk of overclaiming: High. Larger synthetic graphs are easy to overstate as real-world scalability evidence.
- Safety risk: Low if kept offline and synthetic/replayed.
- Artifact-hygiene risk: Medium. Larger generated outputs and baselines can become uncontrolled artifacts.
- Design needed before implementation: Yes.
- Evidence it would add: More stress signals for synthetic or replayed reporting paths.
- What it still would not prove: Real-world scalability, production readiness, live AWS correctness, or arbitrary enterprise graph correctness.

### Resource-Policy Finding-Level Path Design

- Research value: Medium. It would target a known evidence boundary around finding-level resource-policy reachability.
- Engineering cost: High. It likely depends on reasoner support and careful semantic design before benchmark expansion.
- Risk of overclaiming: High. Scenario-edge-level evidence must not be confused with finding-level path support.
- Safety risk: Medium if it eventually requires live AWS cases, but design-only work is low risk.
- Artifact-hygiene risk: Medium for future live cases and snapshots.
- Design needed before implementation: Yes, and reasoner support must exist before benchmark claims expand.
- Evidence it would add: A plan for moving from scenario-edge-level resource-policy evidence toward finding-level path evidence.
- What it still would not prove: Generic resource-policy Deny support, broad IAMScope correctness, arbitrary resource-policy semantics, or production readiness.

### Generic Resource-Policy Deny Design

- Research value: Medium, but only after prerequisite semantics are clear.
- Engineering cost: High. Deny semantics are subtle and could cut across reasoner behavior, scenario validation, and benchmark interpretation.
- Risk of overclaiming: Very high. A narrow Deny case can easily be misread as generic Deny support.
- Safety risk: Medium if future live AWS cases are added, but design-only work is low risk.
- Artifact-hygiene risk: Medium for future snapshots and raw artifact boundaries.
- Design needed before implementation: Yes.
- Evidence it would add: A scoped plan for Deny semantics and benchmark boundaries.
- What it still would not prove: Generic Deny correctness, production readiness, broad IAMScope correctness, or arbitrary enterprise graph correctness.

## Recommended Next Phase

Recommended next phase: runtime validation/probe design.

Reasoning:

- The current benchmark program already has a strong static/frozen/reporting scaffold for this phase.
- Runtime validation is the most distinct remaining evidence type because it could test selected operational assumptions rather than adding another report or synthetic fixture.
- The risk is real, so the next phase must be design-only first.
- Choosing runtime probe design does not authorize immediate runtime probes, live AWS execution, CI gating, or production-readiness claims.

Runtime validation/probe design must be framed as:

- Separate from the reasoning corpus.
- Non-destructive first.
- STS AssumeRole probes first.
- Test identities/resources only.
- No production resources.
- No persistence.
- No privilege changes.
- No destructive actions.
- Strict profile/account assumptions.
- Explicit rollback/cleanup.
- Clear evidence boundaries.
- Not proof of production readiness.
- Not broad exploitability proof.

If runtime validation is later judged too risky during design, the fallback next phase should be multi-day/multi-region stability design. That fallback would still be design-only and should not introduce immediate live AWS implementation.

## Explicitly De-Scoped

This review explicitly de-scopes:

- Immediate live AWS implementation.
- Immediate runtime probes.
- Generic resource-policy Deny.
- Finding-level resource-policy reachability unless reasoner support exists.
- CI threshold gates.
- Composite score.
- Production-readiness claim.
- Arbitrary enterprise graph correctness claim.

## Recommended Next Slice

Recommended next slice: design non-destructive STS AssumeRole runtime validation probes.

This next slice must be design-only, not implementation. It should define safety boundaries, account/profile assumptions, input/output shape, artifact hygiene, rollback/cleanup expectations, and evidence limits before any runtime probe code or live AWS execution is considered.
