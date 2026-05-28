# Benchmark Research Readiness External Review

## Purpose

This review assesses whether IAMScope is ready for external research presentation or discussion based on the completed benchmark, scalability, reporting, threshold, artifact-discipline, and runtime STS proof evidence layers.

This is docs/review only. It does not implement new benchmark logic, add fixtures, run live AWS, call STS AssumeRole, add runtime probes, change executor logic, change validator logic, change collector/reasoner/scorer/scenario-validation logic, change threshold/comparator/reporting/harness logic, add Terraform, add raw artifacts, commit `/tmp` outputs, add CI gates, add pass/fail benchmark labels, add composite scoring, claim production readiness, claim broad IAMScope correctness, claim arbitrary enterprise graph correctness, claim broad runtime exploitability, or claim real-world scalability.

## Core Claim Candidate

Conservative external-facing claim:

> IAMScope has a bounded evidence program showing deterministic reasoning behavior across frozen live AWS cases, mutation-pair sensitivity, synthetic degradation and scalability fixtures, offline reporting/comparison, report-only threshold review, and narrow runtime STS corroboration.

This claim intentionally does not say:

- Production ready.
- Broadly correct.
- Enterprise-scale validated.
- Exploitability proven.
- Real-world scalable.
- Complete IAM reasoning.

Recommended qualifier:

> The evidence is deliberately bounded: it supports discussion of specific frozen cases, controlled mutation pairs, deterministic synthetic fixtures, report generation, advisory threshold review, artifact discipline, and two narrow STS runtime probes. It does not certify production readiness or broad IAM correctness.

## Evidence Inventory

### Live Semantic Cases

Current live semantic evidence includes:

- `24/24` frozen live AWS cases.
- Stability coverage.
- Degradation guardrails.
- Frozen snapshot and reports retained as bounded evidence, not broad production claims.

### Mutation Pairs

Current mutation-pair evidence includes:

- `10` complete mutation pairs.
- Mutation-pair sensitivity is the primary live semantic evidence unit.
- The pairs support claims about named live case deltas, not arbitrary IAM graphs.

### Degradation Guardrails

Current degradation evidence includes:

- Guardrails for missing artifacts, missing edges, missing blocker/condition evidence, malformed or partially parsed policy evidence, and partial or skipped collection scenarios.
- These are benchmark-framework guardrails, not live AWS exploitability claims.

### Synthetic Scalability Matrix

Implemented synthetic fixtures:

- `small`
- `medium`
- `constraint_heavy`
- `dense_trust`
- `multihop_stress`
- `negative_no_valid_path`

These fixtures provide deterministic synthetic pressure coverage. They do not prove real-world scalability.

### Reporting And Comparison

Completed reporting/comparison evidence:

- Synthetic JSON and Markdown reporting.
- Frozen-corpus JSON and Markdown reporting.
- Synthetic baseline comparator.
- Frozen-corpus baseline comparator.
- Report-only outputs.
- No pass/fail benchmark behavior.
- No composite score.

### Artifact Hygiene

Completed artifact discipline:

- Artifact hygiene remains enforced in `./scripts/check.sh`.
- Baseline/golden-output policy exists.
- Output-path checks exist.
- `.agent` workflow harness exists.
- Raw AWS artifacts, credentials, Terraform state/cache/provider artifacts, uncontrolled generated outputs, and raw `/tmp` proof outputs remain out of committed evidence by default.

### Threshold Review

Completed threshold review evidence:

- Threshold policy.
- Threshold config schema.
- Threshold config parser.
- Synthetic threshold evaluator.
- Frozen-corpus threshold evaluator.
- All threshold evaluation remains report-only/advisory.
- No threshold gates.
- No pass/fail labels.
- No composite score.

### Runtime STS Proof

Completed runtime STS proof evidence:

- One bounded denied proof:
  - `iamscope-admin` -> `arf-rt-DevRole`
  - Expected: `denied`
  - Observed: `denied`
  - `credentials_obtained=false`
  - Downstream AWS actions: none
- One bounded assumed proof:
  - `iamscope-positive-source` -> `iamscope-positive-target-role`
  - Expected: `assumed`
  - Observed: `assumed`
  - `credentials_obtained=true`
  - Raw credentials emitted: no
  - Downstream AWS actions: none
  - Positive test resources torn down

Runtime STS proof evidence is a separate evidence track and does not replace frozen reasoning evidence.

## What This Proves

The completed evidence program proves only:

- Deterministic benchmark and reporting machinery exists.
- Mutation-pair sensitivity exists for frozen live cases.
- Synthetic scalability and degradation coverage exists.
- Offline reports and comparators exist.
- Threshold review can be performed without gates or composite scores.
- STS runtime probing can classify one denied and one assumed case under explicit test conditions.
- Credential sanitization was preserved in the positive runtime proof.
- Artifact hygiene and caller-provided output-path discipline are part of the program.

These proof points are bounded and should be presented as such.

## What This Does Not Prove

This evidence program does not prove:

- Production readiness.
- Broad IAMScope correctness.
- Arbitrary enterprise graph correctness.
- Real-world scalability.
- Broad runtime exploitability.
- Downstream AWS authorization.
- Generic resource-policy Deny support.
- Finding-level resource-policy reachability.
- Enterprise coverage.
- Multi-day or multi-region runtime stability.
- CI threshold gate validity.

These unknowns should stay visible in any external presentation.

## External Presentation Framing

### Paper Or Research Talk

Recommended language:

> We evaluate IAMScope through a deliberately bounded evidence program: frozen live AWS cases, mutation pairs, deterministic synthetic scalability and degradation fixtures, offline report/comparison tooling, report-only threshold review, and two narrow STS runtime probes. The goal is truth before breadth: demonstrate specific behaviors under controlled conditions while keeping production readiness and broad correctness out of scope.

Avoid:

- “IAMScope is production ready.”
- “IAMScope proves exploitability.”
- “IAMScope handles enterprise-scale IAM.”
- “The benchmark score is...”

### README Or Repo Summary

Recommended language:

> IAMScope includes a bounded benchmark and evidence scaffold for reviewing specific IAM reasoning behaviors. Current evidence covers frozen live AWS cases, mutation-pair sensitivity, deterministic synthetic fixtures, offline reporting/comparison, advisory threshold review, artifact hygiene, and two sanitized STS runtime proof records.

Add nearby caveat:

> These artifacts do not establish production readiness, broad IAM correctness, real-world scalability, downstream authorization, or broad exploitability.

### Conference Or Demo Explanation

Recommended language:

> The demo uses frozen reports and sanitized evidence records by default. It shows how IAMScope separates live semantic evidence, synthetic pressure fixtures, offline reporting, advisory threshold review, and narrow runtime STS proof records.

Demo caveat:

> We do not rerun live AWS probes during the presentation unless separately approved. Runtime proof summaries are evidence records, not live exploit demonstrations.

### Reviewer Response

Recommended language:

> We intentionally avoid a composite score because it would collapse different evidence types into a misleading single number. Instead, we report per-case, per-fixture, per-comparison, and per-probe evidence with explicit caveats.

Recommended response to scope concerns:

> The current evidence is strong enough to support research discussion of the implemented benchmark scaffold and controlled behaviors, but not broad production-readiness or arbitrary enterprise correctness claims.

## Demo Readiness Recommendation

A demo is advisable only if it stays safe and evidence-bound.

Safe demo recommendation:

- No live AWS by default.
- Use frozen reports and sanitized summaries.
- Show denied and assumed runtime proof summaries only as evidence records.
- Do not rerun live probes during presentation unless separately approved.
- Do not show raw `/tmp` outputs.
- Do not show credentials or credential-shaped fields.
- Do not present threshold review as CI gating.
- Do not present synthetic scalability as real-world scalability.
- Do not present runtime STS proof as broad exploitability.

Recommended demo content:

- Live semantic summary table.
- Mutation-pair examples.
- Synthetic fixture matrix.
- Example JSON/Markdown reports.
- Comparator output examples.
- Report-only threshold summary.
- Sanitized denied/assumed STS proof summaries.
- Explicit “what remains unproven” slide.

## Risks

### Overclaim Risk

Risk: external audiences may hear “24/24,” “thresholds,” or “runtime proof” as broad correctness or production readiness.

Mitigation: keep claims tied to named evidence layers and repeat that the evidence is bounded.

### Live AWS Safety Risk

Risk: a live demo could accidentally call AWS, require credentials, or look like exploit execution.

Mitigation: use frozen reports and sanitized summaries by default. Do not rerun live probes unless separately approved.

### Artifact Leakage Risk

Risk: raw AWS logs, `/tmp` outputs, credentials, Terraform state, or raw benchmark artifacts could leak into presentation material.

Mitigation: use only reviewed, sanitized, committed summaries and safe generated reports.

### Audience Misunderstanding Risk

Risk: audiences may conflate static reasoning evidence, synthetic scalability, threshold review, and runtime proof evidence.

Mitigation: present each evidence layer separately and label its boundaries.

### Benchmark-As-Score Risk

Risk: pressure to summarize the program with a composite score could obscure failures, unavailable metrics, and evidence boundaries.

Mitigation: explicitly reject composite scoring and use per-case/per-fixture/per-probe records.

### Runtime Proof Misinterpretation Risk

Risk: two STS runtime proofs may be mistaken for broad exploitability or downstream authorization.

Mitigation: state that the denied and assumed proofs cover only one source/target pair each under explicit conditions, with no downstream actions.

## Recommended External Artifacts

Safe artifacts for external review:

- Maturity checkpoint docs.
- Sanitized runtime proof summaries.
- Frozen benchmark reports.
- Synthetic scalability reports.
- Comparator outputs.
- Report-only threshold summaries.
- Artifact policy docs.
- Evidence-boundary tables.

Do not include:

- Raw AWS artifacts.
- Credentials.
- Tokens.
- Secrets.
- Raw `/tmp` outputs.
- Terraform state.
- Terraform cache.
- Terraform providers.
- Raw collect directories.
- Composite scores.

## Reviewer Questions And Answers

### What does this prove?

It proves the existence and behavior of a bounded evidence program: deterministic benchmark/reporting machinery, mutation-pair sensitivity for frozen cases, synthetic degradation/scalability fixtures, offline reporting/comparison, report-only threshold review, and two narrow STS runtime classifications.

### What does it not prove?

It does not prove production readiness, broad IAMScope correctness, arbitrary enterprise graph correctness, real-world scalability, broad runtime exploitability, downstream AWS authorization, generic resource-policy Deny support, finding-level resource-policy reachability, enterprise coverage, multi-day/multi-region runtime stability, or CI threshold gate validity.

### Why no composite score?

Because a composite score would combine unlike evidence layers and obscure the truth boundaries. IAMScope reports evidence per case, per mutation pair, per synthetic fixture, per comparator, per threshold result, and per runtime probe.

### Why synthetic scalability?

Synthetic scalability provides deterministic pressure dimensions that are useful for regression and design discussion. It is not presented as real-world scalability evidence.

### Why only two runtime STS proofs?

The runtime proof phase was intentionally bounded. One denied and one assumed proof demonstrate that IAMScope can classify both outcomes and preserve credential sanitization without turning runtime probing into broad exploitability or production testing.

### Why no production-readiness claim?

The evidence is intentionally scoped to frozen cases, deterministic fixtures, reports, comparators, advisory thresholds, and narrow runtime probes. Production readiness would require different evidence, operational validation, environment diversity, safety review, and deployment criteria.

### How are artifacts kept safe?

Artifact hygiene is enforced through `./scripts/check.sh`, output-path discipline, baseline/golden-output policy, `.agent` slice contracts, and explicit bans on raw AWS artifacts, credentials, Terraform state/cache/provider artifacts, raw `/tmp` proof outputs, and uncontrolled generated outputs.

### How are mutation pairs used?

Mutation pairs are the main live semantic evidence unit. They compare controlled paired cases to show that IAMScope reacts to meaningful IAM condition changes in the frozen corpus.

## Next Phase Recommendation

Recommended next phase: external presentation package design.

This should be docs/design only. It should gather safe figures, tables, language, demo flow, and reviewer-response material without adding benchmark behavior.

Do not recommend more live probes, production testing, CI gates, composite scoring, new fixture families, large graph work, Terraform expansion, or multiple phases at once.
