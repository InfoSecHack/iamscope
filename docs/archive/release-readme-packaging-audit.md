# Release / README / Research Packaging Audit

> **Archive note:** Historical packaging audit. Superseded by `README.md`,
> `docs/START_HERE.md`, and
> `docs/specs/supported-unsupported-evidence-matrix.md`. Not the current public
> reviewer entrypoint. Recommendations below are historical and may describe
> work that has already been completed or material that is no longer included
> in the public research-preview export.

## Purpose

This audit assesses how IAMScope should be packaged for README, release, and research-facing consumption after the current evidence program.

This is docs/review only. It does not change the README, release files, benchmark behavior, validation behavior, executor logic, validator logic, collector/reasoner/scorer/scenario-validation logic, threshold/comparator/reporting/harness logic, Terraform, raw artifacts, `/tmp` outputs, CI gates, pass/fail benchmark labels, composite scoring, or any production-readiness or broad-correctness claim.

## Current Evidence Status

Current evidence that can be safely summarized publicly, with boundaries:

- Frozen live semantic benchmark layer: twenty-four bounded live AWS benchmark cases are frozen in `benchmarks/snapshots/phase0-20260509-env27` and summarized by `BENCHMARK_STATUS.md`.
- Mutation pairs: the current corpus includes mutation-pair evidence for identity Deny removal, permission boundary removal, trust-condition removal, permission-condition removal, SCP removal, PassRole condition mutations, cross-account trust scoping, S3 resource-policy Allow scoping, and multihop trust scoping.
- Synthetic scalability/degradation fixtures: synthetic scalability and degradation fixtures exercise large or degraded artifact shapes and missing, malformed, partial, or artifact-insufficient evidence states. They are guardrails and reporting inputs, not live AWS corpus cases and not real-world scalability proof.
- Reporting/comparison layer: corpus summaries, pair reports, snapshot index, benchmark archive ingestion/evaluation, and frozen-snapshot helpers exist for sanitized artifact review.
- Threshold review layer: threshold/comparison docs and scripts exist as reporting aids and should not be described as broad correctness gates.
- Runtime STS standalone proofs: standalone STS executor proofs include one denied and one assumed case, both bounded runtime-probe evidence.
- Controlled validation Run #1: Env06 positive path was blocked before live execution as `environment_mismatch`.
- Controlled validation Run #2: matched `iamscope-admin` denied path was corroborated by live AWS as `denied/access_denied`, with no credentials obtained and no downstream actions.
- Controlled STS schema/validator/generator/bundle machinery: schema, validator, report generator, bundle generator, and sanitized bundle generation/review are merged.
- External presentation planning artifacts were excluded from the public research-preview export.

## Recommended Public-Facing Core Claim

Recommended conservative README/release claim:

> IAMScope is a deterministic AWS IAM evidence and reachability analysis tool focused on truth-labeled findings. It collects read-only IAM facts, builds reproducible graph artifacts, and emits findings as validated, blocked, inconclusive, or precondition-only with explicit evidence and reasoning traces. The repository includes bounded live AWS benchmark snapshots, mutation-pair evidence, synthetic degradation fixtures, and controlled STS validation checkpoints that demonstrate selected narrow behaviors while preserving artifact-safety and non-claim boundaries.

The public claim must not say or imply:

- Production ready.
- Broadly correct.
- Enterprise validated.
- Exploitability proven.
- Real-world scalable.
- Complete IAM reasoning.
- All findings verified.

## README Audit

The README should eventually contain these sections or links:

- Short project description: deterministic AWS IAM evidence and reachability analysis that refuses to guess.
- What IAMScope does: read-only collection, deterministic scenario artifacts, reasoners, evidence-rich findings, truth-state verdicts.
- Evidence program summary: frozen benchmark corpus, mutation pairs, synthetic degradation fixtures, standalone STS proofs, and controlled validation checkpoints.
- Safe reproduction path: install, run checks/tests, inspect frozen/sanitized evidence, optionally generate controlled STS validation bundle to `/tmp`.
- Limitations and non-claims: no production-readiness claim, no broad correctness claim, no all-findings-verified claim, no generic resource-policy Deny support claim.
- Artifact safety notes: no raw AWS artifacts, credentials, Terraform state, provider caches, generated bundles, or `/tmp` outputs should be committed by default.
- Link map to key docs: start-here/current-status, benchmark status, final controlled validation maturity checkpoint, supported/unsupported evidence matrix, and schema/validator/generator docs.
- Status/maturity statement: current evidence is enough for human review and research packaging, not production adoption or broad correctness certification.

README risk observed in the current state:

- The opening positioning is strong and useful, but should be paired near the top with evidence boundaries and maturity status so readers do not infer broad production readiness.
- The benchmark section already contains important caveats; a shorter start-here pointer would make it easier for reviewers to find the current evidence state without reading every internal checkpoint.
- README should avoid turning benchmark counts into a score or guarantee.

## Docs Link Map

Recommended top-level reading order for a release/research package:

1. Start-here doc: a new small README-adjacent status page or README section that explains current maturity and points outward.
2. `BENCHMARK_STATUS.md`: current benchmark truth status and latest frozen snapshot.
3. `docs/specs/final-controlled-validation-maturity-checkpoint.md`: final controlled validation maturity state.
4. `docs/archive/BENCHMARK_ROADMAP_RESEARCH_READINESS_REVIEW.md` and `docs/archive/BENCHMARK_RESEARCH_READINESS_EXTERNAL_REVIEW.md`: research-readiness framing.
5. External presentation planning artifacts were excluded from the public research-preview export.
6. `docs/specs/controlled-sts-validation-report-schema.md`, `docs/specs/controlled-sts-validation-report-validator.md`, `docs/specs/controlled-sts-validation-report-generator.md`, and `docs/specs/controlled-sts-validation-report-bundle-generator.md`: controlled STS report machinery.
7. Artifact hygiene docs and scripts: `scripts/check_benchmark_artifact_hygiene.sh`, `scripts/check.sh`, snapshot freeze/index specs, and benchmark artifact management specs.

## Stale / Doc-Risk Audit

Recommended treatment categories:

### Promote To README

- `BENCHMARK_STATUS.md` as the current evidence status entry point.
- Latest snapshot path: `benchmarks/snapshots/phase0-20260509-env27`.
- `benchmarks/snapshots/INDEX.md`.
- `docs/specs/final-controlled-validation-maturity-checkpoint.md`.
- A concise non-claims block.

### Link From README

- `docs/archive/BENCHMARK_ROADMAP_RESEARCH_READINESS_REVIEW.md`.
- `docs/archive/BENCHMARK_RESEARCH_READINESS_EXTERNAL_REVIEW.md`.
- External presentation planning artifacts were excluded from the public research-preview export.
- Controlled STS report schema/validator/generator/bundle specs.
- Benchmark archive/evaluation/corpus/snapshot specs.

### Leave As Internal Checkpoint

- Individual EnvXX benchmark harness specs.
- Individual controlled STS Run #1 and Run #2 step-by-step checkpoint docs.
- ARF runtime verification notes.
- Branch hygiene and historical handoff notes.

### Archive Or Deprecate Later

- Older benchmark readiness or milestone notes if superseded by `BENCHMARK_STATUS.md` and final maturity docs.
- Older runtime STS proof gap/next-step reviews once their final checkpoint is linked.
- Older changelog drafts after the release note is finalized.

### Avoid Linking Publicly By Default

- Highly procedural run scripts and one-off checkpoint logs.
- Local branch-hygiene notes or extraction handoffs.
- Any doc that references raw `/tmp` artifact paths as instructions rather than historical context.
- Any internal checkpoint that could be mistaken for a current live-run instruction.

No deletion or archival should happen in this PR.

## Release Package Contents

A safe release/research package should include:

- README with a conservative evidence summary.
- Selected docs/checkpoints: benchmark status, supported/unsupported evidence matrix, final controlled validation maturity checkpoint, and current controlled STS, PassRole, and static Identity Deny checkpoints.
- Sanitized summaries and frozen benchmark snapshot summaries.
- Safe reports only if separately approved by an artifact-review slice.
- Schema/validator/generator docs for controlled STS validation reports.
- Artifact hygiene notes and reproduction commands for non-live checks.

A safe release/research package should not include:

- Raw AWS artifacts.
- Credentials, tokens, or credential-shaped fields.
- Raw `/tmp` outputs.
- Terraform state, provider caches, plans, or crash logs.
- Generated controlled STS bundles committed by default.
- Composite scores.
- Pass/fail benchmark labels.

## Reproduction Guidance

Recommended safe reproduction flow:

1. Install project dependencies in the expected virtual environment.
2. Run `./scripts/check.sh`.
3. Run `./scripts/test_fast.sh`.
4. Run `./scripts/check_benchmark_artifact_hygiene.sh` before packaging artifacts.
5. Inspect `BENCHMARK_STATUS.md` and the latest frozen benchmark snapshot.
6. Inspect mutation-pair reports and synthetic degradation docs as separate evidence tracks.
7. Inspect controlled STS maturity and report-schema docs.
8. Optionally generate a controlled STS validation bundle to `/tmp` using `scripts/generate_controlled_sts_validation_bundle.sh`.
9. Do not run live AWS by default.
10. Treat live probes as a separate protocol requiring explicit scope, pre-live planning, operator approval, and artifact-safety review.

## Visible Non-Claims

The README/release/research package must visibly state:

- No production readiness.
- No broad IAMScope correctness.
- No arbitrary enterprise graph correctness.
- No broad runtime exploitability.
- No downstream AWS authorization proof.
- No generic resource-policy Deny support.
- No finding-level reachability.
- No real-world scalability.
- No all-findings-verified claim.

## Recommended Next Slice

Archived historical recommendation: draft README research-facing update. This has been superseded by current public reviewer docs.

This recommendation is retained for history only and is not current public reviewer guidance.
