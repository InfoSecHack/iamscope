# Release Tag / Versioning Decision

## Purpose

This decision document decides whether the current IAMScope repository state should receive a release tag and what that tag should mean. It is docs/decision only: it does not create a Git tag, create a GitHub release, change package metadata, add validation, run live AWS, call STS, generate benchmark outputs, or change IAMScope behavior.

## Current Evidence Basis

The current repository state has a bounded research/reviewer evidence package:

- Frozen live semantic benchmark layer: twenty-four bounded live AWS cases are summarized in `BENCHMARK_STATUS.md` and frozen under `benchmarks/snapshots/phase0-20260509-env27`.
- Mutation-pair sensitivity: ten known mutation pairs are summarized in `benchmarks/pair-reports/phase0-20260509-env27-mutation-pairs.md`, with no composite score.
- Synthetic scalability/degradation fixtures: synthetic fixtures exercise large/degraded artifact shapes and missing, malformed, partial, or artifact-insufficient evidence states without claiming real-world scale proof.
- Reporting/comparison layer: frozen corpus, pair, threshold, and reporting utilities support offline review of sanitized evidence.
- Report-only threshold review: threshold review remains advisory/report-only and is not a CI gate or production-quality threshold claim.
- Runtime STS denied/assumed proofs: standalone denied and assumed STS runtime summaries are documented as bounded runtime-probe evidence.
- Controlled validation Run #1: blocked before live execution as `environment_mismatch`.
- Controlled validation Run #2: one selected live-profile-matched denied STS prediction was corroborated as `denied/access_denied` with no credentials obtained and no downstream actions.
- Controlled STS schema/validator/generator/bundle machinery: schema, validator, generator, and safe bundle-generation docs are present for sanitized summaries.
- README/release hygiene status: README research framing is merged, README/start-here links were audited, release hygiene checkpoint is complete, and artifact hygiene is green.

## Versioning Options

| Option | Clarity | Overclaim risk | User expectation risk | Maintenance burden | Compatibility with current evidence | External/reviewer usefulness |
| --- | --- | --- | --- | --- | --- | --- |
| A. No tag yet | Clear that nothing is being released | Lowest | Lowest | Lowest | Compatible, but undersells the coherent checkpoint | Low; reviewers lack a stable reference |
| B. Research checkpoint tag | Clear if named as research/evidence only | Low | Low to medium | Low | Strong fit for current bounded evidence state | High; provides a stable review anchor |
| C. Pre-release version tag, e.g. `v0.1.0-research` | Familiar version shape, but mixed signal | Medium | Medium; users may expect package semantics | Medium | Compatible if heavily caveated | Medium; useful but may look more release-like than intended |
| D. Evidence checkpoint tag, e.g. `evidence-2026-05-controlled-validation` | Very explicit evidence boundary | Lowest among tag options | Low | Low | Strong fit, though name is longer | High; accurately names what is being preserved |
| E. Full semantic version release, e.g. `v0.1.0` | Familiar and short | High | High; implies product/version readiness | Medium to high | Too strong for current evidence boundaries | Medium externally, but misleading for current maturity |

## Recommended Tag Decision

Recommend exactly one decision: create a research/evidence checkpoint tag, not a production release tag.

Selected tag name: `evidence-2026-05-controlled-validation`.

This name is intentionally explicit. It avoids the stronger product expectation of `v0.1.0`, avoids the semi-product implication of `v0.1.0-research`, and makes the checkpoint's evidence nature visible at the tag name itself. It is useful to reviewers because it identifies a stable repository state for the completed benchmark, runtime STS proof, controlled validation, README framing, link audit, and release hygiene work.

## What The Tag Means

The selected tag would mean:

- A bounded evidence checkpoint for the current IAMScope research/reviewer package.
- The current research-facing README and documentation state.
- A benchmark/runtime/controlled-validation documentation milestone.
- Frozen live semantic benchmark evidence is documented for the current scope.
- Runtime STS proof and controlled validation maturity checkpoints are documented for the current scope.
- `./scripts/check.sh` and `./scripts/test_fast.sh` were green at the checkpoint decision stage.
- Artifact hygiene was green at the checkpoint decision stage.

## What The Tag Does Not Mean

The selected tag would not mean:

- Not production ready.
- Not broad IAMScope correctness.
- Not arbitrary enterprise graph correctness.
- Not broad exploitability.
- Not real-world scalability.
- Not all findings verified.
- Not CI threshold gate validity.
- Not generic resource-policy Deny support.
- Not finding-level reachability.

## Release Notes Boundaries

Safe release-note bullets for this checkpoint:

- Marks a bounded IAMScope evidence-program milestone for research/reviewer discussion.
- Points to the research-facing README and release hygiene checkpoint.
- Summarizes the frozen live semantic benchmark layer and mutation-pair evidence without a composite score.
- References synthetic scalability/degradation fixtures as guardrails, not real-world scalability proof.
- References controlled STS validation schema/validator/generator/bundle machinery for sanitized summaries.
- References standalone denied/assumed runtime STS summaries as bounded runtime evidence.
- States that threshold review remains report-only/advisory.
- States artifact hygiene boundaries and excludes raw AWS artifacts, credentials, `/tmp` outputs, and Terraform state/cache/provider artifacts.

Avoid in release notes:

- Production claims.
- Broad correctness claims.
- Exploitability claims.
- Enterprise validation claims.
- Pass/fail grade language.
- Composite score language.

## Safe Artifacts To Reference

Safe references:

- `README.md`.
- `docs/specs/release-hygiene-checkpoint.md`.
- `docs/archive/release-readme-packaging-audit.md` (archived historical packaging audit).
- `docs/specs/readme-link-target-audit.md`.
- `docs/archive/BENCHMARK_RESEARCH_READINESS_EXTERNAL_REVIEW.md`.
- `docs/specs/final-controlled-validation-maturity-checkpoint.md`.
- `docs/archive/BENCHMARK_RUNTIME_STS_PROOF_MATURITY_CHECKPOINT.md`.
- Controlled STS schema/validator/generator docs:
  - `docs/specs/controlled-sts-validation-report-schema.md`.
  - `docs/specs/controlled-sts-validation-report-validator.md`.
  - `docs/specs/controlled-sts-validation-report-generator.md`.
  - `docs/specs/controlled-sts-validation-report-bundle-generator.md`.
- External presentation docs:
  - External presentation planning artifacts were excluded from the public research-preview export.

Excluded unless separately reviewed:

- Raw AWS artifacts.
- Credentials, tokens, or credential-shaped values.
- `/tmp` outputs.
- Terraform state/cache/provider artifacts.
- Raw live logs.
- Generated controlled STS bundles unless separately reviewed.
- Generated PPTX or presentation binaries unless separately reviewed.

## Preconditions Before Actually Tagging

Before creating the tag, require:

- `main` synced to the intended checkpoint commit.
- `./scripts/check.sh` passed.
- `./scripts/test_fast.sh` passed.
- `git status` clean.
- Tag name reviewed: `evidence-2026-05-controlled-validation`.
- Release-note text reviewed.
- No raw artifacts staged.
- No credentials or credential-shaped values staged.
- No generated outputs staged.
- No Terraform state/cache/provider artifacts staged.

## Recommended Next Slice

Recommend exactly one next slice: draft release notes for selected research/evidence checkpoint tag.

That next slice should be docs/release-notes only and must not create the tag yet. It should not create a GitHub release, add new validation, run more live probes, add CI gates, add composite scoring, or bundle multiple phases at once.
