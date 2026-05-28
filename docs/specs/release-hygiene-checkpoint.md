# Release Hygiene Checkpoint

## Purpose

This is the final release-facing hygiene checkpoint for the current IAMScope evidence and research-packaging phase. It records that the public-facing README/docs surface is ready for bounded reviewer and research discussion, while preserving the evidence boundaries and non-claims already established by the benchmark, runtime proof, and controlled validation checkpoints.

This is docs/checkpoint only. It does not add validation, run live AWS, call STS, generate benchmark outputs, change IAMScope behavior, add Terraform, copy raw artifacts, commit `/tmp` outputs, add CI gates, add pass/fail labels, add composite scoring, or claim production readiness or broad correctness.

## Current Release-Facing Status

- README research framing exists in `README.md`.
- README/start-here links were audited in `docs/specs/readme-link-target-audit.md`.
- No missing start-here target was found; README uses an inline "Start here for review" sequence with existing paths.
- No broken README/start-here paths were found.
- Benchmark evidence phase is complete for the current scope.
- Runtime STS proof phase is complete for the current scope.
- Controlled validation phase is complete for the current scope.
- External presentation docs are prepared for bounded research/reviewer discussion.

## Hygiene Checks

The current release-facing hygiene state is:

- `./scripts/check.sh` passed.
- `./scripts/test_fast.sh` passed with 1691 tests.
- Artifact hygiene check passed as part of `./scripts/check.sh`.
- No tracked Terraform state/cache/provider artifacts were reported.
- No tracked raw live artifacts in benchmark snapshots were reported.
- No tracked gitlinks/submodules were reported.
- No tracked filenames with carriage returns were reported.
- No composite score is introduced by this checkpoint.
- No pass/fail benchmark labels are introduced by this checkpoint.

## Release-Facing Claim Boundary

IAMScope is ready for bounded research and reviewer discussion of the current evidence package.

IAMScope is not production ready. It does not claim broad IAMScope correctness, arbitrary enterprise graph correctness, broad runtime exploitability, real-world scalability, or all-findings verification. The release-facing language should continue to present IAMScope as a truth-focused evidence program with bounded live, synthetic, and controlled-validation evidence, not as a production oracle.

## Recommended Release Package

Safe release-facing materials:

- `README.md`.
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
- External presentation materials:
  - External presentation planning artifacts were excluded from the public research-preview export.
- Artifact hygiene scripts/docs, especially `scripts/check_benchmark_artifact_hygiene.sh` and checkpoint/spec documents that explain artifact boundaries.

Explicitly excluded from the release package unless separately sanitized and reviewed:

- Raw AWS artifacts.
- Credentials, tokens, or credential-shaped values.
- `/tmp` outputs.
- Terraform state/cache/provider artifacts.
- Raw live run logs.
- Raw `scenario.json`, `findings.json`, `binding_metadata.json`, or `run.log` artifacts unless separately sanitized and reviewed.
- Generated controlled STS bundles or reports unless separately reviewed.

## Remaining Known Limitations

The release-facing package must continue to make these limitations visible:

- No production readiness.
- No broad IAMScope correctness.
- No arbitrary enterprise graph correctness.
- No generic resource-policy Deny support.
- No finding-level reachability.
- No real-world scalability.
- No multi-account/multi-day runtime stability.
- No all-findings-verified claim.

## Recommended Next Phase

Recommend exactly one next phase: release tag / versioning decision.

That next phase should be a decision/review slice, not code. It should decide whether and how to tag or version the current research-facing evidence package. It should not add new validation, more live probes, benchmark framework expansion, CI gates, composite scoring, or multiple phases at once.
