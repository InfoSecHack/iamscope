# Specs Index

This directory contains IAMScope design notes, evidence checkpoints, schema
notes, and procedural reviews. Not every checkpoint is first-read material.
Start with the public reviewer documents, then drill into the specific evidence
area you want to audit.

IAMScope remains a research-preview / bounded-evidence project. These documents
do not claim production readiness, broad IAMScope correctness, broad runtime
exploitability, generic Deny correctness, real-world scalability, or a composite
benchmark score.

## Public Reviewer Docs

- [`../START_HERE.md`](../START_HERE.md) — shortest reviewer orientation path.
- [`supported-unsupported-evidence-matrix.md`](supported-unsupported-evidence-matrix.md) — supported, bounded, and unsupported evidence areas.
- [`public-release-readiness-review.md`](public-release-readiness-review.md) — public research-preview readiness review.
- [`private-reviewer-readiness-review.md`](private-reviewer-readiness-review.md) — private reviewer readiness review.
- [`private-reviewer-request-note.md`](private-reviewer-request-note.md) — request note for selected private reviewers.
- [`readiness-refresh-after-identity-deny.md`](readiness-refresh-after-identity-deny.md) — readiness posture after static Identity Deny evidence.

## Evidence And Readiness Docs

- [`final-controlled-validation-maturity-checkpoint.md`](final-controlled-validation-maturity-checkpoint.md) — controlled validation maturity boundary.
- [`release-hygiene-checkpoint.md`](release-hygiene-checkpoint.md) — release-facing hygiene status.
- [`public-visibility-change-readiness-checklist.md`](public-visibility-change-readiness-checklist.md) — operational checklist before any visibility change.
- [`github-prerelease-publication-checkpoint.md`](github-prerelease-publication-checkpoint.md) — GitHub prerelease checkpoint.

## Controlled STS Docs

- [`controlled-sts-validation-report-schema.md`](controlled-sts-validation-report-schema.md) — controlled STS report schema.
- [`controlled-sts-validation-report-validator.md`](controlled-sts-validation-report-validator.md) — controlled STS report validator checkpoint.
- [`controlled-sts-validation-report-generator.md`](controlled-sts-validation-report-generator.md) — controlled STS report generator design.
- [`controlled-sts-validation-report-bundle-generator.md`](controlled-sts-validation-report-bundle-generator.md) — controlled STS bundle generator design.
- [`controlled-sts-run-001-env-mismatch.md`](controlled-sts-run-001-env-mismatch.md) — Run #1 environment mismatch checkpoint.
- [`controlled-sts-run-002-live-result-checkpoint.md`](controlled-sts-run-002-live-result-checkpoint.md) — selected denied/access_denied controlled STS result.

## Controlled PassRole Docs

- [`controlled-passrole-validation-protocol.md`](controlled-passrole-validation-protocol.md) — controlled PassRole validation protocol.
- [`controlled-passrole-validation-report-schema.md`](controlled-passrole-validation-report-schema.md) — controlled PassRole report schema, validator, generator, and checkpoint history.
- [`controlled-passrole-active-lambda-validation-protocol.md`](controlled-passrole-active-lambda-validation-protocol.md) — active PassRole-to-Lambda protocol.
- [`controlled-passrole-active-run-001-result-and-teardown-checkpoint.md`](controlled-passrole-active-run-001-result-and-teardown-checkpoint.md) — one controlled service-mediated PassRole-to-Lambda result and teardown.
- [`controlled-passrole-run-001-static-validation-checkpoint.md`](controlled-passrole-run-001-static-validation-checkpoint.md) — static PassRole report-validation checkpoint.

## Controlled Identity Deny Docs

- [`controlled-identity-deny-validation-protocol.md`](controlled-identity-deny-validation-protocol.md) — controlled explicit identity-Deny validation protocol.
- [`controlled-identity-deny-validation-report-schema.md`](controlled-identity-deny-validation-report-schema.md) — controlled identity Deny report schema and validator checkpoint.
- [`controlled-identity-deny-candidate-selection.md`](controlled-identity-deny-candidate-selection.md) — selected candidate search and boundary.
- [`controlled-identity-deny-run-001-prelive-plan.md`](controlled-identity-deny-run-001-prelive-plan.md) — pre-live/static report plan.
- [`controlled-identity-deny-run-001-static-validation-checkpoint.md`](controlled-identity-deny-run-001-static-validation-checkpoint.md) — static Identity Deny report-validation checkpoint.

## Benchmark, Runtime, And Schema Docs

- [`benchmark-phase0-freeze-snapshot.md`](benchmark-phase0-freeze-snapshot.md) — frozen benchmark snapshot design.
- [`benchmark-snapshot-index.md`](benchmark-snapshot-index.md) — benchmark snapshot index design.
- [`benchmark-mutation-pair-report.md`](benchmark-mutation-pair-report.md) — mutation-pair report design.
- [`benchmark-degradation-family-design.md`](benchmark-degradation-family-design.md) — synthetic degradation family design.
- [`benchmark-stability-snapshots.md`](benchmark-stability-snapshots.md) — stability snapshot design.
- [`benchmark-structural-assertions.md`](benchmark-structural-assertions.md) — benchmark structural assertions.
- [`sts-probe-executor-skeleton.md`](sts-probe-executor-skeleton.md) — STS probe executor skeleton.

## Internal / Procedural Checkpoints

The many `envNN-*`, `arf-*`, and step-by-step checkpoint documents preserve
implementation history and bounded evidence decisions. They are useful for
auditing a specific slice, but they are not intended as the first reading path
for public reviewers.

Historical packaging audits, changelog drafts, and older checkpoint material live
under [`../archive/`](../archive/). They are retained as background context, not
current public reviewer guidance.

When adding a new non-trivial design or checkpoint, keep it narrow:

- State goal and non-goals.
- Preserve artifact-safety boundaries.
- Avoid broad claims.
- Link from this index only if it helps reviewers navigate current evidence.
