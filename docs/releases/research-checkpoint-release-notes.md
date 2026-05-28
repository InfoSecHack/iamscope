# Research Checkpoint Release Notes

## Proposed Tag

- Proposed tag name: `evidence-2026-05-controlled-validation`
- Release type: research/evidence checkpoint
- Tag status: not created by this document
- GitHub release status: not created by this document

## Short Summary

This checkpoint marks a bounded IAMScope evidence-program milestone for research and reviewer discussion. It captures the current research-facing README, frozen benchmark evidence, mutation-pair evidence, synthetic degradation/scalability fixtures, runtime STS proof maturity, controlled validation maturity, controlled STS report machinery, external presentation documentation, and artifact hygiene boundaries.

This is not a production release. It is a stable reference point for the current evidence package and documentation state.

## Evidence Layers Included

- Research-facing README framing in `README.md`.
- Frozen live semantic benchmark layer summarized in `BENCHMARK_STATUS.md` and frozen under `benchmarks/snapshots/phase0-20260509-env27`.
- Mutation-pair sensitivity summarized in `benchmarks/pair-reports/phase0-20260509-env27-mutation-pairs.md`.
- Synthetic scalability/degradation fixtures that exercise large or degraded artifact shapes without claiming real-world scalability.
- Reporting/comparison layer for offline review of frozen and sanitized evidence.
- Report-only threshold review; threshold outputs remain advisory and are not CI gates.
- Runtime STS denied/assumed standalone proof maturity, documented in `docs/archive/BENCHMARK_RUNTIME_STS_PROOF_MATURITY_CHECKPOINT.md`.
- Controlled validation Run #1, classified as `environment_mismatch` before live execution.
- Controlled validation Run #2, one selected denied STS prediction corroborated as `denied/access_denied` with no credentials obtained and no downstream actions.
- Controlled STS report schema/validator/generator/bundle machinery for sanitized summaries.
- External presentation package/design/narrative/storyboard/Markdown deck docs.
- Artifact hygiene checks and release hygiene documentation.

## Benchmark / Runtime / Controlled-Validation Status

- Benchmark evidence is complete for the current scope.
- Runtime STS proof is complete for the current scope.
- Controlled validation is complete for the current scope.
- README/start-here links have been audited with no missing target and no broken README/start-here paths found.
- Release hygiene checkpoint is complete for the current scope.

## Artifact Hygiene Status

At the release-note drafting stage:

- `./scripts/check.sh` passed.
- `./scripts/test_fast.sh` passed.
- Artifact hygiene check passed as part of `./scripts/check.sh`.
- No tracked Terraform state/cache/provider artifacts were reported.
- No tracked raw live artifacts in benchmark snapshots were reported.
- No tracked gitlinks/submodules were reported.
- No tracked filenames with carriage returns were reported.
- No composite score is introduced.
- No pass/fail benchmark label is introduced.

## Safe Reproduction Commands

Safe local validation path:

```bash
source .venv/bin/activate
./scripts/check.sh
./scripts/test_fast.sh
```

Optional sanitized report/bundle generation may write to `/tmp` only when using the documented controlled STS bundle machinery. Generated bundles and reports are not committed by default.

Live AWS collection or STS probes are not part of the default release-note reproduction path. They require separate protocol, explicit scope, operator approval, and artifact-safety review.

## Safe Artifacts To Reference

Safe release-note references:

- `README.md`.
- `docs/specs/release-tag-versioning-decision.md`.
- `docs/specs/release-hygiene-checkpoint.md`.
- `docs/archive/release-readme-packaging-audit.md` (archived historical packaging audit).
- `docs/specs/readme-link-target-audit.md`.
- `docs/archive/BENCHMARK_RESEARCH_READINESS_EXTERNAL_REVIEW.md`.
- `docs/specs/final-controlled-validation-maturity-checkpoint.md`.
- `docs/archive/BENCHMARK_RUNTIME_STS_PROOF_MATURITY_CHECKPOINT.md`.
- Controlled STS report docs:
  - `docs/specs/controlled-sts-validation-report-schema.md`.
  - `docs/specs/controlled-sts-validation-report-validator.md`.
  - `docs/specs/controlled-sts-validation-report-generator.md`.
  - `docs/specs/controlled-sts-validation-report-bundle-generator.md`.
- External presentation docs:
  - External presentation planning artifacts were excluded from the public research-preview export.

Excluded unless separately sanitized and reviewed:

- Raw AWS artifacts.
- Credentials, tokens, or credential-shaped values.
- `/tmp` outputs.
- Terraform state/cache/provider artifacts.
- Raw live logs.
- Generated controlled STS bundles.
- Generated PPTX or presentation binaries.

## Explicit Non-Claims

This checkpoint does not claim:

- Production readiness.
- Broad IAMScope correctness.
- Arbitrary enterprise graph correctness.
- Broad runtime exploitability.
- Real-world scalability.
- All findings verified.
- CI threshold gate validity.
- Generic resource-policy Deny support.
- Finding-level reachability.
- Enterprise validation.
- A pass/fail grade.
- A composite benchmark score.

## Known Limitations

Known limitations remain visible and unchanged:

- The live benchmark corpus is bounded to named cases and does not prove all AWS IAM shapes.
- Synthetic scalability/degradation fixtures are not proof of real-world scalability.
- Runtime STS proofs are narrow and do not prove downstream authorization.
- Controlled validation has one environment mismatch and one corroborated denied selected-path result; positive controlled finding/path validation remains outside this checkpoint.
- Resource-policy Deny support and finding-level resource-policy reachability remain outside the current claim boundary.
- Multi-account/multi-day runtime stability remains unproven.
- Threshold review remains report-only/advisory.

## What Changed Since Prior Baseline

Since the earlier pre-release documentation baseline, the repository now has:

- Research-facing README framing.
- README/start-here link target audit.
- Release hygiene checkpoint.
- Release tag/versioning decision selecting `evidence-2026-05-controlled-validation`.
- This draft release-note document for that selected research/evidence checkpoint tag.

No tag, GitHub release, package metadata change, live AWS run, STS call, benchmark output, raw artifact, CI gate, pass/fail label, or composite score is introduced by this release-note slice.

## Recommended Next Step After Tag

After the tag decision and release-note text are reviewed, the next step should be a separate tag execution review for `evidence-2026-05-controlled-validation`.

That future slice should verify `main` is synced, validations are green, `git status` is clean, the tag name and release notes are approved, and no raw artifacts, credentials, generated outputs, or Terraform state/cache/provider artifacts are staged. It should not add new validation scope, run live AWS, add CI gates, introduce composite scoring, or broaden claims.
