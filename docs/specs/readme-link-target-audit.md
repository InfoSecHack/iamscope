# README Link Target Audit

## Purpose

This audit verifies that the research-facing README links point to existing, safe, reviewer-appropriate repository documents after the README framing update. It is docs/audit only: it does not add evidence, run live AWS, call STS, generate benchmark outputs, change IAMScope behavior, or alter README content.

## README Link Inventory

| README reference | Path | Status | Safety / reviewer status |
| --- | --- | --- | --- |
| Benchmark status | `BENCHMARK_STATUS.md` | Exists | Safe and appropriate as the main benchmark status entry point; includes bounded-evidence and no-composite-score caveats. |
| Latest frozen snapshot | `benchmarks/snapshots/phase0-20260509-env27` | Exists | Safe as a frozen snapshot directory; reviewer should start with the snapshot README/corpus report rather than raw run directories. |
| Mutation-pair report | `benchmarks/pair-reports/phase0-20260509-env27-mutation-pairs.md` | Exists | Safe; explicitly says it is pair-specific, emits no composite score, and does not claim broad correctness. |
| Runtime STS proof maturity | `docs/archive/BENCHMARK_RUNTIME_STS_PROOF_MATURITY_CHECKPOINT.md` | Exists | Safe; clearly separates standalone STS executor proofs from broad exploitability or production readiness. |
| Release/readme packaging audit | `docs/archive/release-readme-packaging-audit.md` | Archived | Historical background only; not part of the current public reviewer path. |
| Research-readiness review | `docs/archive/BENCHMARK_RESEARCH_READINESS_EXTERNAL_REVIEW.md` | Exists | Safe; good external-facing research framing with explicit non-claims. |
| Final controlled validation maturity checkpoint | `docs/specs/final-controlled-validation-maturity-checkpoint.md` | Exists | Safe; documents Run #1 mismatch and Run #2 denied corroboration without overclaiming. |
| External presentation package design | Not included in public export | Excluded | Presentation-planning material was excluded from the public research-preview export. |
| Controlled STS report schema | `docs/specs/controlled-sts-validation-report-schema.md` | Exists | Safe but technical/procedural; appropriate in the README machinery list, not as the first read. |
| Controlled STS report validator | `docs/specs/controlled-sts-validation-report-validator.md` | Exists | Safe but technical/procedural; appropriate for implementers/reviewers validating report hygiene. |
| Controlled STS report generator | `docs/specs/controlled-sts-validation-report-generator.md` | Exists | Safe but technical/procedural; should remain a machinery reference. |
| Controlled STS bundle generator | `docs/specs/controlled-sts-validation-report-bundle-generator.md` | Exists | Safe but technical/procedural; correctly describes `/tmp` output and no raw artifact ingestion. |
| Artifact hygiene script | `scripts/check_benchmark_artifact_hygiene.sh` | Exists | Safe and appropriate; it is also covered by `./scripts/check.sh`. |
| Architecture guide | `docs/ARCHITECTURE.md` | Exists | Safe for technical contributors; not part of the research start-here path but appropriate in Documentation. |
| Contributing guide | `docs/CONTRIBUTING.md` | Exists | Safe for contributors; not primary research evidence. |
| Snapshot index | `benchmarks/snapshots/INDEX.md` | Exists | Safe; useful after `BENCHMARK_STATUS.md`. |
| Synthetic degradation design/status | `docs/specs/benchmark-degradation-family-design.md` | Exists | Safe; explains synthetic degradation as guardrails, not live AWS corpus proof. |

## Existing / Missing Path Status

- Broken README links found: none.
- Missing start-here document referenced by README: none. README has an inline "Start here for review" sequence rather than a link to a nonexistent start-here file.
- README path fixes made in this slice: none.
- README broad rewrite needed now: no.

## Safety Status Summary

The current README links are safe for a reviewer-facing entry point because they mostly target bounded status/checkpoint documents and frozen sanitized summaries. The linked benchmark status, mutation-pair report, runtime STS checkpoint, controlled validation checkpoint, and research-readiness review all preserve evidence boundaries and avoid production-readiness, broad-correctness, broad-exploitability, and composite-score claims.

The controlled STS schema/validator/generator/bundle-generator specs are safe but more procedural. They are acceptable as a machinery reference, but they should not be promoted above the benchmark status, research-readiness review, or final controlled validation checkpoint in public-facing reading order.

The operator Quick Start remains linked-free but includes commands that can call live AWS. README now labels those as operator examples rather than the default research reproduction path, which is an appropriate boundary.

## Recommended First Read Sequence

Recommended reviewer order remains:

1. `README.md` research/evidence status section.
2. `BENCHMARK_STATUS.md`.
3. `benchmarks/snapshots/phase0-20260509-env27/README.md` and `benchmarks/snapshots/phase0-20260509-env27/corpus/corpus_report.md`.
4. `benchmarks/pair-reports/phase0-20260509-env27-mutation-pairs.md`.
5. `docs/archive/BENCHMARK_RESEARCH_READINESS_EXTERNAL_REVIEW.md`.
6. `docs/specs/final-controlled-validation-maturity-checkpoint.md`.
7. `docs/archive/BENCHMARK_RUNTIME_STS_PROOF_MATURITY_CHECKPOINT.md`.
8. External presentation planning artifacts were excluded from the public research-preview export.
9. Controlled STS schema/validator/generator docs only if the reviewer needs implementation-level report hygiene details.

## Docs To Keep Internal / Procedural

These document categories should remain available but should not be promoted as first-read public links:

- Individual EnvXX harness specs and one-off benchmark build/run notes.
- Controlled STS pre-live plan and run-specific checkpoint details beyond the final maturity checkpoint.
- Branch hygiene, extraction handoff, and review-slice packaging notes.
- Low-level generator/validator specs except as machinery references.
- Any doc whose main value is operator procedure rather than evidence summary.
- Any doc that references `/tmp` paths as historical context rather than reusable public instructions.

## Broken Or Stale Links Fixed

None. No README edit was needed in this audit slice.

## Unresolved Issues

- A tiny dedicated start-here document is optional, not required. README already contains an inline start-here sequence with existing paths.
- The README still has detailed operator examples later in the file. They are now prefaced as live-AWS-capable operator examples, so they are safe enough for this slice.
- Future release packaging should avoid elevating procedural specs above bounded status and maturity documents.

## Recommended Next Slice

Recommend exactly one next slice: release hygiene checkpoint.

Because no broken README/start-here links were found and no missing start-here target exists, the next step should verify release-facing hygiene rather than add another documentation layer by default. It should not add new validation, live probes, benchmark framework changes, CI gates, pass/fail labels, composite scoring, or broad correctness claims.
