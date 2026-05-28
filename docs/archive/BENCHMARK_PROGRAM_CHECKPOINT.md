# Benchmark Program Checkpoint

## Final Current-Phase Maturity

Current `origin/main` is green for the standard local gates:

- `./scripts/check.sh`: pass
- `./scripts/test_fast.sh`: pass, `1600` tests

This checkpoint is documentation-only. It does not change benchmark logic, threshold evaluator logic, threshold parser logic, comparator logic, reporting logic, scalability harness logic, fixture definitions, collector logic, scoring logic, scenario-validation logic, reasoner logic, or artifact hygiene behavior.

The current benchmark/scalability/reporting/comparison/threshold scaffold is complete enough for this phase. The program now has five distinct layers of bounded evidence:

- Live semantic corpus: the current live AWS benchmark phase is complete for the named cases in `benchmarks/snapshots/phase0-20260509-env27`.
- Synthetic scalability fixture matrix: six deterministic synthetic fixtures cover baseline, constraint-pressure, trust-density, path-depth, and no-valid-path/rejection pressure dimensions.
- Reporting and comparison scaffold: synthetic scalability reports, offline frozen-corpus batch reports, and report-only baseline comparators for both report families emit JSON and Markdown.
- Artifact policy scaffold: baseline/golden-output policy and output-path tests exist so generated reports stay caller-directed and do not create repo-local outputs by default.
- Threshold review layer: threshold config validation and report-only/advisory threshold evaluators exist for synthetic scalability comparisons and frozen-corpus baseline comparisons.

Truth-before-breadth framing:

- IAMScope can currently claim that the named live benchmark cases, frozen corpus, synthetic fixtures, report generators, comparators, artifact-policy checks, and report-only threshold evaluators behave as recorded by this repo's bounded tests and frozen artifacts.
- The benchmark program proves specific live semantic mutation-pair deltas, repeated stability snapshots, synthetic degradation guardrails, deterministic synthetic scalability/reporting behavior, offline frozen-corpus reporting behavior, report-only baseline comparison behavior, artifact-output hygiene for the implemented scripts, and report-only threshold review behavior.
- The current scaffold implies a disciplined path toward regression review and future roadmap decisions, but it does not by itself prove future CI gate validity, real-world scalability, production readiness, broad IAMScope semantic correctness, or arbitrary enterprise graph correctness.
- Unknowns remain explicit and should stay visible in reviews, reports, threshold summaries, and any future benchmark phase.

No composite score is claimed or implied.

## Live Semantic Evidence

- Latest frozen snapshot: `benchmarks/snapshots/phase0-20260509-env27`
- Snapshot index: `benchmarks/snapshots/INDEX.md`
- Evaluated live AWS cases: `24`
- Corpus result: `24` passed / `0` failed
- Complete passing mutation pairs: `10`
- Latest pair report: `benchmarks/pair-reports/phase0-20260509-env27-mutation-pairs.md`

Mutation-pair sensitivity is the main live semantic evidence unit. The program currently covers:

- Identity Deny: Env03 -> Env16
- Permission boundary: Env05 -> Env09
- Trust condition: Env08 -> Env10
- Permission condition: Env14 -> Env15
- SCP: Env13 -> Env17
- Lambda PassRole: Env18 -> Env19
- ECS PassRole: Env20 -> Env21
- Cross-account trust: Env22 -> Env23
- S3 resource-policy Allow: Env24 -> Env25, scenario-edge-level only
- Same-account multihop trust: Env26 -> Env27

Stability snapshots currently cover:

- Env03
- Env05
- Env06
- Env07
- Env18
- Env19
- Env20
- Env21

Degradation guardrails currently cover:

- DEG07: missing required artifacts
- DEG01: missing trust edge
- DEG02: missing permission edge
- DEG03: missing blocker evidence
- DEG04: missing condition evidence
- DEG05: malformed or partially parsed policy evidence
- DEG06: partial or skipped target-account collection

Evidence boundaries:

- Env24/Env25 are scenario-edge-level resource-policy Allow evidence only. They do not prove finding-level resource-policy reachability or generic resource-policy Deny support.
- Env26/Env27 prove one controlled same-account multihop pair only. They do not prove arbitrary enterprise graph correctness, deeper-chain behavior, or cross-account multihop behavior.
- Stability snapshots prove bounded repeated-run behavior for their named cases only. They do not prove multi-day or multi-region stability.
- Degradation cases are synthetic benchmark-framework guardrails, not live AWS corpus cases.
- The live semantic corpus does not create a broad production-readiness claim or an arbitrary enterprise-environment correctness claim.

## Synthetic Scalability Evidence

Implemented deterministic synthetic fixtures:

- `small`: baseline smoke/regression
- `medium`: baseline/regression
- `constraint_heavy`: constraint-evaluation pressure
- `dense_trust`: trust-edge density pressure
- `multihop_stress`: path-depth / multihop pressure
- `negative_no_valid_path`: rejection/no-valid-path behavior

This proves only that a bounded deterministic synthetic scalability fixture matrix exists, the harness can generate and run the implemented fixtures, JSON and Markdown reports can include them, and per-fixture metrics remain non-composite.

This does not prove real-world scalability. Synthetic pressure dimensions are useful regression signals, not evidence that IAMScope will scale to arbitrary customer environments or enterprise graphs.

## Reporting And Baseline Comparison Evidence

Implemented reporting modes:

- Synthetic scalability JSON report
- Synthetic scalability Markdown report
- Offline frozen-corpus batch JSON report
- Offline frozen-corpus batch Markdown report

Implemented comparators:

- Synthetic scalability baseline comparator
- Frozen-corpus baseline comparator

Comparator boundaries:

- Both comparators are report-only.
- No thresholds are used by default.
- No pass/fail behavior is emitted.
- No composite score is emitted.
- Markdown reports preserve claim-boundary language.
- Unavailable metrics are represented explicitly and are not treated as zero.
- Frozen-corpus reporting and comparison are offline artifact/report operations and do not create new live AWS evidence.

## Artifact Policy Evidence

Artifact hygiene remains enforced by `scripts/check_benchmark_artifact_hygiene.sh` inside `./scripts/check.sh`.

Current artifact-policy state:

- Forbidden raw artifacts remain forbidden, including Terraform artifacts, `collect/` directories, raw live AWS artifacts, live-run `scenario.json` / `findings.json` / `binding_metadata.json` / `run.log`, credentials, cloud tokens, and uncontrolled generated run directories.
- Generated scalability, frozen-corpus, comparator, and threshold-evaluation outputs should default to caller-provided paths, preferably under `/tmp`.
- Generated outputs should not be committed by default.
- Baseline artifact / golden-output policy defines when small deterministic synthetic or sanitized fixtures may be committed for tests.
- Output-path tests cover `scripts/run_scalability_benchmark.sh`, `scripts/run_frozen_corpus_batch_report.sh`, `scripts/compare_scalability_baseline.sh`, and `scripts/compare_frozen_corpus_baseline.sh`.
- Those tests confirm the scripts can write to caller-provided paths and do not create repo-local generated outputs by default.

## Threshold Review Evidence

Implemented threshold review components:

- Threshold policy design exists.
- Threshold config schema design exists.
- Threshold config parser validates schema only.
- Synthetic threshold evaluator exists.
- Frozen-corpus threshold semantics design exists.
- Frozen-corpus threshold evaluator exists.

Threshold review boundaries:

- Both threshold evaluators are report-only/advisory.
- No CI gating is emitted.
- No fail-build behavior is emitted.
- No pass/fail benchmark labels are emitted.
- No composite score is emitted.
- The threshold config parser validates explicit schema and forbidden fields, but it does not execute thresholds.
- Threshold evaluation results support review of comparison reports; they are not production-readiness claims, correctness certificates, or real-world scalability evidence.

## Still Unproven

Important surfaces remain outside the current evidence boundary:

- Production readiness.
- Arbitrary enterprise graph correctness.
- Real-world scalability.
- Runtime exploitability.
- Generic resource-policy Deny support.
- Finding-level resource-policy reachability.
- Broad IAMScope semantic correctness.
- Broader cross-account variants.
- Multi-day and multi-region stability.
- CI threshold gate validity.
- Runtime validation/probe behavior.

These are not failures of the current program. They are explicit truth boundaries.

## Recommended Next Phase

Recommended next phase: pause implementation and perform a roadmap/research-readiness review before starting any new benchmark phase.

The current phase now has live semantic evidence, synthetic scalability fixtures, offline reporting, baseline comparators, artifact policy, and report-only threshold review tooling. The next risk is overbuilding or overclaiming, so the correct next move is to pause and decide the next phase deliberately.

Do not do next:

- Do not immediately add live AWS.
- Do not immediately add CI gating.
- Do not immediately add a new fixture family.
- Do not immediately add a large graph family.
- Do not introduce a composite score.
- Do not combine multiple next slices at once.
