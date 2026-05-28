# Benchmark Scalability Design

## Purpose

This design defines the next IAMScope benchmark phase: performance and scalability regression evidence at controlled graph sizes. It evaluates how IAMScope behaves as scenario graphs grow in node count, edge count, constraint count, path depth, and candidate-path volume.

This phase is not an additional semantic-correctness benchmark family. The current benchmark program already has a twenty-four-case frozen live AWS corpus, ten complete mutation pairs, eight stability snapshots, and seven synthetic degradation guardrails. The next missing proof is whether benchmarked IAMScope workflows remain deterministic, measurable, and non-regressive on larger synthetic or replayed graphs.

## Non-Goals

- This is not a live AWS benchmark.
- This is not a runtime exploitability proof.
- This is not a production-readiness proof.
- This is not an arbitrary enterprise graph correctness proof.
- This is not a composite score.
- This is not a replacement for semantic mutation-pair testing.
- This does not expand finding-level resource-policy reachability claims.
- This does not claim or test generic resource-policy Deny support.
- This does not change collector, scorer, reasoner, or scenario validation semantics.

## Current Benchmark Context

- Latest frozen live corpus: `benchmarks/snapshots/phase0-20260509-env27`.
- Live corpus size: `24` evaluated / `24` passed cases.
- Latest mutation-pair report: `benchmarks/pair-reports/phase0-20260509-env27-mutation-pairs.md`.
- Mutation-pair coverage: `10` complete passing pairs.
- Stability coverage: Env03, Env05, Env06, Env07, Env18, Env19, Env20, Env21.
- Degradation coverage: DEG07 and DEG01 through DEG06.
- Artifact hygiene is enforced by `scripts/check_benchmark_artifact_hygiene.sh` inside `./scripts/check.sh`.

These inputs are bounded benchmark evidence only. They do not prove broad IAMScope correctness, arbitrary enterprise graph correctness, or production readiness.

## Benchmark Inputs

Future scalability benchmarks should use safe repo-local inputs that are small enough to review and deterministic enough to compare across runs.

- Synthetic graph fixtures: hand-authored or generated `scenario`/fact-graph shapes with known topology, deterministic IDs, and no live AWS dependency.
- Replayed frozen benchmark artifacts where available: evaluated snapshot summaries or sanitized scenario-derived inputs, never raw live archives.
- Generated scenario graphs with controlled size and topology: seeded generators that can vary graph dimensions while preserving stable output ordering.
- Optional stress fixtures derived from existing benchmark patterns: Env18/19 PassRole, Env22/23 cross-account trust, Env24/25 resource-policy Allow, Env26/27 multihop, and DEG-style negative/no-valid-path shapes.

Raw live AWS archives, Terraform state, provider caches, `collect/` directories, `run.log`, `scenario.json`, `findings.json`, and `binding_metadata.json` from live runs must not be committed as scalability artifacts.

## Scale Dimensions

The design should vary dimensions independently where possible so regressions can be localized rather than hidden inside one large graph.

- Number of principals.
- Number of roles.
- Number of accounts.
- Number of trust edges.
- Number of permission edges.
- Number of constraints.
- Number of candidate paths.
- Path depth.
- Branching factor.
- Number of resource-policy edges.
- Number of SCP, permission-boundary, and condition constraints.

Each benchmark result must be interpreted with its fixture class and size. A metric from a dense trust graph should not be compared directly to a constraint-heavy graph without that context.

## Workload Families

Initial scalability design should cover these workload families, with exact sizes chosen during implementation:

- Small regression fixture: fast smoke fixture for local development and CI gating.
- Medium synthetic org graph: representative multi-account graph with mixed principals, roles, edges, and constraints.
- Large synthetic org graph: larger deterministic graph intended to expose superlinear behavior without using live AWS.
- Dense trust graph: many trust and AssumeRole permission combinations to stress path enumeration and chain walking.
- Constraint-heavy graph: many SCP, permission-boundary, and condition constraints to stress binding lookup and blocker evaluation.
- Multihop path graph: controlled paths at multiple depths and branching factors to stress `assume_role_chain` and `admin_reachability`.
- Negative/no-valid-path graph: many plausible-looking paths with missing witnesses, scoped-away trust, or blocked preconditions to test rejection cost.
- Replayed frozen-corpus batch: deterministic batch over existing evaluated benchmark summaries or sanitized replay inputs to measure end-to-end benchmark report overhead.

## Metrics

Reports must keep metrics separate. They must not roll measurements into a composite benchmark score.

- Wall-clock runtime.
- Peak memory if feasible on the target platform.
- Candidate paths considered.
- Paths validated.
- Paths rejected.
- Constraint evaluations.
- Artifact load time.
- Report generation time.
- Deterministic output stability.
- Failure mode classification.

When a metric is unavailable, the report should say `not_collected` rather than guessing. For example, peak memory may be unavailable on some local platforms without extra tooling.

## Acceptance Criteria

These are initial design targets, not final performance promises:

- Fixed inputs produce deterministic outputs.
- Generated graph fixtures use fixed seeds and stable ordering.
- No raw artifacts are committed.
- No semantic claim expands because a scalability fixture passes.
- No benchmark result is interpreted without fixture class and graph size.
- Regressions are reported per metric, not hidden inside a composite score.
- Failure modes are explicit: timeout, memory ceiling, nondeterministic output, semantic mismatch, unsupported fixture, or infrastructure error.
- The design remains compatible with `./scripts/check.sh` artifact hygiene.

## Output Artifacts

Future implementation may emit safe summary artifacts:

- Summary Markdown report.
- Structured JSON summary.
- Per-fixture metric records.
- Benchmark configuration manifest.
- Fixture manifest with generator seed, graph size, and topology parameters.

Future implementation must not emit or commit unsafe artifacts:

- Raw live AWS archives.
- Terraform state, caches, plans, provider binaries, or tfvars.
- Live `collect/` directories.
- Live `scenario.json`, `findings.json`, `binding_metadata.json`, or `run.log`.
- A composite score.

## Reproducibility Requirements

Future implementation should require:

- Fixed seeds for generated graphs.
- Fixture manifests describing graph size, topology, seed, and benchmark family.
- Versioned benchmark configuration.
- Stable output ordering for generated nodes, edges, constraints, findings, and metric records.
- Clear benchmark command examples.
- Artifact hygiene compatibility with `./scripts/check.sh`.
- A deterministic failure record when a benchmark times out or exceeds a memory ceiling.

Example future commands:

```bash
# Small smoke scalability run
bash scripts/run_scalability_benchmark.sh --fixture small --out /tmp/iamscope-scalability-small

# Medium deterministic synthetic-org run
bash scripts/run_scalability_benchmark.sh --fixture medium-org --seed 20260509 --out /tmp/iamscope-scalability-medium

# Render a repo-local summary from safe evaluated metric records
python -m benchmarks.reporting.scalability --input /tmp/iamscope-scalability-medium --format markdown
```

These commands are illustrative only. This design slice does not add those scripts or modules.

## Reporting Format

Future reports should use a simple layout:

- Benchmark config: tool version, command, seed, fixture manifest path, and benchmark date.
- Fixture class: small, medium-org, large-org, dense-trust, constraint-heavy, multihop, negative/no-valid-path, or replayed-corpus.
- Graph size: principals, roles, accounts, trust edges, permission edges, resource-policy edges, constraints, path depth, and branching factor.
- Metrics table: wall-clock runtime, peak memory if available, candidate paths considered, paths validated, paths rejected, constraint evaluations, artifact load time, report generation time, deterministic output stability, and failure mode classification.
- Regression notes: per-metric deltas against an explicitly named baseline.
- Caveats: fixture-specific limitations and any unavailable metrics.
- Unproven areas: semantic correctness beyond the fixture, live AWS runtime behavior, production readiness, generic resource-policy Deny, arbitrary enterprise graph correctness, and runtime exploitability.

## Risks And Overclaim Traps

- Do not treat synthetic scale as real-world correctness.
- Do not hide tradeoffs in a composite score.
- Do not confuse fast runtime with correct reasoning.
- Do not confuse replayed artifacts with live AWS validation.
- Do not claim generic resource-policy Deny support.
- Do not claim arbitrary enterprise graph correctness.
- Do not compare fixtures without carrying fixture class and graph size.
- Do not treat a passing scalability run as permission to weaken semantic mutation-pair or degradation checks.

## Minimal Harness Checkpoint

The scalability harness currently implements six bounded synthetic fixtures:

- Harness module: `benchmarks/scalability/harness.py`.
- Runner: `scripts/run_scalability_benchmark.sh`.
- Test coverage: `tests/test_benchmark_scalability.py`.
- Implemented fixture sizes: `small`, `medium`, `constraint_heavy`, `dense_trust`, `multihop_stress`, and `negative_no_valid_path`.
- Fixture source: deterministic generated synthetic graph definitions with fixed seed `20260509`.
- Output: structured JSON and Markdown summaries with per-fixture metrics.

These are the only implemented scalability fixtures so far. The harness does not yet implement large or replayed frozen-corpus workloads.

Current fixture matrix:

| Fixture | Pressure Dimension | Key Comparison Anchor |
| --- | --- | --- |
| `small` | Baseline smoke/regression fixture | Minimal deterministic fixture for harness and reporting smoke coverage. |
| `medium` | Baseline/regression fixture | Reference fixture for comparing bounded pressure dimensions. |
| `constraint_heavy` | Constraint-evaluation pressure | `1,920` constraint evaluations versus `medium` at `288`. |
| `dense_trust` | Trust-edge density pressure | `88` trust edges versus `medium` at `34`. |
| `multihop_stress` | Path-depth / multihop pressure | Max path depth `6` versus `medium` at `3`. |
| `negative_no_valid_path` | Rejection/no-valid-path behavior | `48` candidate paths, `38` nodes, `34` permission edges, `34` trust edges, and zero expected full-depth valid synthetic paths. |

These fixtures are designed to isolate different synthetic pressure dimensions, not to form a single composite benchmark score. Fixture comparisons must carry the fixture class, graph size, and relevant pressure dimension instead of collapsing the matrix into a grade, ranking, or pass rate.

The `constraint_heavy` fixture is synthetic and bounded. It uses two accounts, ten principals, twenty-four roles, path depth `3`, branching factor `2`, thirty-two synthetic constraints, and six synthetic resource-policy edges. Its purpose is to increase constraint-evaluation pressure without adding live AWS behavior, broad graph families, semantic benchmark claims, or a composite score.

This is the only new fixture family added in the constraint-pressure slice. The `medium` fixture emits `288` synthetic constraint evaluations; `constraint_heavy` emits `1,920` synthetic constraint evaluations. That increases synthetic constraint-evaluation pressure while preserving bounded fixture size and fast local execution.

The `dense_trust` fixture is synthetic and bounded. It uses two accounts, eight principals, twenty-four roles, path depth `3`, branching factor `3`, four synthetic constraints, four synthetic resource-policy edges, and deterministic extra trust-only edges. It emits `88` trust edges compared with `34` trust edges for `medium`, creating materially higher trust-edge density while keeping constraint evaluations below `constraint_heavy`.

This is the only new fixture family added in the trust-density slice. It increases synthetic trust-edge pressure while preserving bounded fixture size; it is not a large-graph benchmark.

The `multihop_stress` fixture is synthetic and bounded. It uses two accounts, six principals, thirty-six roles, path depth `6`, branching factor `2`, four synthetic constraints, and four synthetic resource-policy edges. It emits candidate paths at depth `6` compared with `medium` at depth `3`, creating materially higher bounded multihop path pressure while keeping trust edges below `dense_trust` and constraint evaluations below `constraint_heavy`.

This is the only new fixture family added in the multihop-depth slice. It is not a large-graph benchmark, a dense-trust benchmark, or a constraint-heavy benchmark. Specifically, it emits `34` trust edges versus `dense_trust` at `88`, and `288` constraint evaluations versus `constraint_heavy` at `1,920`.

The `negative_no_valid_path` fixture is synthetic and bounded. It uses two accounts, eight principals, twenty-four roles, path depth `4`, branching factor `2`, four synthetic constraints, and four synthetic resource-policy edges. It has `38` nodes, `34` permission edges, `34` trust edges, and `48` candidate paths, but intentionally omits the terminal matching AssumeRole pair so it has zero expected full-depth valid synthetic paths. It reports `expected_valid_synthetic_paths=0` through the existing stable fixture/report representation.

This is the only new fixture family added in the no-valid-path slice. It is not an empty graph, not a large-graph benchmark, and not a frozen-corpus batch. It exists to exercise bounded negative-path search behavior without adding live AWS behavior, IAMScope semantic claims, or a composite score.

Example command:

```bash
bash scripts/run_scalability_benchmark.sh \
  --json-out /tmp/iamscope-scalability-minimal.json \
  --markdown-out /tmp/iamscope-scalability-minimal.md
```

Reporting support now exists for both safe output formats:

- JSON summary output via `--json-out`.
- Markdown summary output via `--markdown-out`.
- Markdown rendering lives in `benchmarks/scalability/harness.py` through `render_markdown_report()` and `write_markdown_report()`.
- `scripts/run_scalability_benchmark.sh` supports both output paths and writes only to caller-provided destinations.

Offline frozen-corpus batch reporting now exists for already-frozen benchmark snapshots:

- Reporter module: `benchmarks/scalability/frozen_corpus_batch.py`.
- Runner: `scripts/run_frozen_corpus_batch_report.sh`.
- Example command:

```bash
bash scripts/run_frozen_corpus_batch_report.sh \
  --snapshot benchmarks/snapshots/phase0-20260509-env27 \
  --json-out /tmp/iamscope-frozen-corpus-batch.json \
  --markdown-out /tmp/iamscope-frozen-corpus-batch.md
```

The frozen-corpus batch mode is offline only. It reads safe snapshot artifacts that are already committed under the selected snapshot, such as `corpus_summary.json`, `run_manifest.json`, `scorer_result.json`, `gate_result.json`, and `report.md`. It does not collect from AWS, invoke Terraform, require cloud credentials, copy raw artifacts, or write repo-local outputs unless the caller explicitly points an output path into the repo.

The frozen-corpus batch report can summarize:

- Batch counts available from the frozen corpus summary, such as case count, evaluated cases, passes, failures, artifact-insufficient cases, blocked promotions, and human-review-required count.
- Per-case metadata available from safe frozen artifacts, such as case ID, run ID, family, benchmark date, environment, authority, confidence, scenario-validation status, score result, artifact sufficiency, promotion-blocked status, human-review flag, assertion counts, defect counts, and safe snapshot artifact presence.

The frozen-corpus batch report cannot honestly recover scalability instrumentation that was not captured in the frozen semantic snapshot. Metrics such as wall-clock runtime, peak memory, candidate paths considered, paths validated, paths rejected, constraint evaluations, artifact load time, and report generation time are represented as `not_collected` with an explicit reason rather than invented.

Frozen-corpus batch reporting checkpoint:

- Frozen-corpus batch reporting is implemented in `benchmarks/scalability/frozen_corpus_batch.py`.
- The runner is `scripts/run_frozen_corpus_batch_report.sh`.
- The mode is offline only and reads already-frozen safe snapshot artifacts.
- The mode emits a JSON report and a Markdown report.
- Reports include batch summary counts where available and per-case summaries where available.
- Unavailable metrics are represented honestly as `not_collected` or `unavailable_with_reason`.
- It does not run live AWS, invoke Terraform, copy raw artifacts, add live benchmark cases, change collector/scoring/scenario-validation/reasoner behavior, or change synthetic fixtures.
- It does not emit a composite score, grade, pass rate, ranking, or production-readiness language.

This checkpoint proves only that frozen-corpus batch reporting can run offline over already-frozen safe artifacts, produce JSON and Markdown reports from the frozen corpus, preserve artifact-hygiene-compatible outputs, and bridge the synthetic scalability reporting style to frozen benchmark artifacts without inventing unavailable metrics.

This checkpoint does not prove real-world scalability, live AWS correctness beyond the already-frozen benchmark evidence, runtime exploitability, production readiness, arbitrary enterprise graph correctness, broad IAMScope semantic correctness, generic resource-policy Deny support, or finding-level resource-policy reachability.

The emitted JSON and Markdown metrics are intentionally per-fixture and do not include a composite score:

- `wall_clock_runtime_ms`.
- `candidate_paths_considered`.
- `constraint_evaluations`.
- `artifact_load_time_ms`.
- `deterministic_output_stability`.
- `failure_mode_classification`.
- `not_collected` placeholders for unavailable metrics such as peak memory, paths validated, paths rejected, and report generation time.

The reporting scope is still bounded:

- Existing implemented fixtures only: `small`, `medium`, `constraint_heavy`, `dense_trust`, `multihop_stress`, and `negative_no_valid_path`.
- No additional fixture families.
- JSON includes `constraint_heavy`.
- Markdown includes `constraint_heavy`.
- JSON includes `dense_trust`.
- Markdown includes `dense_trust`.
- JSON includes `multihop_stress`.
- Markdown includes `multihop_stress`.
- JSON includes `negative_no_valid_path`.
- Markdown includes `negative_no_valid_path`.
- Reports remain per-fixture only.
- No composite score.
- No pass/fail grade.
- No benchmark ranking.
- No production-readiness claim.

The current harness proves only that:

- A deterministic synthetic scalability harness exists.
- The `small`, `medium`, `constraint_heavy`, `dense_trust`, `multihop_stress`, and `negative_no_valid_path` synthetic fixtures can be generated and run consistently.
- A bounded deterministic constraint-heavy synthetic fixture exists.
- The harness can report higher synthetic constraint-evaluation pressure than `medium`.
- JSON and Markdown reporting include `constraint_heavy`.
- A bounded deterministic dense-trust synthetic fixture exists.
- The harness can report materially higher synthetic trust-edge density than `medium`.
- JSON and Markdown reporting include `dense_trust`.
- A bounded deterministic multihop-stress synthetic fixture exists.
- The harness can report materially higher synthetic path depth than `medium`.
- JSON and Markdown reporting include `multihop_stress`.
- A bounded deterministic negative/no-valid-path synthetic fixture exists.
- The harness can report candidate search work with zero expected full-depth valid synthetic paths.
- JSON and Markdown reporting include `negative_no_valid_path`.
- The harness covers baseline, constraint-pressure, trust-density, path-depth, and no-valid-path pressure dimensions as separate synthetic fixture classes.
- The per-fixture metric schema is stable.
- No composite score is emitted.
- Per-fixture metrics remain non-composite.
- Artifact-hygiene-compatible JSON and Markdown outputs are possible.

The current reporting refinement proves only that:

- Existing scalability JSON output can be rendered into a stable human-readable Markdown summary.
- JSON output remains supported.
- Claim-boundary language is included in the Markdown report.
- Reports can be generated without live AWS or raw artifacts.
- Already-frozen semantic benchmark snapshots can be rendered into an offline JSON and Markdown batch report without live AWS, raw artifacts, or composite scoring.

The current harness does not prove:

- Real-world scalability.
- Live AWS correctness.
- Runtime exploitability.
- Production readiness.
- Arbitrary enterprise graph correctness.
- Generic resource-policy Deny support.
- Finding-level resource-policy reachability.
- Broad IAMScope semantic correctness.

The harness does not run live AWS, does not use raw benchmark artifacts, does not create Terraform artifacts, and does not change collector, scorer, reasoner, or scenario validation semantics.

## Regression Baseline Comparison Design

Purpose: future regression/baseline comparison should let scalability and frozen-corpus reports be compared against explicitly named stored baselines without introducing a composite score. The comparison should make changes visible per fixture, per case, and per metric so reviewers can see what changed and decide whether follow-up is needed.

Non-goals:

- This is design only, not implementation.
- This is not a live AWS benchmark.
- This is not a production-readiness proof.
- This is not a broad IAMScope correctness proof.
- This is not an arbitrary enterprise graph correctness proof.
- This is not a real-world scalability proof.
- This is not composite scoring.
- This is not ranking or grading.

Supported baseline inputs:

- Synthetic scalability JSON reports produced by `scripts/run_scalability_benchmark.sh`.
- Offline frozen-corpus batch JSON reports produced by `scripts/run_frozen_corpus_batch_report.sh`.
- Optional Markdown reports as human-readable companions only, not as machine-comparison sources.
- No raw live artifacts, Terraform artifacts, `collect/` directories, `scenario.json`, `findings.json`, `binding_metadata.json`, or `run.log`.

Comparison dimensions should stay per fixture or per case:

- Wall-clock runtime, with machine, load, and environment caveats.
- Candidate paths considered.
- Constraint evaluations.
- Artifact load time.
- Deterministic output stability digest.
- Failure mode classification.
- Case counts where available.
- Unavailable metrics, which must remain `not_collected` or `unavailable_with_reason` and must not be treated as zero.

Future comparison output should include:

- JSON comparison report.
- Markdown comparison report.
- Per-fixture and per-case deltas.
- `unchanged`, `changed`, and `unavailable` classification for compared fields.
- Caveats that preserve fixture class, graph size, report type, machine context when known, and unavailable metrics.
- No composite score.
- No pass/fail grade unless a future run explicitly provides named per-metric thresholds.

Threshold policy:

- Default mode should be report-only.
- Optional thresholds must be explicit, per metric, and visible in the output.
- There must be no hidden thresholds.
- Runtime thresholds must be treated cautiously because machine noise can dominate small changes.
- Deterministic stability digest changes should be highlighted even when other metrics are unchanged.
- Unavailable metrics must not be treated as zero, passing, failing, or regressed.

Interpretation rules:

- A metric regression is evidence of changed benchmark behavior, not automatically a product bug.
- Runtime changes require machine and context caveats.
- Synthetic fixture changes do not imply real-world scalability changes.
- Frozen-corpus reporting changes do not imply new live AWS evidence.
- Comparison results do not expand semantic correctness claims.
- Comparison results must not weaken semantic mutation-pair, degradation, stability, or artifact-hygiene checks.

Artifact hygiene:

- Comparison outputs must be written only to caller-provided paths.
- No raw artifacts may be copied.
- No Terraform artifacts may be created or committed.
- No uncontrolled benchmark run directories may be written.
- Safe JSON and Markdown summaries are the only intended output artifacts.

Minimal synthetic baseline comparator command:

```bash
bash scripts/compare_scalability_baseline.sh \
  --baseline /tmp/iamscope-scalability-baseline.json \
  --current /tmp/iamscope-scalability-current.json \
  --json-out /tmp/iamscope-scalability-comparison.json \
  --markdown-out /tmp/iamscope-scalability-comparison.md
```

The minimal comparator is scoped to synthetic scalability JSON reports only. It is report-only, uses no thresholds by default, emits no pass/fail result, emits no composite score, does not compare frozen-corpus reports yet, and does not prove real-world scalability or broad IAMScope correctness.

Synthetic baseline comparator checkpoint:

- The synthetic scalability baseline comparator is implemented in `benchmarks/scalability/baseline_compare.py`.
- The runner is `scripts/compare_scalability_baseline.sh`.
- It compares synthetic scalability JSON reports only.
- It emits JSON and Markdown comparison reports.
- It emits per-fixture comparisons with `changed`, `unchanged`, and `unavailable` classifications.
- It emits numeric deltas where metrics are available.
- Unavailable metrics are not treated as zero.
- It is report-only: `thresholds_used=false`, no pass/fail behavior, no composite score, no grade, no ranking, no pass rate, no severity, and no production-readiness language.
- It does not compare frozen-corpus reports yet.
- It does not run live AWS, copy raw artifacts, change collector/scoring/scenario-validation/reasoner behavior, or change synthetic fixtures.

This checkpoint proves only that synthetic scalability JSON reports can be compared in report-only mode, JSON and Markdown comparison reports can be generated, per-fixture deltas and `changed`/`unchanged`/`unavailable` classifications can be emitted, unavailable metrics can be represented without invention, and no composite score is required for baseline comparison.

This checkpoint does not prove real-world scalability, live AWS correctness, runtime exploitability, production readiness, arbitrary enterprise graph correctness, broad IAMScope semantic correctness, generic resource-policy Deny support, finding-level resource-policy reachability, or frozen-corpus regression behavior.

## Frozen-Corpus Baseline Comparison Design

Purpose: future frozen-corpus baseline comparison should compare offline frozen-corpus batch JSON reports against explicitly named frozen-corpus baselines without introducing composite scoring or creating new live AWS evidence. The comparison should make batch-level and per-case changes visible while preserving the evidence boundary that these are already-frozen artifact summaries.

Non-goals:

- This is design only, not implementation.
- This is not a live AWS benchmark.
- This is not new benchmark collection.
- This is not raw artifact comparison.
- This is not a production-readiness proof.
- This is not a broad IAMScope correctness proof.
- This is not an arbitrary enterprise graph correctness proof.
- This is not a real-world scalability proof.
- This is not composite scoring.
- This is not ranking, grading, or pass/fail gating.

Supported inputs:

- Baseline frozen-corpus batch JSON report.
- Current frozen-corpus batch JSON report.
- Markdown reports as human-readable companions only, not machine-comparison inputs.
- No raw live artifacts.
- No Terraform artifacts.
- No `collect/` directories.

Comparison dimensions should stay per batch or per case:

- Case presence and absence.
- Case metadata changes where available, such as case ID, run ID, family, benchmark date, environment, authority, and confidence.
- Case status or classification changes where available, such as score result, artifact sufficiency, promotion-blocked status, human-review flag, assertion counts, defect counts, and scenario-validation status.
- Available batch summary count deltas, such as case count, evaluated cases, passes, failures, blocked promotions, artifact-insufficient cases, and human-review-required count.
- Unavailable metrics, which must remain `not_collected` or `unavailable_with_reason` and must not be inferred.
- Caveat changes.
- `offline_only` and `live_aws_used` consistency.
- `report_type` consistency.
- Artifact and snapshot path handling, where path differences should be shown as metadata differences rather than correctness verdicts.

Future comparison output should include:

- JSON comparison report.
- Markdown comparison report.
- Per-case `changed`, `unchanged`, and `unavailable` classification.
- Added, removed, and matched case classification.
- Batch summary deltas where available.
- Caveats.
- No composite score.
- No grade.
- No ranking.
- No pass/fail unless a future run explicitly supplies separate named thresholds.

Threshold policy:

- Default mode should be report-only.
- No thresholds should be used by default.
- There must be no hidden thresholds.
- Unavailable metrics must not be treated as zero.
- Case additions and removals should be highlighted, but not automatically pass or fail.
- Any future threshold gating must be explicit and separate from the report-only comparator.

Interpretation rules:

- Frozen-corpus comparison is offline artifact/report comparison.
- It does not create new live AWS evidence.
- It does not expand semantic correctness claims.
- Changed metadata or counts require human interpretation.
- Unavailable metrics must remain unavailable, not inferred.
- Differences may indicate report-schema drift, corpus changes, or benchmark behavior changes.
- Comparison results must not weaken semantic mutation-pair, degradation, stability, or artifact-hygiene checks.

Artifact hygiene:

- Comparison outputs must be written only to caller-provided paths.
- No raw artifacts may be copied.
- No Terraform artifacts may be created or committed.
- No uncontrolled benchmark run directories may be written.
- Safe JSON and Markdown summaries are the only intended output artifacts.

Minimal frozen-corpus baseline comparator command:

```bash
bash scripts/compare_frozen_corpus_baseline.sh \
  --baseline /tmp/iamscope-frozen-corpus-baseline.json \
  --current /tmp/iamscope-frozen-corpus-current.json \
  --json-out /tmp/iamscope-frozen-corpus-comparison.json \
  --markdown-out /tmp/iamscope-frozen-corpus-comparison.md
```

The minimal frozen-corpus comparator is scoped to frozen-corpus batch JSON reports only. It is report-only, uses no thresholds by default, emits no pass/fail result, emits no composite score, does not compare raw artifacts, does not run live AWS, and does not prove real-world scalability or broad IAMScope correctness.

## Frozen-Corpus Baseline Comparator Checkpoint

The frozen-corpus baseline comparator is now implemented. The comparator module is `benchmarks/scalability/frozen_corpus_baseline_compare.py`, and the runner is `scripts/compare_frozen_corpus_baseline.sh`.

Command:

```bash
bash scripts/compare_frozen_corpus_baseline.sh \
  --baseline /tmp/iamscope-frozen-corpus-baseline.json \
  --current /tmp/iamscope-frozen-corpus-current.json \
  --json-out /tmp/iamscope-frozen-corpus-comparison.json \
  --markdown-out /tmp/iamscope-frozen-corpus-comparison.md
```

Scope boundaries:

- Frozen-corpus batch JSON reports only.
- Offline/report-only comparison.
- No thresholds by default.
- No pass/fail behavior.
- No composite score.
- No raw artifact comparison.
- No live AWS.
- No Terraform.
- No collector, scoring, scenario-validation, or reasoner changes.
- No fixture changes.

Outputs:

- JSON comparison report.
- Markdown comparison report.
- Batch summary deltas where available.
- Per-case `added`, `removed`, and `matched` classification.
- Field-level `changed`, `unchanged`, and `unavailable` classification.
- Unavailable metrics are represented without treating them as zero.
- No grade, ranking, pass rate, severity, or production-readiness language.

This checkpoint proves only that frozen-corpus batch JSON reports can be compared in offline report-only mode, JSON and Markdown comparison reports can be generated, added/removed/matched case classifications can be emitted, changed/unchanged/unavailable field classifications can be emitted, unavailable metrics can be represented without invention, and no composite score is required for frozen-corpus baseline comparison.

This checkpoint does not prove real-world scalability, new live AWS correctness evidence, runtime exploitability, production readiness, arbitrary enterprise graph correctness, broad IAMScope semantic correctness, generic resource-policy Deny support, or finding-level resource-policy reachability.

## Baseline Artifact And Golden-Output Policy

Purpose: IAMScope benchmark and scalability reporting should handle generated reports, baseline outputs, and golden fixtures without weakening artifact hygiene or expanding benchmark claims. This policy defines which artifacts are forbidden, which outputs should stay local, and when a tiny committed fixture is acceptable for tests.

Artifact categories:

- Forbidden raw artifacts: files that must not be committed because they may contain raw live collection data, Terraform state, credentials, or uncontrolled run output.
- Generated run outputs: JSON and Markdown reports created by scalability, frozen-corpus, or comparator scripts during local review or CI diagnostics.
- Safe summary reports: bounded JSON or Markdown summaries that contain only safe metadata and preserve claim boundaries.
- Committed golden fixtures: small deterministic fixtures used by tests to exercise stable schemas or behavior.
- Committed golden comparison fixtures: tiny baseline/current or expected-comparison fixtures used only to test comparator behavior.
- Temporary local outputs: caller-provided output paths, preferably under `/tmp`, that are not intended for commit.

Forbidden artifacts:

- Terraform state, cache, lock, provider, and plugin artifacts.
- `collect/` directories or equivalent live collection directories.
- Raw live AWS artifacts.
- Raw `scenario.json`, `findings.json`, `binding_metadata.json`, or `run.log` files from live runs.
- Credentials, profiles, account secrets, cloud tokens, or environment dumps.
- Uncontrolled generated benchmark run directories.

Generated outputs:

- Scalability, frozen-corpus, and comparator JSON/Markdown reports should default to caller-provided paths, preferably under `/tmp`.
- Generated outputs should not be committed by default.
- Generated outputs may be used for local review, PR discussion, or CI diagnostics.
- Committing generated output requires an explicit golden-fixture rationale and must satisfy the committed-fixture criteria below.

Safe summary reports are acceptable only when they contain:

- No raw live artifacts.
- No credentials or secrets.
- Bounded metadata only.
- No Terraform artifacts.
- No uncontrolled case dumps.
- Claim-boundary language preserving synthetic/offline/report-only limits where relevant.
- No composite score. Composite scoring is currently forbidden unless a future policy explicitly allows it.

Committed golden fixtures must be:

- Small.
- Deterministic.
- Synthetic or sanitized.
- Purpose-specific.
- Stable in schema.
- Free of raw live AWS data.
- Free of secrets.
- Covered by tests.
- Stored in a dedicated fixture path such as `tests/fixtures/...` or an existing repo convention.
- Justified in nearby docs, test names, or test comments.

Committed golden comparison fixtures must be:

- Tiny.
- Deterministic.
- Synthetic or sanitized.
- Limited to safe summary fields.
- Able to include unavailable metrics where that behavior is under test.
- Free of pass/fail, grade, ranking, pass rate, or composite score semantics.
- Used only to test comparator behavior.
- Not presented as benchmark results.

Directory guidance:

- Generated local outputs should go to `/tmp` or another caller-provided path.
- Committed test fixtures should live under `tests/fixtures/...` or the closest existing fixture convention.
- Benchmark snapshots should remain under `benchmarks/snapshots/...` only for approved frozen safe artifacts.
- New repo-local run-output directories should not be created unless this policy is explicitly updated to allow them.

Review checklist for output-related PRs:

- Does this commit raw artifacts?
- Are outputs deterministic and bounded?
- Are secrets impossible or scrubbed?
- Is the artifact synthetic or sanitized?
- Is there a clear reason the artifact must be committed?
- Do generated outputs go to `/tmp` or another caller-provided path by default?
- Does the change preserve no-composite and no-overclaim language?
- Does `./scripts/check.sh` still catch forbidden artifacts?

Interaction with artifact hygiene:

- This policy complements `scripts/check_benchmark_artifact_hygiene.sh`.
- This policy does not weaken existing hygiene checks.
- Future hygiene checks may encode more of this policy.
- Policy violations should block PRs.

Minimal output-path policy checks now live in `tests/test_benchmark_scalability.py`. They exercise `scripts/run_scalability_benchmark.sh`, `scripts/run_frozen_corpus_batch_report.sh`, `scripts/compare_scalability_baseline.sh`, and `scripts/compare_frozen_corpus_baseline.sh` with caller-provided temporary output paths and with default stdout output, and assert that no repo-local generated outputs, raw artifact-like files, `collect/` directories, or uncontrolled run-output directories are created.

## Optional Per-Metric Threshold Policy Design

Purpose: optional per-metric regression thresholds may be useful later for highlighting changed benchmark behavior, but they must not create fake precision, composite scoring, or broad benchmark pass/fail claims. Thresholds should remain explicit, metric-specific review signals layered on top of report-only comparisons.

Non-goals:

- This is design only, not implementation.
- This is not default gating.
- This is not composite scoring.
- This is not a production-readiness proof.
- This is not a real-world scalability proof.
- This is not a broad IAMScope correctness proof.
- This is not an arbitrary enterprise graph correctness proof.
- This is not live AWS validation.
- This is not a replacement for human interpretation.

Threshold scope:

- `candidate_paths_considered`: optional numeric threshold on explicit per-fixture deltas.
- `constraint_evaluations`: optional numeric threshold on explicit per-fixture deltas.
- `artifact_load_time_ms`: optional numeric threshold with runtime and machine-context caveats.
- `wall_clock_runtime_ms`: optional numeric threshold with strong machine, load, platform, and CI-context caveats.
- Case counts where available: optional numeric threshold for frozen-corpus batch count deltas.
- `deterministic_output_stability` digest equality/change: categorical change only, not a numeric threshold.
- `failure_mode_classification` equality/change: categorical change only, not a numeric threshold.

Default behavior:

- Default mode remains report-only.
- Thresholds are absent unless explicitly supplied.
- `thresholds_used=false` unless thresholds are explicitly supplied.
- There must be no hidden thresholds.
- There must be no automatic pass/fail by default.

Allowed future threshold types:

- Absolute delta threshold.
- Relative percentage threshold.
- Categorical equality expectation.
- Presence/absence expectation for cases.
- Unavailable metric expectation.

Disallowed threshold types:

- Composite score.
- Total benchmark score.
- Grade.
- Ranking.
- Pass rate.
- Production-readiness score.
- Broad "tool passed benchmark" framing.

Runtime policy:

- Runtime thresholds are machine-dependent and noisy.
- Runtime threshold reports should record environment and context where possible, such as host class, OS, Python version, CI/local mode, and whether the run was contended.
- Runtime thresholds must not be used as correctness evidence.
- Runtime thresholds should not be compared across unrelated machines without an explicit caveat.

Unavailable metrics:

- Unavailable is not zero.
- Unavailable is not failure by default.
- Unavailable metrics can be highlighted.
- Future thresholds may explicitly expect availability, but only when configured.

Interpretation rules:

- A threshold breach is evidence of changed benchmark behavior, not automatically a bug.
- Threshold satisfaction is not proof of correctness or production readiness.
- Synthetic threshold results do not imply real-world scalability.
- Frozen-corpus threshold results do not create new live AWS evidence.
- Categorical digest or classification changes require review.
- Threshold results must not weaken mutation-pair, stability, degradation, artifact-hygiene, or claim-boundary checks.

Future threshold-aware output model:

- `thresholds_used=true` only when an explicit threshold config is supplied.
- `threshold_config_path` when supplied.
- Per-metric threshold evaluations.
- Per-fixture or per-case status.
- Caveats.
- No composite score.
- No global pass/fail unless a future policy explicitly designs a narrow CI gate separately.

Artifact hygiene:

- Threshold configs must be safe text, JSON, or YAML if committed.
- Generated threshold-aware reports should go to caller-provided paths.
- No raw artifacts.
- No Terraform artifacts.
- No generated output commits by default.

## Threshold Config Schema Design

Purpose: a future threshold config format should allow optional per-metric regression thresholds to be parsed later without introducing threshold execution, default gating, pass/fail benchmark behavior, or composite scoring. The schema should make every threshold explicit, justified, and reviewable.

Non-goals:

- This is design only, not implementation.
- This is not threshold execution.
- This is not default gating.
- This is not pass/fail benchmark behavior.
- This is not composite scoring.
- This is not a production-readiness proof.
- This is not a broad IAMScope correctness proof.
- This is not a real-world scalability proof.

Config scope:

- Synthetic scalability comparison reports.
- Frozen-corpus comparison reports.
- Explicit fixtures or cases.
- Explicit metrics or categorical fields.

Required future top-level fields:

- `schema_version`: threshold config schema version.
- `config_type`: expected value such as `iamscope_threshold_config`.
- `mode`: expected value such as `report_only` or `advisory`.
- `report_type`: target report family, such as `synthetic_scalability_baseline_comparison` or `frozen_corpus_baseline_comparison`.
- `thresholds`: list of explicit threshold entries.
- `caveats` or `notes`: human-readable context for interpreting the config.

Allowed future modes:

- `report_only`: parse and report threshold evaluations without gating.
- `advisory`: parse and emit review signals without gating.

Deferred and out of scope unless separately designed:

- `hard_gate`
- `fail_build`
- `production_ready`

Threshold entry fields:

- `target_type`: `fixture`, `case`, or `batch`.
- `target_name` or `selector`: explicit fixture, case, or batch selector.
- `metric`: explicit metric or categorical field.
- `comparison_type`: one allowed comparison type.
- `expected` or `delta_limit`: expected value, allowed delta, or availability expectation.
- `rationale`: why this threshold exists.
- `caveat`: interpretation warning, especially for runtime or machine-sensitive metrics.

Allowed comparison types:

- `max_absolute_delta`
- `max_relative_delta`
- `equals`
- `changed_or_unchanged`
- `must_be_available`
- `may_be_unavailable`

Disallowed config fields:

- `composite_score`
- `overall_score`
- `grade`
- `ranking`
- `pass_rate`
- `production_readiness`
- `broad_pass_fail`
- `severity`, unless separately designed in a future policy slice.

Runtime threshold schema requirements:

- Runtime threshold entries must include a machine or context note.
- Runtime threshold entries must state that runtime is not correctness evidence.
- Runtime threshold entries must caveat that cross-machine comparisons are unreliable without context.

Unavailable metric semantics:

- `unavailable`, `missing`, `zero`, and `not_collected` must remain distinct.
- `unavailable` and `missing` must not be treated as zero.
- `not_collected` must not be treated as zero.
- Future parser behavior should preserve these states in threshold reports.

Future parser validation expectations:

- Reject unknown `schema_version` unless explicitly supported.
- Reject composite, ranking, grading, pass-rate, production-readiness, and broad-pass/fail fields.
- Reject hidden or default thresholds.
- Require a `rationale` for every threshold entry.
- Preserve report-only default behavior.
- Fail closed on malformed config.

Example config:

```json
{
  "schema_version": "0.1",
  "config_type": "iamscope_threshold_config",
  "mode": "report_only",
  "report_type": "synthetic_scalability_baseline_comparison",
  "caveats": [
    "advisory_only",
    "no_composite_score",
    "threshold_satisfaction_is_not_correctness_or_production_readiness"
  ],
  "thresholds": [
    {
      "target_type": "fixture",
      "target_name": "constraint_heavy",
      "metric": "constraint_evaluations",
      "comparison_type": "max_absolute_delta",
      "delta_limit": 0,
      "rationale": "Constraint-evaluation count should stay deterministic for this synthetic fixture.",
      "caveat": "A change is a review signal, not automatically a bug."
    },
    {
      "target_type": "fixture",
      "target_name": "small",
      "metric": "deterministic_output_stability.fixture_digest",
      "comparison_type": "equals",
      "expected": "unchanged",
      "rationale": "Small fixture topology should remain stable unless intentionally changed.",
      "caveat": "Digest equality is a stability signal, not proof of semantic correctness."
    },
    {
      "target_type": "fixture",
      "target_name": "medium",
      "metric": "paths_validated",
      "comparison_type": "may_be_unavailable",
      "expected": "not_collected",
      "rationale": "The current minimal harness exposes this metric as not_collected.",
      "caveat": "Unavailable is distinct from zero."
    }
  ]
}
```

Artifact hygiene:

- Threshold configs are safe text files only if they contain no secrets, raw artifacts, Terraform artifacts, account credentials, or live collection dumps.
- Committed threshold configs must be small, deterministic, purpose-specific, and justified.
- Generated threshold reports should go to caller-provided paths.
- No raw artifacts.
- No Terraform artifacts.

## Threshold Config Parser Checkpoint

The threshold-config parser is now implemented in `benchmarks/scalability/threshold_config.py`. It supports JSON configs, validates schema only, and does not execute thresholds.

The parser validates:

- `schema_version`
- `config_type`
- `mode`
- `report_type`
- `thresholds` list
- Required threshold entry fields
- Allowed modes
- Allowed comparison types
- Runtime metric caveats
- `unavailable`, `missing`, `zero`, and `not_collected` distinctions

The parser rejects:

- Unsupported modes
- Unknown comparison types
- Unknown fields
- Forbidden fields at any level
- Malformed JSON
- Missing required top-level fields
- Malformed threshold entries
- Hidden or default threshold behavior
- Composite, ranking, pass-rate, production-readiness, severity, and broad-pass/fail style fields

Scope boundaries:

- Parser/validation only.
- No threshold execution.
- No threshold gates.
- No pass/fail benchmark behavior.
- No comparator or reporting output changes.
- No composite score.
- No live AWS.
- No raw artifacts.
- No Terraform artifacts.

This checkpoint proves only that threshold configs can be schema-validated, forbidden score/gate fields can be rejected, runtime thresholds require context caveats, unavailable/missing/zero/not_collected distinctions can be preserved, and the parser fails closed on malformed or unsupported configs.

This checkpoint does not prove threshold execution correctness, regression gate validity, production readiness, real-world scalability, broad IAMScope correctness, arbitrary enterprise graph correctness, live AWS correctness, generic resource-policy Deny support, or finding-level resource-policy reachability.

## Threshold Execution Semantics Design

Purpose: future threshold execution should apply parsed threshold configs to comparison reports without creating hidden gates, composite scoring, fake precision, or broad pass/fail claims. Execution should remain explicit, per-metric, report-first, and interpretable.

Non-goals:

- This is design only, not implementation.
- This is not default gating.
- This is not CI failure behavior.
- This is not composite scoring.
- This is not a production-readiness proof.
- This is not a broad IAMScope correctness proof.
- This is not a real-world scalability proof.
- This is not live AWS validation.
- This is not a replacement for human review.

Inputs:

- Parsed threshold config.
- Synthetic scalability comparison JSON report.
- Frozen-corpus comparison JSON report.
- No raw artifacts.
- No Markdown as machine input.

Supported future execution modes:

- `report_only`: evaluate thresholds and report statuses without gates.
- `advisory`: same as `report_only`, with review-priority language in output.

Explicitly deferred or disallowed unless separately designed:

- `hard_gate`
- `fail_build`
- `production_ready`

Future threshold evaluation output may include:

- `thresholds_used=true`
- `threshold_config_path`
- Per-threshold evaluation records
- Target type and target name
- Metric
- Comparison type
- Observed value
- Expected or limit value
- Result classification
- Rationale
- Caveat
- No composite score
- No global pass/fail

Non-gating result classifications:

- `satisfied`
- `breached`
- `unavailable`
- `not_applicable`
- `malformed_threshold`

Do not use:

- `pass`
- `fail`
- `severity`
- `grade`
- `score`
- `ranking`

Numeric threshold semantics:

- `max_absolute_delta`: compare an observed numeric delta with a configured absolute limit.
- `max_relative_delta`: compare an observed numeric relative delta with a configured percentage or ratio limit.
- `equals`: compare numeric values only when explicitly configured.
- Unavailable or missing values do not equal zero.
- Runtime metrics require machine/context caveats.
- Runtime breaches are performance signals, not correctness failures.

Categorical threshold semantics:

- `changed_or_unchanged`: compare observed changed/unchanged classification with the expected category.
- `equals`: compare observed categorical value with the expected value.
- `must_be_available`: classify unavailable or missing observed values as `breached` or `unavailable` according to the future output contract, but not as pass/fail.
- `may_be_unavailable`: classify unavailable observed values as expected, preserving the unavailable state.
- Digest and classification changes require review.
- Unavailable means unavailable, not failure by default.

Target matching semantics:

- `fixture`: match an explicit fixture by exact name.
- `case`: match an explicit case by exact case ID or configured selector.
- `batch`: match batch-level fields in the comparison report.
- Exact target name match is preferred.
- Missing target should produce `not_applicable` or `unavailable`, not pass/fail.
- Duplicate target names should fail closed or be marked `malformed_threshold`.
- Selectors must be explicit and bounded.

Interpretation rules:

- A breached threshold means changed benchmark behavior requiring review, not automatically a bug.
- A satisfied threshold is not proof of correctness.
- `report_only` and `advisory` output does not expand benchmark claims.
- Synthetic threshold results do not prove real-world scalability.
- Frozen-corpus threshold results do not create new live AWS evidence.
- Threshold results must be read with caveats and comparison context.

Artifact hygiene:

- Threshold evaluation outputs should go to caller-provided paths.
- Generated outputs should not be committed by default.
- No raw artifacts.
- No Terraform artifacts.
- Safe JSON and Markdown summaries only.

## Synthetic Threshold Evaluator

The synthetic threshold evaluator is now implemented. The evaluator lives at `benchmarks/scalability/threshold_evaluator.py`, the runner lives at `scripts/evaluate_synthetic_thresholds.sh`, and the implementation spec lives at `docs/specs/synthetic-threshold-evaluator.md`.

Command shape:

```bash
bash scripts/evaluate_synthetic_thresholds.sh \
  --threshold-config /tmp/iamscope-thresholds.json \
  --comparison /tmp/iamscope-scalability-comparison.json \
  --json-out /tmp/iamscope-threshold-evaluation.json \
  --markdown-out /tmp/iamscope-threshold-evaluation.md
```

Scope boundaries:

- Synthetic scalability comparison JSON only.
- Report-only or advisory evaluation only.
- No frozen-corpus threshold execution yet.
- No CI gating.
- No fail-build behavior.
- No pass/fail benchmark behavior.
- No composite score.
- No live AWS.
- No raw artifacts.
- No Terraform artifacts.
- No comparator, reporting, harness, scoring, reasoner, or fixture changes.
- No fixture changes.

Output:

- JSON threshold evaluation summary.
- Markdown threshold evaluation summary.
- Threshold result classifications only:
  - `satisfied`
  - `breached`
  - `unavailable`
  - `not_applicable`
  - `malformed_threshold`
- No pass/fail labels.
- No severity.
- No grade.
- No ranking.
- No global benchmark status.
- No composite score.

Supported comparison types:

- `max_absolute_delta`
- `max_relative_delta`
- `equals`
- `changed_or_unchanged`
- `must_be_available`
- `may_be_unavailable`

The evaluator preserves runtime caveats from threshold configs and keeps unavailable, missing, and `not_collected` values distinct from zero. Runtime breaches are performance review signals, not correctness failures.

This checkpoint proves only that parsed threshold configs can be applied to synthetic scalability comparison JSON in report-only/advisory mode, JSON and Markdown threshold evaluation summaries can be generated, supported threshold result classifications can be emitted, unavailable/missing/not_collected values are not treated as zero, and threshold evaluation can support review without composite scoring or gates.

This checkpoint does not prove threshold gate validity, CI gating readiness, production readiness, real-world scalability, broad IAMScope correctness, arbitrary enterprise graph correctness, live AWS correctness, frozen-corpus threshold behavior, generic resource-policy Deny support, or finding-level resource-policy reachability.

## Frozen-Corpus Threshold Evaluation Semantics Design

Purpose: future frozen-corpus threshold evaluation should apply parsed threshold configs to frozen-corpus baseline comparison JSON reports without creating new live AWS evidence, hidden gates, composite scoring, fake precision, or broad pass/fail claims. Evaluation should remain explicit, per-metric/per-case, report-first, and interpretable.

Non-goals:

- This is design only, not implementation.
- This is not default gating.
- This is not CI failure behavior.
- This is not new live AWS validation.
- This is not raw artifact comparison.
- This is not composite scoring.
- This is not a production-readiness proof.
- This is not a broad IAMScope correctness proof.
- This is not a real-world scalability proof.
- This is not a replacement for human review.

Inputs:

- Parsed threshold config.
- Frozen-corpus baseline comparison JSON report.
- No raw snapshot artifacts.
- No raw live AWS artifacts.
- No Terraform artifacts.
- No Markdown as machine input.

Supported future execution modes:

- `report_only`: evaluate thresholds and report statuses without gates.
- `advisory`: same as `report_only`, with review-priority language in output.

Explicitly deferred or disallowed unless separately designed:

- `hard_gate`
- `fail_build`
- `production_ready`

Future frozen-corpus threshold evaluation output may include:

- `report_type`, for example `frozen_corpus_threshold_evaluation`
- `thresholds_used=true`
- `threshold_config_path`
- `comparison_path`
- `evaluation_mode`
- Per-threshold evaluation records
- Target type and target name
- Metric or case field
- Comparison type
- Observed value
- Expected or limit value
- Result classification
- Rationale
- Caveat
- No composite score
- No global pass/fail

Non-gating result classifications:

- `satisfied`
- `breached`
- `unavailable`
- `not_applicable`
- `malformed_threshold`

Do not use:

- `pass`
- `fail`
- `severity`
- `grade`
- `score`
- `ranking`

Frozen-corpus-specific semantics:

- Case `added`, `removed`, and `matched` classifications are threshold targets only if explicitly configured.
- Snapshot path differences are metadata, not pass/fail outcomes.
- `offline_only` and `live_aws_used` consistency can be checked, but differences require review.
- `report_type` consistency can be checked.
- Batch summary deltas can be checked only if available in the comparison report.
- Per-case status or classification changes can be checked only if present in the comparison report.
- Unavailable fields remain unavailable, not zero.

Target matching semantics:

- `batch`: match batch-level fields in the frozen-corpus comparison report.
- `case`: match an explicit case by exact case identifier.
- Exact case identifier match is preferred.
- Missing cases should produce `not_applicable` or `unavailable`, unless explicitly configured otherwise.
- Duplicate case identifiers should fail closed or be marked `malformed_threshold`.
- Selectors must be explicit and bounded.

Interpretation rules:

- A breached threshold means changed offline report behavior requiring review, not automatically a bug.
- A satisfied threshold is not proof of correctness.
- Frozen-corpus threshold results do not create new live AWS evidence.
- Threshold results do not expand semantic correctness claims.
- Unavailable metrics must remain unavailable.
- Case additions and removals require human interpretation.
- `report_only` and `advisory` output does not imply production readiness.

Artifact hygiene:

- Threshold evaluation outputs should go to caller-provided paths.
- Generated outputs should not be committed by default.
- No raw artifacts.
- No Terraform artifacts.
- Safe JSON and Markdown summaries only.

## Frozen-Corpus Threshold Evaluator

The frozen-corpus threshold evaluator is now implemented. The evaluator lives at `benchmarks/scalability/frozen_threshold_evaluator.py`, and the runner lives at `scripts/evaluate_frozen_corpus_thresholds.sh`.

Command shape:

```bash
bash scripts/evaluate_frozen_corpus_thresholds.sh \
  --threshold-config /tmp/iamscope-frozen-thresholds.json \
  --comparison /tmp/iamscope-frozen-corpus-comparison.json \
  --json-out /tmp/iamscope-frozen-threshold-evaluation.json \
  --markdown-out /tmp/iamscope-frozen-threshold-evaluation.md
```

Scope boundaries:

- Frozen-corpus baseline comparison JSON only.
- Offline report-only or advisory evaluation only.
- No CI gating.
- No fail-build behavior.
- No pass/fail benchmark labels.
- No composite score.
- No raw artifact comparison.
- No new live AWS evidence.
- No live AWS.
- No raw artifacts.
- No Terraform artifacts.
- No comparator, reporting, harness, or fixture changes.
- No fixture changes.

Output:

- JSON frozen-corpus threshold evaluation summary.
- Markdown frozen-corpus threshold evaluation summary.
- `live_aws_used=false`.
- Threshold result classifications only:
  - `satisfied`
  - `breached`
  - `unavailable`
  - `not_applicable`
  - `malformed_threshold`
- No pass/fail labels.
- No severity.
- No grade.
- No ranking.
- No global benchmark status.
- No composite score.

Supported comparison types:

- `max_absolute_delta`
- `max_relative_delta`
- `equals`
- `changed_or_unchanged`
- `must_be_available`
- `may_be_unavailable`

The evaluator supports explicit `batch` and `case` targets. Case `added`, `removed`, and `matched` classifications are evaluated only when explicitly configured. Missing cases and fields produce non-gating `not_applicable` or `unavailable` classifications. Unavailable, missing, and `not_collected` values remain distinct from zero.

This checkpoint proves only that parsed threshold configs can be applied to frozen-corpus baseline comparison JSON in offline report-only/advisory mode, JSON and Markdown threshold evaluation summaries can be generated, supported threshold result classifications can be emitted, added/removed/matched case targets can be handled when explicitly configured, unavailable/missing/not_collected values are not treated as zero, and threshold evaluation can support offline review without composite scoring or gates.

This checkpoint does not prove threshold gate validity, CI gating readiness, production readiness, real-world scalability, broad IAMScope correctness, arbitrary enterprise graph correctness, new live AWS correctness evidence, generic resource-policy Deny support, or finding-level resource-policy reachability.

## Recommended Next Slice

Recommended next slice: final benchmark program maturity checkpoint after completing the threshold review layer.

This should be docs/checkpoint-only. The threshold review layer is now complete enough for the current phase, so the next step should summarize full benchmark program maturity and remaining unproven areas before deciding whether to stop or start a new phase. Do not add CI gating, fail-build behavior, pass/fail benchmark labels, composite scoring, new fixtures, live AWS, large graph work, or multiple slices at once.
