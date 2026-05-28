# Benchmark Phase 0 Skeleton

## Scope
- Build the smallest useful benchmark/results-tracking skeleton around the two already-proven live AWS cases: Env03 and Env05.
- Do not add new AWS environments.
- Do not change IAMScope reasoner logic.
- Do not build dashboards or composite scores.

## Phase 0 contract
- Case manifests must state what the benchmark directly proves, what it does not prove, and what remains unknown.
- Run manifests must reference the retained benchmark artifacts: `scenario.json`, `findings.json`, `binding_metadata.json`, `run.log`, and `scenario_validate.txt`.
- Scoring is semantic-assertion based only: finding counts, blocker presence, and required-check presence.
- Gates are machine-checkable and anti-overclaim oriented.
- Reports must separate directly proven, strongly supported, only implied, and still unknown.

## Minimal implementation
- JSON manifests and JSON schema-like descriptor files under `benchmarks/schema/`.
- Python stdlib validator, scorer, gate evaluator, and Markdown renderer.
- Python stdlib archive ingester that normalizes a live benchmark archive into a Phase 0 run manifest.
- Python stdlib end-to-end archive evaluator that ingests, scores, gates, and renders a report in one step.
- Focused tests using the archived Env03/Env05 benchmark artifacts already present in the repo.
