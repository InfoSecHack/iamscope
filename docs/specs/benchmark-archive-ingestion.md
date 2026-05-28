# Benchmark Archive Ingestion

## Scope
- Add the smallest Phase 0 ingestion step that turns a live benchmark archive into a normalized run manifest.
- Keep the output compatible with the existing Phase 0 validator, scorer, gate evaluator, and dry-run renderer.
- Do not change IAMScope reasoner logic or broaden benchmark scoring.

## Input archive shape
- Required:
  - `run.log`
  - `scenario_validate.txt`
  - `collect/scenario.json`
  - `collect/findings.json`
- Optional:
  - `collect/binding_metadata.json`
  - `expected_findings.json`

## Output contract
- The ingester emits one `benchmark_run_manifest` JSON document.
- It records:
  - `run_id`
  - `case_id`
  - `tool_name`
  - `git_sha` if available, else `null`
  - `started_at` / `ended_at` if inferable, else `null`
  - `benchmark_date`
  - `artifact_status.scenario_validation`
  - artifact paths for the archive contents that actually exist
  - enough `context` for current Phase 0 source/target filtering
- It must not claim optional artifacts that are absent.

## Phase 0 case support
- Env03 and Env05 are fully Phase 0-scored now.
- Env06 is included as a Phase 0 case only for the existing count-based positive-path assertions:
  - validated admin reachability present
  - blocked admin reachability absent
  - inconclusive admin reachability absent
- The separate live harness assertion that validated Env06 findings carry zero blockers remains outside the current Phase 0 scorer contract.