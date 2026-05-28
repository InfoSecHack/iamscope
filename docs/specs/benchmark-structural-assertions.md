# Benchmark Structural Assertions

## Goal

Add the smallest benchmark-scoring extensions needed to machine-score structural benchmark evidence without inventing new finding surfaces.

## Supported Assertion Types

- `scenario_edge_count`
  - Filters: `edge_type`, `source_provider_id_from_context`, `target_provider_id_from_context`
  - Operators: `eq`, `gte`
- `scenario_constraint_count`
  - Filters: `constraint_type`, optional `condition_key_contains`
  - Operators: `eq`, `gte`
- `scenario_edge_constraint_count`
  - Filters: `edge_type`, `source_provider_id_from_context`, `target_provider_id_from_context`, `constraint_type`, optional `condition_key_contains`
  - Operators: `eq`, `gte`

## Truth Contract

- Structural assertions score only `scenario.json` edges, top-level constraints, and `edge_constraints`.
- They do not imply a dedicated finding exists.
- Env07 uses structural assertions to prove the expected AssumeRole permission and trust edges exist for the exact alice -> reader path.
- Env08 uses structural assertions to prove the expected trust condition exists and is bound to the exact alice -> conditioned-admin trust edge.
- False admin claims remain findings-based and continue to use `finding_count`.

## Out Of Scope

- No graph search or generalized path engine in benchmark scoring.
- No new IAMScope reasoner outputs.
- No change to existing findings-based assertion behavior.
