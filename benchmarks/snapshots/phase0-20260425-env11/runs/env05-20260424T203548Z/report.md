# Benchmark Dry Run: env05_permission_boundary_blocked_chain

- Run ID: `iamscope-benchmark-env05-20260424T203548Z`
- Artifact sufficient: `yes`
- Human review required: `yes`

## Directly Proven
- This exact boundary-blocked admin path is not overclaimed as validated.
- The blocked chain and blocked admin reachability are both observed for the benchmark path.

## Strongly Supported
- The current boundary resolution path is coherent for this narrow real-AWS case.

## Only Implied
- Broader positive-vs-blocked admin reachability behavior outside this path family is only implied.

## Still Unknown
- How boundary handling behaves across longer chains or richer policy shapes remains unproven here.
- Reasoner interactions outside the Env05 path family remain unknown here.

## Defects
- None

## Gate Results
- `artifact_sufficient`: `pass` (triggered_by=none)
- `false_admin_claim`: `pass` (triggered_by=none)
- `dishonest_degradation`: `pass` (triggered_by=none)
- `semantic_mismatch`: `pass` (triggered_by=none)

## Artifact Sufficiency
- Required scenario validation: `pass`
- Observed scenario validation: `pass`
