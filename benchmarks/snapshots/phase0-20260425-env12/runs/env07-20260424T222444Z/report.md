# Benchmark Dry Run: env07_validated_non_admin_reachability

- Run ID: `iamscope-benchmark-env07-20260424T222444Z`
- Artifact sufficient: `yes`
- Human review required: `yes`

## Directly Proven
- The exact Env07 alice->reader path exists structurally as permission plus trust edges.
- The exact Env07 alice->reader path is not falsely emitted as admin reachability.

## Strongly Supported
- IAMScope can distinguish reachable non-admin structure from admin reachability for this narrow real-AWS case.

## Only Implied
- Broader non-admin scoring coverage remains only implied.

## Still Unknown
- Whether broader non-admin path families should become first-class findings remains unproven here.
- How stable the same structural/non-admin behavior is across richer policy shapes remains unknown here.

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
