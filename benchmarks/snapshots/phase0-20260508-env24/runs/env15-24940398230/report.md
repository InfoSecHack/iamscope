# Benchmark Dry Run: env15_permission_condition_removed_validated_admin

- Run ID: `iamscope-benchmark-env15-24940398230`
- Artifact sufficient: `yes`
- Human review required: `yes`

## Directly Proven
- The exact Env15 alice->admin permission edge exists structurally.
- The exact Env15 alice->admin permission edge has no aws:MultiFactorAuthPresent condition evidence.
- The exact Env15 alice->admin trust edge exists structurally.
- The exact Env15 alice->admin path is emitted as validated admin reachability.
- The exact Env15 alice->admin path is not emitted as blocked or inconclusive.

## Strongly Supported
- IAMScope responds meaningfully to this narrow permission-condition removal in a controlled real-AWS case.

## Only Implied
- Broader permission-condition mutation behavior outside this exact case remains only implied.

## Still Unknown
- How richer permission-condition operators behave remains unknown here.
- Whether every permission-condition removal should validate remains unproven here.

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
