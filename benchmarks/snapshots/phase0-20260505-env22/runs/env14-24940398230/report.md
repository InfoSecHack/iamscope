# Benchmark Dry Run: env14_permission_condition_blocked_admin

- Run ID: `iamscope-benchmark-env14-24940398230`
- Artifact sufficient: `yes`
- Human review required: `yes`

## Directly Proven
- The exact Env14 alice->admin permission edge exists structurally.
- The permission edge carries aws:MultiFactorAuthPresent condition evidence.
- The exact Env14 alice->admin trust edge exists structurally.
- The exact Env14 alice->admin path is not falsely emitted as validated admin reachability.

## Strongly Supported
- IAMScope can demote or hold uncertain a permission-conditioned admin path instead of overclaiming it as validated.

## Only Implied
- Broader permission-condition coverage remains only implied.

## Still Unknown
- How richer permission-condition operators behave remains unknown here.
- Whether other reasoner families should expose permission-condition evidence differently remains unknown here.

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
