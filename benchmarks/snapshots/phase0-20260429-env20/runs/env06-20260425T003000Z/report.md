# Benchmark Dry Run: env06_validated_admin_reachability

- Run ID: `iamscope-benchmark-env06-20260425T003000Z`
- Artifact sufficient: `yes`
- Human review required: `yes`

## Directly Proven
- This exact positive admin path is emitted as validated.
- This exact positive admin path is not emitted as blocked or inconclusive.

## Strongly Supported
- The current positive admin-reachability path is coherent for this narrow real-AWS case.

## Only Implied
- Broader positive-path coverage outside this exact case remains only implied.

## Still Unknown
- How validated admin reachability behaves across longer chains or richer trust-policy shapes remains unproven here.
- How stable the same positive-path result is across more complex mixed-signal environments remains unknown here.

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
