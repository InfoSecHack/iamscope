# Benchmark Dry Run: env09_boundary_removed_validated_admin

- Run ID: `iamscope-benchmark-env09-20260425T012013Z`
- Artifact sufficient: `yes`
- Human review required: `yes`

## Directly Proven
- This exact mutated admin path is emitted as validated.
- This exact mutated admin path is not emitted as blocked or inconclusive.

## Strongly Supported
- IAMScope responds meaningfully to this narrow boundary-removal change in a controlled real-AWS case.

## Only Implied
- Broader mutation-pair behavior outside this exact case remains only implied.

## Still Unknown
- How stable the same positive result is across richer two-hop policy shapes remains unknown here.
- Whether assume_role_chain consistently validates the same positive path remains unproven here.

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
