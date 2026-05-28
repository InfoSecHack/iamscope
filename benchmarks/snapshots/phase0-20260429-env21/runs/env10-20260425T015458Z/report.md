# Benchmark Dry Run: env10_trust_condition_removed_validated_admin

- Run ID: `iamscope-benchmark-env10-20260425T015458Z`
- Artifact sufficient: `yes`
- Human review required: `yes`

## Directly Proven
- The exact Env10 alice->admin permission edge exists structurally.
- The exact Env10 alice->admin trust edge exists structurally.
- The exact Env10 alice->admin path is emitted as validated admin reachability.
- The exact Env10 alice->admin path is not emitted as blocked or inconclusive.
- The Env10 trust edge is not bound to aws:MultiFactorAuthPresent TRUST_CONDITION evidence.

## Strongly Supported
- IAMScope responds meaningfully to this narrow trust-condition removal in a controlled real-AWS case.

## Only Implied
- Broader trust-condition mutation behavior outside this exact case remains only implied.

## Still Unknown
- How stable the same positive result is across richer trust-policy shapes remains unknown here.
- Whether every trust-condition removal should validate remains unproven here.

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
