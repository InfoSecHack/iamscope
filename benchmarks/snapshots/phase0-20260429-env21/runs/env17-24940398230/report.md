# Benchmark Dry Run: env17_scp_removed_validated_admin

- Run ID: `iamscope-benchmark-env17-24940398230`
- Artifact sufficient: `yes`
- Human review required: `yes`

## Directly Proven
- The exact Env17 alice->admin permission edge exists structurally.
- The exact Env17 alice->admin trust edge exists structurally.
- The exact Env17 alice->admin trust edge is not bound to an SCP constraint.
- The exact Env17 alice->admin path is emitted as validated admin reachability.
- The exact Env17 alice->admin path is not emitted as blocked or inconclusive.
- The exact Env17 alice->admin path has no SCP blocker evidence.

## Strongly Supported
- IAMScope responds meaningfully to this narrow SCP-removal mutation in a controlled real-AWS case.

## Only Implied
- Broader SCP removal behavior outside this exact case remains only implied.

## Still Unknown
- Whether every complete SCP removal should validate remains unproven here.
- Whether multi-account AssumeRole paths interact with SCP removal the same way remains outside this case.

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
