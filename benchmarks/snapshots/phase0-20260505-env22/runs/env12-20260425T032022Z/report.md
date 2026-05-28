# Benchmark Dry Run: env12_scp_blocked_assumerole

- Run ID: `iamscope-benchmark-env12-20260425T032022Z`
- Artifact sufficient: `yes`
- Human review required: `yes`

## Directly Proven
- The exact Env12 alice->admin permission edge exists structurally.
- The exact Env12 alice->admin trust edge exists structurally.
- A live Organizations SCP denying sts:AssumeRole on env12-admin is present in scenario.json.
- The Env12 trust edge is bound to an SCP constraint.
- The exact Env12 alice->admin path is not falsely emitted as validated admin reachability.

## Strongly Supported
- IAMScope can avoid shortcutting IAM-allowed paths into validated admin reachability when a target-scoped SCP blocks sts:AssumeRole.

## Only Implied
- Broader SCP family correctness remains only implied.

## Still Unknown
- Whether other SCP condition and exception forms produce the intended truth states remains outside this case.
- Whether multi-account cross-account AssumeRole paths interact with SCPs the same way remains outside this case.

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
