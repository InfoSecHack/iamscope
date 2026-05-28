# Benchmark Dry Run: env13_complete_scp_blocked_assumerole

- Run ID: `iamscope-benchmark-env13-20260425T035707Z`
- Artifact sufficient: `yes`
- Human review required: `yes`

## Directly Proven
- The exact Env13 alice->admin permission edge exists structurally.
- The exact Env13 alice->admin trust edge exists structurally.
- A live Organizations SCP denying sts:AssumeRole with wildcard Resource is present in scenario.json.
- The Env13 trust edge is bound to an SCP constraint.
- The exact Env13 alice->admin path is emitted as blocked admin reachability with SCP blocker evidence.
- The exact Env13 alice->admin path is not falsely emitted as validated admin reachability.

## Strongly Supported
- IAMScope can distinguish partial/resource-scoped SCP evidence from complete wildcard-resource SCP blocking in this benchmark family.

## Only Implied
- Broader SCP family correctness remains only implied.

## Still Unknown
- Whether other SCP condition and exception forms produce the intended truth states remains outside this case.
- Whether multi-account cross-account AssumeRole paths interact with SCPs the same way remains outside this case.
- Whether the management caller PrincipalArn carveout works for every credential sourcing shape remains outside this case.

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
