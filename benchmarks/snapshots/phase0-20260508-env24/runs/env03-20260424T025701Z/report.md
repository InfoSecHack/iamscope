# Benchmark Dry Run: env03_identity_deny_group_escalation

- Run ID: `iamscope-benchmark-env03-20260424T025701Z`
- Artifact sufficient: `yes`
- Human review required: `yes`

## Directly Proven
- This exact blocked group-escalation path is truthfully detected as blocked.
- The blocker attribution includes identity_deny evidence.

## Strongly Supported
- The current deny binder + reasoner path is coherent for this narrow real-AWS case.

## Only Implied
- Broader deny coverage outside this exact path family is only implied, not directly proven.

## Still Unknown
- How the same deny logic behaves in more complex multi-hop paths remains unproven here.
- False-negative behavior for partially parsed or malformed deny policies remains unknown here.

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
