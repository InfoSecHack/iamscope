# Benchmark Dry Run: env24_s3_resource_policy_allow

- Run ID: `iamscope-benchmark-env24-20260508T151202Z`
- Artifact sufficient: `yes`
- Human review required: `yes`

## Directly Proven
- The exact Env24 resource-policy Allow edge exists structurally.
- The exact Env24 edge is unconditioned and has resource-policy provenance.
- The Env24 target path is not accidentally witnessed by an identity-policy s3:GetObject edge.
- No generic RESOURCE_POLICY_DENY constraint is emitted.

## Strongly Supported
- IAMScope's S3 resource-policy Allow parser/binder/export path behaves coherently on one controlled live AWS fixture.

## Only Implied
- Broader resource-policy Allow correctness remains only implied.

## Still Unknown
- Env25 scoped-away mutation remains future work.
- Finding-level resource-policy Allow semantics remain outside this case.
- Conditioned resource-policy Allow statements remain outside this case.
- Generic resource-policy Deny remains explicitly de-scoped.

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
