# Benchmark Dry Run: env25_s3_resource_policy_allow_scoped_away_nonvalidated

- Run ID: `iamscope-benchmark-env25-20260508T210637Z`
- Artifact sufficient: `yes`
- Human review required: `yes`

## Directly Proven
- The exact Env25 decoy resource-policy Allow edge exists structurally.
- The exact Env25 reader resource-policy Allow edge is absent.
- The Env25 decoy edge is unconditioned and has resource-policy provenance.
- The Env25 reader path is not accidentally witnessed by an identity-policy s3:GetObject edge.
- No generic RESOURCE_POLICY_DENY constraint is emitted.

## Strongly Supported
- IAMScope's S3 resource-policy Allow parser/binder/export path respects exact principal scoping on one controlled live AWS fixture.

## Only Implied
- Broader resource-policy Allow correctness remains only implied.

## Still Unknown
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
