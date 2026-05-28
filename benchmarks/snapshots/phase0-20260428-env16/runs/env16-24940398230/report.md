# Benchmark Dry Run: env16_identity_deny_removed_validated_group_escalation

- Run ID: `iamscope-benchmark-env16-24940398230`
- Artifact sufficient: `yes`
- Human review required: `yes`

## Directly Proven
- The exact Env16 alice->admins path is emitted as validated group membership escalation.
- The exact Env16 alice->admins path is not emitted as blocked or inconclusive.
- The exact Env16 alice->admins path has no identity_deny blocker evidence.

## Strongly Supported
- IAMScope responds meaningfully to this narrow identity-deny removal in a controlled real-AWS case.

## Only Implied
- Broader identity-deny mutation behavior outside this exact case remains only implied.

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
