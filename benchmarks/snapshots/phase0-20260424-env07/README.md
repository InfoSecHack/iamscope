# Phase 0 Benchmark Snapshot: phase0-20260424-env07

- snapshot_id: `phase0-20260424-env07`
- created_at: `2026-04-24T23:04:39Z`
- source runs dir: `/tmp/iamscope-phase0-runs-all4`
- source corpus dir: `/tmp/iamscope-phase0-corpus-all4`
- corpus decision: `hold_review`

## Included Cases / Runs
- env05_permission_boundary_blocked_chain / iamscope-benchmark-env05-20260424T203548Z -> runs/env05-20260424T203548Z
- env07_validated_non_admin_reachability / iamscope-benchmark-env07-20260424T222444Z -> runs/env07-20260424T222444Z
- env03_identity_deny_group_escalation / iamscope-benchmark-env03-20260424T025701Z -> runs/env03-20260424T025701Z
- env06_validated_admin_reachability / iamscope-benchmark-env06-20260424T044157Z -> runs/env06-20260424T044157Z

## Directly Proven
- The blocked chain and blocked admin reachability are both observed for the benchmark path.
- The blocker attribution includes identity_deny evidence.
- The exact Env07 alice->reader path exists structurally as permission plus trust edges.
- The exact Env07 alice->reader path is not falsely emitted as admin reachability.
- This exact blocked group-escalation path is truthfully detected as blocked.
- This exact boundary-blocked admin path is not overclaimed as validated.
- This exact positive admin path is emitted as validated.
- This exact positive admin path is not emitted as blocked or inconclusive.

## Only Implied
- Broader deny coverage outside this exact path family is only implied, not directly proven.
- Broader non-admin scoring coverage remains only implied.
- Broader positive-path coverage outside this exact case remains only implied.
- Broader positive-vs-blocked admin reachability behavior outside this path family is only implied.

## Still Unknown
- False-negative behavior for partially parsed or malformed deny policies remains unknown here.
- How boundary handling behaves across longer chains or richer policy shapes remains unproven here.
- How stable the same positive-path result is across more complex mixed-signal environments remains unknown here.
- How stable the same structural/non-admin behavior is across richer policy shapes remains unknown here.
- How the same deny logic behaves in more complex multi-hop paths remains unproven here.
- How validated admin reachability behaves across longer chains or richer trust-policy shapes remains unproven here.
- Reasoner interactions outside the Env05 path family remain unknown here.
- Whether broader non-admin path families should become first-class findings remains unproven here.
