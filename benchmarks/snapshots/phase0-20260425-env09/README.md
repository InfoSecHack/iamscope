# Phase 0 Benchmark Snapshot: phase0-20260425-env09

- snapshot_id: `phase0-20260425-env09`
- created_at: `2026-04-25T01:26:18Z`
- source runs dir: `/tmp/iamscope-phase0-runs-all6`
- source corpus dir: `/tmp/iamscope-phase0-corpus-all6`
- corpus decision: `hold_review`

## Included Cases / Runs
- env05_permission_boundary_blocked_chain / iamscope-benchmark-env05-20260424T203548Z -> runs/env05-20260424T203548Z
- env07_validated_non_admin_reachability / iamscope-benchmark-env07-20260424T222444Z -> runs/env07-20260424T222444Z
- env08_trust_condition_blocked_admin / iamscope-benchmark-env08-20260425T002835Z -> runs/env08-20260425T002835Z
- env03_identity_deny_group_escalation / iamscope-benchmark-env03-20260424T025701Z -> runs/env03-20260424T025701Z
- env09_boundary_removed_validated_admin / iamscope-benchmark-env09-20260425T012013Z -> runs/env09-20260425T012013Z
- env06_validated_admin_reachability / iamscope-benchmark-env06-20260425T003000Z -> runs/env06-20260425T003000Z

## Directly Proven
- The blocked chain and blocked admin reachability are both observed for the benchmark path.
- The blocker attribution includes identity_deny evidence.
- The exact Env07 alice->reader path exists structurally as permission plus trust edges.
- The exact Env07 alice->reader path is not falsely emitted as admin reachability.
- The exact Env08 alice->conditioned-admin path is not falsely emitted as validated admin reachability.
- The exact Env08 alice->conditioned-admin permission edge exists structurally.
- The exact Env08 alice->conditioned-admin trust edge exists structurally.
- The trust edge carries TRUST_CONDITION evidence for aws:MultiFactorAuthPresent.
- This exact blocked group-escalation path is truthfully detected as blocked.
- This exact boundary-blocked admin path is not overclaimed as validated.
- This exact mutated admin path is emitted as validated.
- This exact mutated admin path is not emitted as blocked or inconclusive.
- This exact positive admin path is emitted as validated.
- This exact positive admin path is not emitted as blocked or inconclusive.

## Only Implied
- Broader deny coverage outside this exact path family is only implied, not directly proven.
- Broader mutation-pair behavior outside this exact case remains only implied.
- Broader non-admin scoring coverage remains only implied.
- Broader positive-path coverage outside this exact case remains only implied.
- Broader positive-vs-blocked admin reachability behavior outside this path family is only implied.
- Broader trust-condition coverage remains only implied.

## Still Unknown
- False-negative behavior for partially parsed or malformed deny policies remains unknown here.
- How boundary handling behaves across longer chains or richer policy shapes remains unproven here.
- How consistent the same guarded behavior is across richer multi-condition trust policies remains unknown here.
- How stable the same positive result is across richer two-hop policy shapes remains unknown here.
- How stable the same positive-path result is across more complex mixed-signal environments remains unknown here.
- How stable the same structural/non-admin behavior is across richer policy shapes remains unknown here.
- How the same deny logic behaves in more complex multi-hop paths remains unproven here.
- How validated admin reachability behaves across longer chains or richer trust-policy shapes remains unproven here.
- Reasoner interactions outside the Env05 path family remain unknown here.
- Whether assume_role_chain consistently validates the same positive path remains unproven here.
- Whether broader non-admin path families should become first-class findings remains unproven here.
- Whether other trust-condition shapes should resolve to blocked rather than inconclusive remains unknown here.
