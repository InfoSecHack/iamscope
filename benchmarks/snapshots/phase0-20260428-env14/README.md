# Phase 0 Benchmark Snapshot: phase0-20260428-env14

- snapshot_id: `phase0-20260428-env14`
- created_at: `2026-04-28T22:12:24Z`
- source runs dir: `/tmp/iamscope-phase0-runs-all11`
- source corpus dir: `/tmp/iamscope-phase0-corpus-all11`
- corpus decision: `hold_review`

## Included Cases / Runs
- env14_permission_condition_blocked_admin / iamscope-benchmark-env14-24940398230 -> runs/env14-24940398230
- env05_permission_boundary_blocked_chain / iamscope-benchmark-env05-20260424T203548Z -> runs/env05-20260424T203548Z
- env10_trust_condition_removed_validated_admin / iamscope-benchmark-env10-20260425T015458Z -> runs/env10-20260425T015458Z
- env13_complete_scp_blocked_assumerole / iamscope-benchmark-env13-20260425T035707Z -> runs/env13-20260425T035707Z
- env07_validated_non_admin_reachability / iamscope-benchmark-env07-20260424T222444Z -> runs/env07-20260424T222444Z
- env11_broad_trust_condition_blocked_admin / iamscope-benchmark-env11-20260425T020442Z -> runs/env11-20260425T020442Z
- env08_trust_condition_blocked_admin / iamscope-benchmark-env08-20260425T002835Z -> runs/env08-20260425T002835Z
- env03_identity_deny_group_escalation / iamscope-benchmark-env03-20260424T025701Z -> runs/env03-20260424T025701Z
- env12_scp_blocked_assumerole / iamscope-benchmark-env12-20260425T032022Z -> runs/env12-20260425T032022Z
- env09_boundary_removed_validated_admin / iamscope-benchmark-env09-20260425T012013Z -> runs/env09-20260425T012013Z
- env06_validated_admin_reachability / iamscope-benchmark-env06-20260425T003000Z -> runs/env06-20260425T003000Z

## Directly Proven
- A live Organizations SCP denying sts:AssumeRole on env12-admin is present in scenario.json.
- A live Organizations SCP denying sts:AssumeRole with wildcard Resource is present in scenario.json.
- The Env10 trust edge is not bound to aws:MultiFactorAuthPresent TRUST_CONDITION evidence.
- The Env11 target role has broad-looking trust structure.
- The Env12 trust edge is bound to an SCP constraint.
- The Env13 trust edge is bound to an SCP constraint.
- The blocked chain and blocked admin reachability are both observed for the benchmark path.
- The blocker attribution includes identity_deny evidence.
- The exact Env07 alice->reader path exists structurally as permission plus trust edges.
- The exact Env07 alice->reader path is not falsely emitted as admin reachability.
- The exact Env08 alice->conditioned-admin path is not falsely emitted as validated admin reachability.
- The exact Env08 alice->conditioned-admin permission edge exists structurally.
- The exact Env08 alice->conditioned-admin trust edge exists structurally.
- The exact Env10 alice->admin path is emitted as validated admin reachability.
- The exact Env10 alice->admin path is not emitted as blocked or inconclusive.
- The exact Env10 alice->admin permission edge exists structurally.
- The exact Env10 alice->admin trust edge exists structurally.
- The exact Env11 alice->broad-conditioned-admin path is not falsely emitted as validated admin reachability.
- The exact Env11 alice->broad-conditioned-admin permission edge exists structurally.
- The exact Env12 alice->admin path is not falsely emitted as validated admin reachability.
- The exact Env12 alice->admin permission edge exists structurally.
- The exact Env12 alice->admin trust edge exists structurally.
- The exact Env13 alice->admin path is emitted as blocked admin reachability with SCP blocker evidence.
- The exact Env13 alice->admin path is not falsely emitted as validated admin reachability.
- The exact Env13 alice->admin permission edge exists structurally.
- The exact Env13 alice->admin trust edge exists structurally.
- The exact Env14 alice->admin path is not falsely emitted as validated admin reachability.
- The exact Env14 alice->admin permission edge exists structurally.
- The exact Env14 alice->admin trust edge exists structurally.
- The permission edge carries aws:MultiFactorAuthPresent condition evidence.
- The trust edge carries TRUST_CONDITION evidence for aws:MultiFactorAuthPresent.
- This exact blocked group-escalation path is truthfully detected as blocked.
- This exact boundary-blocked admin path is not overclaimed as validated.
- This exact mutated admin path is emitted as validated.
- This exact mutated admin path is not emitted as blocked or inconclusive.
- This exact positive admin path is emitted as validated.
- This exact positive admin path is not emitted as blocked or inconclusive.

## Only Implied
- Broader SCP family correctness remains only implied.
- Broader broad-trust condition coverage remains only implied.
- Broader deny coverage outside this exact path family is only implied, not directly proven.
- Broader mutation-pair behavior outside this exact case remains only implied.
- Broader non-admin scoring coverage remains only implied.
- Broader permission-condition coverage remains only implied.
- Broader positive-path coverage outside this exact case remains only implied.
- Broader positive-vs-blocked admin reachability behavior outside this path family is only implied.
- Broader trust-condition coverage remains only implied.
- Broader trust-condition mutation behavior outside this exact case remains only implied.

## Still Unknown
- False-negative behavior for partially parsed or malformed deny policies remains unknown here.
- How boundary handling behaves across longer chains or richer policy shapes remains unproven here.
- How consistent the same guarded behavior is across richer multi-condition trust policies remains unknown here.
- How richer permission-condition operators behave remains unknown here.
- How stable the same positive result is across richer trust-policy shapes remains unknown here.
- How stable the same positive result is across richer two-hop policy shapes remains unknown here.
- How stable the same positive-path result is across more complex mixed-signal environments remains unknown here.
- How stable the same structural/non-admin behavior is across richer policy shapes remains unknown here.
- How the same deny logic behaves in more complex multi-hop paths remains unproven here.
- How validated admin reachability behaves across longer chains or richer trust-policy shapes remains unproven here.
- Reasoner interactions outside the Env05 path family remain unknown here.
- Whether assume_role_chain consistently validates the same positive path remains unproven here.
- Whether broader non-admin path families should become first-class findings remains unproven here.
- Whether every trust-condition removal should validate remains unproven here.
- Whether multi-account cross-account AssumeRole paths interact with SCPs the same way remains outside this case.
- Whether other SCP condition and exception forms produce the intended truth states remains outside this case.
- Whether other broad trust principal shapes behave the same way remains unknown here.
- Whether other condition operators should resolve to blocked rather than inconclusive remains unknown here.
- Whether other reasoner families should expose permission-condition evidence differently remains unknown here.
- Whether other trust-condition shapes should resolve to blocked rather than inconclusive remains unknown here.
- Whether the management caller PrincipalArn carveout works for every credential sourcing shape remains outside this case.
