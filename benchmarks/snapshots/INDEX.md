# Benchmark Snapshot Index

Generated from `benchmarks/snapshots`.
This index summarizes only the frozen benchmark snapshots present here. It does not claim broad IAMScope correctness.

## phase0-20260424

- Corpus decision: `hold_review`
- Total cases evaluated: `3`
- Passes: `3`
- Failures: `0`
- Blocked promotions: `0`
- Artifact insufficient count: `0`
- Human review required count: `3`
- README: `benchmarks/snapshots/phase0-20260424/README.md`
- Corpus report: `benchmarks/snapshots/phase0-20260424/corpus/corpus_report.md`

### Included Cases / Runs
- `env03_identity_deny_group_escalation` / `iamscope-benchmark-env03-20260424T025701Z`
- `env05_permission_boundary_blocked_chain` / `iamscope-benchmark-env05-20260424T203548Z`
- `env06_validated_admin_reachability` / `iamscope-benchmark-env06-20260424T044157Z`

### Directly Proven
- The blocked chain and blocked admin reachability are both observed for the benchmark path.
- The blocker attribution includes identity_deny evidence.
- This exact blocked group-escalation path is truthfully detected as blocked.
- This exact boundary-blocked admin path is not overclaimed as validated.
- This exact positive admin path is emitted as validated.
- This exact positive admin path is not emitted as blocked or inconclusive.

### Still Unknown
- False-negative behavior for partially parsed or malformed deny policies remains unknown here.
- How boundary handling behaves across longer chains or richer policy shapes remains unproven here.
- How stable the same positive-path result is across more complex mixed-signal environments remains unknown here.
- How the same deny logic behaves in more complex multi-hop paths remains unproven here.
- How validated admin reachability behaves across longer chains or richer trust-policy shapes remains unproven here.
- Reasoner interactions outside the Env05 path family remain unknown here.

## phase0-20260424-env07

- Corpus decision: `hold_review`
- Total cases evaluated: `4`
- Passes: `4`
- Failures: `0`
- Blocked promotions: `0`
- Artifact insufficient count: `0`
- Human review required count: `4`
- README: `benchmarks/snapshots/phase0-20260424-env07/README.md`
- Corpus report: `benchmarks/snapshots/phase0-20260424-env07/corpus/corpus_report.md`

### Included Cases / Runs
- `env03_identity_deny_group_escalation` / `iamscope-benchmark-env03-20260424T025701Z`
- `env05_permission_boundary_blocked_chain` / `iamscope-benchmark-env05-20260424T203548Z`
- `env06_validated_admin_reachability` / `iamscope-benchmark-env06-20260424T044157Z`
- `env07_validated_non_admin_reachability` / `iamscope-benchmark-env07-20260424T222444Z`

### Directly Proven
- The blocked chain and blocked admin reachability are both observed for the benchmark path.
- The blocker attribution includes identity_deny evidence.
- The exact Env07 alice->reader path exists structurally as permission plus trust edges.
- The exact Env07 alice->reader path is not falsely emitted as admin reachability.
- This exact blocked group-escalation path is truthfully detected as blocked.
- This exact boundary-blocked admin path is not overclaimed as validated.
- This exact positive admin path is emitted as validated.
- This exact positive admin path is not emitted as blocked or inconclusive.

### Still Unknown
- False-negative behavior for partially parsed or malformed deny policies remains unknown here.
- How boundary handling behaves across longer chains or richer policy shapes remains unproven here.
- How stable the same positive-path result is across more complex mixed-signal environments remains unknown here.
- How stable the same structural/non-admin behavior is across richer policy shapes remains unknown here.
- How the same deny logic behaves in more complex multi-hop paths remains unproven here.
- How validated admin reachability behaves across longer chains or richer trust-policy shapes remains unproven here.
- Reasoner interactions outside the Env05 path family remain unknown here.
- Whether broader non-admin path families should become first-class findings remains unproven here.

## phase0-20260425-env08

- Corpus decision: `hold_review`
- Total cases evaluated: `5`
- Passes: `5`
- Failures: `0`
- Blocked promotions: `0`
- Artifact insufficient count: `0`
- Human review required count: `5`
- README: `benchmarks/snapshots/phase0-20260425-env08/README.md`
- Corpus report: `benchmarks/snapshots/phase0-20260425-env08/corpus/corpus_report.md`

### Included Cases / Runs
- `env03_identity_deny_group_escalation` / `iamscope-benchmark-env03-20260424T025701Z`
- `env05_permission_boundary_blocked_chain` / `iamscope-benchmark-env05-20260424T203548Z`
- `env06_validated_admin_reachability` / `iamscope-benchmark-env06-20260425T003000Z`
- `env07_validated_non_admin_reachability` / `iamscope-benchmark-env07-20260424T222444Z`
- `env08_trust_condition_blocked_admin` / `iamscope-benchmark-env08-20260425T002835Z`

### Directly Proven
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
- This exact positive admin path is emitted as validated.
- This exact positive admin path is not emitted as blocked or inconclusive.

### Still Unknown
- False-negative behavior for partially parsed or malformed deny policies remains unknown here.
- How boundary handling behaves across longer chains or richer policy shapes remains unproven here.
- How consistent the same guarded behavior is across richer multi-condition trust policies remains unknown here.
- How stable the same positive-path result is across more complex mixed-signal environments remains unknown here.
- How stable the same structural/non-admin behavior is across richer policy shapes remains unknown here.
- How the same deny logic behaves in more complex multi-hop paths remains unproven here.
- How validated admin reachability behaves across longer chains or richer trust-policy shapes remains unproven here.
- Reasoner interactions outside the Env05 path family remain unknown here.
- Whether broader non-admin path families should become first-class findings remains unproven here.
- Whether other trust-condition shapes should resolve to blocked rather than inconclusive remains unknown here.

## phase0-20260425-env09

- Corpus decision: `hold_review`
- Total cases evaluated: `6`
- Passes: `6`
- Failures: `0`
- Blocked promotions: `0`
- Artifact insufficient count: `0`
- Human review required count: `6`
- README: `benchmarks/snapshots/phase0-20260425-env09/README.md`
- Corpus report: `benchmarks/snapshots/phase0-20260425-env09/corpus/corpus_report.md`

### Included Cases / Runs
- `env03_identity_deny_group_escalation` / `iamscope-benchmark-env03-20260424T025701Z`
- `env05_permission_boundary_blocked_chain` / `iamscope-benchmark-env05-20260424T203548Z`
- `env06_validated_admin_reachability` / `iamscope-benchmark-env06-20260425T003000Z`
- `env07_validated_non_admin_reachability` / `iamscope-benchmark-env07-20260424T222444Z`
- `env08_trust_condition_blocked_admin` / `iamscope-benchmark-env08-20260425T002835Z`
- `env09_boundary_removed_validated_admin` / `iamscope-benchmark-env09-20260425T012013Z`

### Mutation Signals
- Mutation signal present without pairwise scoring: Env05 boundary-present case remains blocked/non-validated, while Env09 boundary-removed case validates admin reachability.

### Directly Proven
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

### Still Unknown
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

## phase0-20260425-env10

- Corpus decision: `hold_review`
- Total cases evaluated: `7`
- Passes: `7`
- Failures: `0`
- Blocked promotions: `0`
- Artifact insufficient count: `0`
- Human review required count: `7`
- README: `benchmarks/snapshots/phase0-20260425-env10/README.md`
- Corpus report: `benchmarks/snapshots/phase0-20260425-env10/corpus/corpus_report.md`

### Included Cases / Runs
- `env03_identity_deny_group_escalation` / `iamscope-benchmark-env03-20260424T025701Z`
- `env05_permission_boundary_blocked_chain` / `iamscope-benchmark-env05-20260424T203548Z`
- `env06_validated_admin_reachability` / `iamscope-benchmark-env06-20260425T003000Z`
- `env07_validated_non_admin_reachability` / `iamscope-benchmark-env07-20260424T222444Z`
- `env08_trust_condition_blocked_admin` / `iamscope-benchmark-env08-20260425T002835Z`
- `env09_boundary_removed_validated_admin` / `iamscope-benchmark-env09-20260425T012013Z`
- `env10_trust_condition_removed_validated_admin` / `iamscope-benchmark-env10-20260425T015458Z`

### Mutation Signals
- Mutation signal present without pairwise scoring: Env05 boundary-present case remains blocked/non-validated, while Env09 boundary-removed case validates admin reachability.

### Directly Proven
- The Env10 trust edge is not bound to aws:MultiFactorAuthPresent TRUST_CONDITION evidence.
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
- The trust edge carries TRUST_CONDITION evidence for aws:MultiFactorAuthPresent.
- This exact blocked group-escalation path is truthfully detected as blocked.
- This exact boundary-blocked admin path is not overclaimed as validated.
- This exact mutated admin path is emitted as validated.
- This exact mutated admin path is not emitted as blocked or inconclusive.
- This exact positive admin path is emitted as validated.
- This exact positive admin path is not emitted as blocked or inconclusive.

### Still Unknown
- False-negative behavior for partially parsed or malformed deny policies remains unknown here.
- How boundary handling behaves across longer chains or richer policy shapes remains unproven here.
- How consistent the same guarded behavior is across richer multi-condition trust policies remains unknown here.
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
- Whether other trust-condition shapes should resolve to blocked rather than inconclusive remains unknown here.

## phase0-20260425-env11

- Corpus decision: `hold_review`
- Total cases evaluated: `8`
- Passes: `8`
- Failures: `0`
- Blocked promotions: `0`
- Artifact insufficient count: `0`
- Human review required count: `8`
- README: `benchmarks/snapshots/phase0-20260425-env11/README.md`
- Corpus report: `benchmarks/snapshots/phase0-20260425-env11/corpus/corpus_report.md`

### Included Cases / Runs
- `env03_identity_deny_group_escalation` / `iamscope-benchmark-env03-20260424T025701Z`
- `env05_permission_boundary_blocked_chain` / `iamscope-benchmark-env05-20260424T203548Z`
- `env06_validated_admin_reachability` / `iamscope-benchmark-env06-20260425T003000Z`
- `env07_validated_non_admin_reachability` / `iamscope-benchmark-env07-20260424T222444Z`
- `env08_trust_condition_blocked_admin` / `iamscope-benchmark-env08-20260425T002835Z`
- `env09_boundary_removed_validated_admin` / `iamscope-benchmark-env09-20260425T012013Z`
- `env10_trust_condition_removed_validated_admin` / `iamscope-benchmark-env10-20260425T015458Z`
- `env11_broad_trust_condition_blocked_admin` / `iamscope-benchmark-env11-20260425T020442Z`

### Mutation Signals
- Mutation signal present without pairwise scoring: Env05 boundary-present case remains blocked/non-validated, while Env09 boundary-removed case validates admin reachability.

### Directly Proven
- The Env10 trust edge is not bound to aws:MultiFactorAuthPresent TRUST_CONDITION evidence.
- The Env11 target role has broad-looking trust structure.
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
- The trust edge carries TRUST_CONDITION evidence for aws:MultiFactorAuthPresent.
- This exact blocked group-escalation path is truthfully detected as blocked.
- This exact boundary-blocked admin path is not overclaimed as validated.
- This exact mutated admin path is emitted as validated.
- This exact mutated admin path is not emitted as blocked or inconclusive.
- This exact positive admin path is emitted as validated.
- This exact positive admin path is not emitted as blocked or inconclusive.

### Still Unknown
- False-negative behavior for partially parsed or malformed deny policies remains unknown here.
- How boundary handling behaves across longer chains or richer policy shapes remains unproven here.
- How consistent the same guarded behavior is across richer multi-condition trust policies remains unknown here.
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
- Whether other broad trust principal shapes behave the same way remains unknown here.
- Whether other condition operators should resolve to blocked rather than inconclusive remains unknown here.
- Whether other trust-condition shapes should resolve to blocked rather than inconclusive remains unknown here.

## phase0-20260425-env12

- Corpus decision: `hold_review`
- Total cases evaluated: `9`
- Passes: `9`
- Failures: `0`
- Blocked promotions: `0`
- Artifact insufficient count: `0`
- Human review required count: `9`
- README: `benchmarks/snapshots/phase0-20260425-env12/README.md`
- Corpus report: `benchmarks/snapshots/phase0-20260425-env12/corpus/corpus_report.md`

### Included Cases / Runs
- `env03_identity_deny_group_escalation` / `iamscope-benchmark-env03-20260424T025701Z`
- `env05_permission_boundary_blocked_chain` / `iamscope-benchmark-env05-20260424T203548Z`
- `env06_validated_admin_reachability` / `iamscope-benchmark-env06-20260425T003000Z`
- `env07_validated_non_admin_reachability` / `iamscope-benchmark-env07-20260424T222444Z`
- `env08_trust_condition_blocked_admin` / `iamscope-benchmark-env08-20260425T002835Z`
- `env09_boundary_removed_validated_admin` / `iamscope-benchmark-env09-20260425T012013Z`
- `env10_trust_condition_removed_validated_admin` / `iamscope-benchmark-env10-20260425T015458Z`
- `env11_broad_trust_condition_blocked_admin` / `iamscope-benchmark-env11-20260425T020442Z`
- `env12_scp_blocked_assumerole` / `iamscope-benchmark-env12-20260425T032022Z`

### Mutation Signals
- Mutation signal present without pairwise scoring: Env05 boundary-present case remains blocked/non-validated, while Env09 boundary-removed case validates admin reachability.

### Directly Proven
- A live Organizations SCP denying sts:AssumeRole on env12-admin is present in scenario.json.
- The Env10 trust edge is not bound to aws:MultiFactorAuthPresent TRUST_CONDITION evidence.
- The Env11 target role has broad-looking trust structure.
- The Env12 trust edge is bound to an SCP constraint.
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
- The trust edge carries TRUST_CONDITION evidence for aws:MultiFactorAuthPresent.
- This exact blocked group-escalation path is truthfully detected as blocked.
- This exact boundary-blocked admin path is not overclaimed as validated.
- This exact mutated admin path is emitted as validated.
- This exact mutated admin path is not emitted as blocked or inconclusive.
- This exact positive admin path is emitted as validated.
- This exact positive admin path is not emitted as blocked or inconclusive.

### Still Unknown
- False-negative behavior for partially parsed or malformed deny policies remains unknown here.
- How boundary handling behaves across longer chains or richer policy shapes remains unproven here.
- How consistent the same guarded behavior is across richer multi-condition trust policies remains unknown here.
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
- Whether other trust-condition shapes should resolve to blocked rather than inconclusive remains unknown here.

## phase0-20260425-env13

- Corpus decision: `hold_review`
- Total cases evaluated: `10`
- Passes: `10`
- Failures: `0`
- Blocked promotions: `0`
- Artifact insufficient count: `0`
- Human review required count: `10`
- README: `benchmarks/snapshots/phase0-20260425-env13/README.md`
- Corpus report: `benchmarks/snapshots/phase0-20260425-env13/corpus/corpus_report.md`

### Included Cases / Runs
- `env03_identity_deny_group_escalation` / `iamscope-benchmark-env03-20260424T025701Z`
- `env05_permission_boundary_blocked_chain` / `iamscope-benchmark-env05-20260424T203548Z`
- `env06_validated_admin_reachability` / `iamscope-benchmark-env06-20260425T003000Z`
- `env07_validated_non_admin_reachability` / `iamscope-benchmark-env07-20260424T222444Z`
- `env08_trust_condition_blocked_admin` / `iamscope-benchmark-env08-20260425T002835Z`
- `env09_boundary_removed_validated_admin` / `iamscope-benchmark-env09-20260425T012013Z`
- `env10_trust_condition_removed_validated_admin` / `iamscope-benchmark-env10-20260425T015458Z`
- `env11_broad_trust_condition_blocked_admin` / `iamscope-benchmark-env11-20260425T020442Z`
- `env12_scp_blocked_assumerole` / `iamscope-benchmark-env12-20260425T032022Z`
- `env13_complete_scp_blocked_assumerole` / `iamscope-benchmark-env13-20260425T035707Z`

### Mutation Signals
- Mutation signal present without pairwise scoring: Env05 boundary-present case remains blocked/non-validated, while Env09 boundary-removed case validates admin reachability.

### Directly Proven
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
- The trust edge carries TRUST_CONDITION evidence for aws:MultiFactorAuthPresent.
- This exact blocked group-escalation path is truthfully detected as blocked.
- This exact boundary-blocked admin path is not overclaimed as validated.
- This exact mutated admin path is emitted as validated.
- This exact mutated admin path is not emitted as blocked or inconclusive.
- This exact positive admin path is emitted as validated.
- This exact positive admin path is not emitted as blocked or inconclusive.

### Still Unknown
- False-negative behavior for partially parsed or malformed deny policies remains unknown here.
- How boundary handling behaves across longer chains or richer policy shapes remains unproven here.
- How consistent the same guarded behavior is across richer multi-condition trust policies remains unknown here.
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
- Whether other trust-condition shapes should resolve to blocked rather than inconclusive remains unknown here.
- Whether the management caller PrincipalArn carveout works for every credential sourcing shape remains outside this case.

## phase0-20260428-env14

- Corpus decision: `hold_review`
- Total cases evaluated: `11`
- Passes: `11`
- Failures: `0`
- Blocked promotions: `0`
- Artifact insufficient count: `0`
- Human review required count: `11`
- README: `benchmarks/snapshots/phase0-20260428-env14/README.md`
- Corpus report: `benchmarks/snapshots/phase0-20260428-env14/corpus/corpus_report.md`

### Included Cases / Runs
- `env03_identity_deny_group_escalation` / `iamscope-benchmark-env03-20260424T025701Z`
- `env05_permission_boundary_blocked_chain` / `iamscope-benchmark-env05-20260424T203548Z`
- `env06_validated_admin_reachability` / `iamscope-benchmark-env06-20260425T003000Z`
- `env07_validated_non_admin_reachability` / `iamscope-benchmark-env07-20260424T222444Z`
- `env08_trust_condition_blocked_admin` / `iamscope-benchmark-env08-20260425T002835Z`
- `env09_boundary_removed_validated_admin` / `iamscope-benchmark-env09-20260425T012013Z`
- `env10_trust_condition_removed_validated_admin` / `iamscope-benchmark-env10-20260425T015458Z`
- `env11_broad_trust_condition_blocked_admin` / `iamscope-benchmark-env11-20260425T020442Z`
- `env12_scp_blocked_assumerole` / `iamscope-benchmark-env12-20260425T032022Z`
- `env13_complete_scp_blocked_assumerole` / `iamscope-benchmark-env13-20260425T035707Z`
- `env14_permission_condition_blocked_admin` / `iamscope-benchmark-env14-24940398230`

### Mutation Signals
- Mutation signal present without pairwise scoring: Env05 boundary-present case remains blocked/non-validated, while Env09 boundary-removed case validates admin reachability.

### Directly Proven
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

### Still Unknown
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

## phase0-20260428-env15

- Corpus decision: `hold_review`
- Total cases evaluated: `12`
- Passes: `12`
- Failures: `0`
- Blocked promotions: `0`
- Artifact insufficient count: `0`
- Human review required count: `12`
- README: `benchmarks/snapshots/phase0-20260428-env15/README.md`
- Corpus report: `benchmarks/snapshots/phase0-20260428-env15/corpus/corpus_report.md`

### Included Cases / Runs
- `env03_identity_deny_group_escalation` / `iamscope-benchmark-env03-20260424T025701Z`
- `env05_permission_boundary_blocked_chain` / `iamscope-benchmark-env05-20260424T203548Z`
- `env06_validated_admin_reachability` / `iamscope-benchmark-env06-20260425T003000Z`
- `env07_validated_non_admin_reachability` / `iamscope-benchmark-env07-20260424T222444Z`
- `env08_trust_condition_blocked_admin` / `iamscope-benchmark-env08-20260425T002835Z`
- `env09_boundary_removed_validated_admin` / `iamscope-benchmark-env09-20260425T012013Z`
- `env10_trust_condition_removed_validated_admin` / `iamscope-benchmark-env10-20260425T015458Z`
- `env11_broad_trust_condition_blocked_admin` / `iamscope-benchmark-env11-20260425T020442Z`
- `env12_scp_blocked_assumerole` / `iamscope-benchmark-env12-20260425T032022Z`
- `env13_complete_scp_blocked_assumerole` / `iamscope-benchmark-env13-20260425T035707Z`
- `env14_permission_condition_blocked_admin` / `iamscope-benchmark-env14-24940398230`
- `env15_permission_condition_removed_validated_admin` / `iamscope-benchmark-env15-24940398230`

### Mutation Signals
- Mutation signal present without pairwise scoring: Env05 boundary-present case remains blocked/non-validated, while Env09 boundary-removed case validates admin reachability.

### Directly Proven
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
- The exact Env15 alice->admin path is emitted as validated admin reachability.
- The exact Env15 alice->admin path is not emitted as blocked or inconclusive.
- The exact Env15 alice->admin permission edge exists structurally.
- The exact Env15 alice->admin permission edge has no aws:MultiFactorAuthPresent condition evidence.
- The exact Env15 alice->admin trust edge exists structurally.
- The permission edge carries aws:MultiFactorAuthPresent condition evidence.
- The trust edge carries TRUST_CONDITION evidence for aws:MultiFactorAuthPresent.
- This exact blocked group-escalation path is truthfully detected as blocked.
- This exact boundary-blocked admin path is not overclaimed as validated.
- This exact mutated admin path is emitted as validated.
- This exact mutated admin path is not emitted as blocked or inconclusive.
- This exact positive admin path is emitted as validated.
- This exact positive admin path is not emitted as blocked or inconclusive.

### Still Unknown
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
- Whether every permission-condition removal should validate remains unproven here.
- Whether every trust-condition removal should validate remains unproven here.
- Whether multi-account cross-account AssumeRole paths interact with SCPs the same way remains outside this case.
- Whether other SCP condition and exception forms produce the intended truth states remains outside this case.
- Whether other broad trust principal shapes behave the same way remains unknown here.
- Whether other condition operators should resolve to blocked rather than inconclusive remains unknown here.
- Whether other reasoner families should expose permission-condition evidence differently remains unknown here.
- Whether other trust-condition shapes should resolve to blocked rather than inconclusive remains unknown here.
- Whether the management caller PrincipalArn carveout works for every credential sourcing shape remains outside this case.

## phase0-20260428-env16

- Corpus decision: `hold_review`
- Total cases evaluated: `13`
- Passes: `13`
- Failures: `0`
- Blocked promotions: `0`
- Artifact insufficient count: `0`
- Human review required count: `13`
- README: `benchmarks/snapshots/phase0-20260428-env16/README.md`
- Corpus report: `benchmarks/snapshots/phase0-20260428-env16/corpus/corpus_report.md`

### Included Cases / Runs
- `env03_identity_deny_group_escalation` / `iamscope-benchmark-env03-20260424T025701Z`
- `env05_permission_boundary_blocked_chain` / `iamscope-benchmark-env05-20260424T203548Z`
- `env06_validated_admin_reachability` / `iamscope-benchmark-env06-20260425T003000Z`
- `env07_validated_non_admin_reachability` / `iamscope-benchmark-env07-20260424T222444Z`
- `env08_trust_condition_blocked_admin` / `iamscope-benchmark-env08-20260425T002835Z`
- `env09_boundary_removed_validated_admin` / `iamscope-benchmark-env09-20260425T012013Z`
- `env10_trust_condition_removed_validated_admin` / `iamscope-benchmark-env10-20260425T015458Z`
- `env11_broad_trust_condition_blocked_admin` / `iamscope-benchmark-env11-20260425T020442Z`
- `env12_scp_blocked_assumerole` / `iamscope-benchmark-env12-20260425T032022Z`
- `env13_complete_scp_blocked_assumerole` / `iamscope-benchmark-env13-20260425T035707Z`
- `env14_permission_condition_blocked_admin` / `iamscope-benchmark-env14-24940398230`
- `env15_permission_condition_removed_validated_admin` / `iamscope-benchmark-env15-24940398230`
- `env16_identity_deny_removed_validated_group_escalation` / `iamscope-benchmark-env16-24940398230`

### Mutation Signals
- Mutation signal present without pairwise scoring: Env05 boundary-present case remains blocked/non-validated, while Env09 boundary-removed case validates admin reachability.

### Directly Proven
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
- The exact Env15 alice->admin path is emitted as validated admin reachability.
- The exact Env15 alice->admin path is not emitted as blocked or inconclusive.
- The exact Env15 alice->admin permission edge exists structurally.
- The exact Env15 alice->admin permission edge has no aws:MultiFactorAuthPresent condition evidence.
- The exact Env15 alice->admin trust edge exists structurally.
- The exact Env16 alice->admins path has no identity_deny blocker evidence.
- The exact Env16 alice->admins path is emitted as validated group membership escalation.
- The exact Env16 alice->admins path is not emitted as blocked or inconclusive.
- The permission edge carries aws:MultiFactorAuthPresent condition evidence.
- The trust edge carries TRUST_CONDITION evidence for aws:MultiFactorAuthPresent.
- This exact blocked group-escalation path is truthfully detected as blocked.
- This exact boundary-blocked admin path is not overclaimed as validated.
- This exact mutated admin path is emitted as validated.
- This exact mutated admin path is not emitted as blocked or inconclusive.
- This exact positive admin path is emitted as validated.
- This exact positive admin path is not emitted as blocked or inconclusive.

### Still Unknown
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
- Whether every permission-condition removal should validate remains unproven here.
- Whether every trust-condition removal should validate remains unproven here.
- Whether multi-account cross-account AssumeRole paths interact with SCPs the same way remains outside this case.
- Whether other SCP condition and exception forms produce the intended truth states remains outside this case.
- Whether other broad trust principal shapes behave the same way remains unknown here.
- Whether other condition operators should resolve to blocked rather than inconclusive remains unknown here.
- Whether other reasoner families should expose permission-condition evidence differently remains unknown here.
- Whether other trust-condition shapes should resolve to blocked rather than inconclusive remains unknown here.
- Whether the management caller PrincipalArn carveout works for every credential sourcing shape remains outside this case.

## phase0-20260428-env17

- Corpus decision: `hold_review`
- Total cases evaluated: `14`
- Passes: `14`
- Failures: `0`
- Blocked promotions: `0`
- Artifact insufficient count: `0`
- Human review required count: `14`
- README: `benchmarks/snapshots/phase0-20260428-env17/README.md`
- Corpus report: `benchmarks/snapshots/phase0-20260428-env17/corpus/corpus_report.md`

### Included Cases / Runs
- `env03_identity_deny_group_escalation` / `iamscope-benchmark-env03-20260424T025701Z`
- `env05_permission_boundary_blocked_chain` / `iamscope-benchmark-env05-20260424T203548Z`
- `env06_validated_admin_reachability` / `iamscope-benchmark-env06-20260425T003000Z`
- `env07_validated_non_admin_reachability` / `iamscope-benchmark-env07-20260424T222444Z`
- `env08_trust_condition_blocked_admin` / `iamscope-benchmark-env08-20260425T002835Z`
- `env09_boundary_removed_validated_admin` / `iamscope-benchmark-env09-20260425T012013Z`
- `env10_trust_condition_removed_validated_admin` / `iamscope-benchmark-env10-20260425T015458Z`
- `env11_broad_trust_condition_blocked_admin` / `iamscope-benchmark-env11-20260425T020442Z`
- `env12_scp_blocked_assumerole` / `iamscope-benchmark-env12-20260425T032022Z`
- `env13_complete_scp_blocked_assumerole` / `iamscope-benchmark-env13-20260425T035707Z`
- `env14_permission_condition_blocked_admin` / `iamscope-benchmark-env14-24940398230`
- `env15_permission_condition_removed_validated_admin` / `iamscope-benchmark-env15-24940398230`
- `env16_identity_deny_removed_validated_group_escalation` / `iamscope-benchmark-env16-24940398230`
- `env17_scp_removed_validated_admin` / `iamscope-benchmark-env17-24940398230`

### Mutation Signals
- Mutation signal present without pairwise scoring: Env05 boundary-present case remains blocked/non-validated, while Env09 boundary-removed case validates admin reachability.

### Directly Proven
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
- The exact Env15 alice->admin path is emitted as validated admin reachability.
- The exact Env15 alice->admin path is not emitted as blocked or inconclusive.
- The exact Env15 alice->admin permission edge exists structurally.
- The exact Env15 alice->admin permission edge has no aws:MultiFactorAuthPresent condition evidence.
- The exact Env15 alice->admin trust edge exists structurally.
- The exact Env16 alice->admins path has no identity_deny blocker evidence.
- The exact Env16 alice->admins path is emitted as validated group membership escalation.
- The exact Env16 alice->admins path is not emitted as blocked or inconclusive.
- The exact Env17 alice->admin path has no SCP blocker evidence.
- The exact Env17 alice->admin path is emitted as validated admin reachability.
- The exact Env17 alice->admin path is not emitted as blocked or inconclusive.
- The exact Env17 alice->admin permission edge exists structurally.
- The exact Env17 alice->admin trust edge exists structurally.
- The exact Env17 alice->admin trust edge is not bound to an SCP constraint.
- The permission edge carries aws:MultiFactorAuthPresent condition evidence.
- The trust edge carries TRUST_CONDITION evidence for aws:MultiFactorAuthPresent.
- This exact blocked group-escalation path is truthfully detected as blocked.
- This exact boundary-blocked admin path is not overclaimed as validated.
- This exact mutated admin path is emitted as validated.
- This exact mutated admin path is not emitted as blocked or inconclusive.
- This exact positive admin path is emitted as validated.
- This exact positive admin path is not emitted as blocked or inconclusive.

### Still Unknown
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
- Whether every complete SCP removal should validate remains unproven here.
- Whether every permission-condition removal should validate remains unproven here.
- Whether every trust-condition removal should validate remains unproven here.
- Whether multi-account AssumeRole paths interact with SCP removal the same way remains outside this case.
- Whether multi-account cross-account AssumeRole paths interact with SCPs the same way remains outside this case.
- Whether other SCP condition and exception forms produce the intended truth states remains outside this case.
- Whether other broad trust principal shapes behave the same way remains unknown here.
- Whether other condition operators should resolve to blocked rather than inconclusive remains unknown here.
- Whether other reasoner families should expose permission-condition evidence differently remains unknown here.
- Whether other trust-condition shapes should resolve to blocked rather than inconclusive remains unknown here.
- Whether the management caller PrincipalArn carveout works for every credential sourcing shape remains outside this case.

## phase0-20260429-env18

- Corpus decision: `hold_review`
- Total cases evaluated: `15`
- Passes: `15`
- Failures: `0`
- Blocked promotions: `0`
- Artifact insufficient count: `0`
- Human review required count: `15`
- README: `benchmarks/snapshots/phase0-20260429-env18/README.md`
- Corpus report: `benchmarks/snapshots/phase0-20260429-env18/corpus/corpus_report.md`

### Included Cases / Runs
- `env03_identity_deny_group_escalation` / `iamscope-benchmark-env03-20260424T025701Z`
- `env05_permission_boundary_blocked_chain` / `iamscope-benchmark-env05-20260424T203548Z`
- `env06_validated_admin_reachability` / `iamscope-benchmark-env06-20260425T003000Z`
- `env07_validated_non_admin_reachability` / `iamscope-benchmark-env07-20260424T222444Z`
- `env08_trust_condition_blocked_admin` / `iamscope-benchmark-env08-20260425T002835Z`
- `env09_boundary_removed_validated_admin` / `iamscope-benchmark-env09-20260425T012013Z`
- `env10_trust_condition_removed_validated_admin` / `iamscope-benchmark-env10-20260425T015458Z`
- `env11_broad_trust_condition_blocked_admin` / `iamscope-benchmark-env11-20260425T020442Z`
- `env12_scp_blocked_assumerole` / `iamscope-benchmark-env12-20260425T032022Z`
- `env13_complete_scp_blocked_assumerole` / `iamscope-benchmark-env13-20260425T035707Z`
- `env14_permission_condition_blocked_admin` / `iamscope-benchmark-env14-24940398230`
- `env15_permission_condition_removed_validated_admin` / `iamscope-benchmark-env15-24940398230`
- `env16_identity_deny_removed_validated_group_escalation` / `iamscope-benchmark-env16-24940398230`
- `env17_scp_removed_validated_admin` / `iamscope-benchmark-env17-24940398230`
- `env18_lambda_passrole_validated` / `iamscope-benchmark-env18-24940398230`

### Mutation Signals
- Mutation signal present without pairwise scoring: Env05 boundary-present case remains blocked/non-validated, while Env09 boundary-removed case validates admin reachability.

### Directly Proven
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
- The exact Env15 alice->admin path is emitted as validated admin reachability.
- The exact Env15 alice->admin path is not emitted as blocked or inconclusive.
- The exact Env15 alice->admin permission edge exists structurally.
- The exact Env15 alice->admin permission edge has no aws:MultiFactorAuthPresent condition evidence.
- The exact Env15 alice->admin trust edge exists structurally.
- The exact Env16 alice->admins path has no identity_deny blocker evidence.
- The exact Env16 alice->admins path is emitted as validated group membership escalation.
- The exact Env16 alice->admins path is not emitted as blocked or inconclusive.
- The exact Env17 alice->admin path has no SCP blocker evidence.
- The exact Env17 alice->admin path is emitted as validated admin reachability.
- The exact Env17 alice->admin path is not emitted as blocked or inconclusive.
- The exact Env17 alice->admin permission edge exists structurally.
- The exact Env17 alice->admin trust edge exists structurally.
- The exact Env17 alice->admin trust edge is not bound to an SCP constraint.
- The exact Env18 Lambda CreateFunction permission edge exists structurally.
- The exact Env18 Lambda service trust edge exists structurally.
- The exact Env18 alice->lambda-admin path is emitted as validated passrole_lambda.
- The exact Env18 alice->lambda-admin path is not emitted as blocked, inconclusive, or precondition_only.
- The exact Env18 iam:PassRole permission edge exists structurally.
- The permission edge carries aws:MultiFactorAuthPresent condition evidence.
- The trust edge carries TRUST_CONDITION evidence for aws:MultiFactorAuthPresent.
- This exact blocked group-escalation path is truthfully detected as blocked.
- This exact boundary-blocked admin path is not overclaimed as validated.
- This exact mutated admin path is emitted as validated.
- This exact mutated admin path is not emitted as blocked or inconclusive.
- This exact positive admin path is emitted as validated.
- This exact positive admin path is not emitted as blocked or inconclusive.

### Still Unknown
- False-negative behavior for partially parsed or malformed deny policies remains unknown here.
- How SCP, permission-boundary, and identity-Deny blockers interact with Lambda PassRole remains outside this case.
- How boundary handling behaves across longer chains or richer policy shapes remains unproven here.
- How consistent the same guarded behavior is across richer multi-condition trust policies remains unknown here.
- How every iam:PassedToService condition shape behaves remains outside this case.
- How richer permission-condition operators behave remains unknown here.
- How stable the same positive result is across richer trust-policy shapes remains unknown here.
- How stable the same positive result is across richer two-hop policy shapes remains unknown here.
- How stable the same positive-path result is across more complex mixed-signal environments remains unknown here.
- How stable the same structural/non-admin behavior is across richer policy shapes remains unknown here.
- How the same deny logic behaves in more complex multi-hop paths remains unproven here.
- How validated admin reachability behaves across longer chains or richer trust-policy shapes remains unproven here.
- Reasoner interactions outside the Env05 path family remain unknown here.
- Whether assume_role_chain consistently validates the same positive path remains unproven here.
- Whether broader PassRole families validate the same way remains unknown here.
- Whether broader non-admin path families should become first-class findings remains unproven here.
- Whether every complete SCP removal should validate remains unproven here.
- Whether every permission-condition removal should validate remains unproven here.
- Whether every trust-condition removal should validate remains unproven here.
- Whether multi-account AssumeRole paths interact with SCP removal the same way remains outside this case.
- Whether multi-account cross-account AssumeRole paths interact with SCPs the same way remains outside this case.
- Whether other SCP condition and exception forms produce the intended truth states remains outside this case.
- Whether other broad trust principal shapes behave the same way remains unknown here.
- Whether other condition operators should resolve to blocked rather than inconclusive remains unknown here.
- Whether other reasoner families should expose permission-condition evidence differently remains unknown here.
- Whether other trust-condition shapes should resolve to blocked rather than inconclusive remains unknown here.
- Whether the management caller PrincipalArn carveout works for every credential sourcing shape remains outside this case.

## phase0-20260429-env19

- Corpus decision: `hold_review`
- Total cases evaluated: `16`
- Passes: `16`
- Failures: `0`
- Blocked promotions: `0`
- Artifact insufficient count: `0`
- Human review required count: `16`
- README: `benchmarks/snapshots/phase0-20260429-env19/README.md`
- Corpus report: `benchmarks/snapshots/phase0-20260429-env19/corpus/corpus_report.md`

### Included Cases / Runs
- `env03_identity_deny_group_escalation` / `iamscope-benchmark-env03-20260424T025701Z`
- `env05_permission_boundary_blocked_chain` / `iamscope-benchmark-env05-20260424T203548Z`
- `env06_validated_admin_reachability` / `iamscope-benchmark-env06-20260425T003000Z`
- `env07_validated_non_admin_reachability` / `iamscope-benchmark-env07-20260424T222444Z`
- `env08_trust_condition_blocked_admin` / `iamscope-benchmark-env08-20260425T002835Z`
- `env09_boundary_removed_validated_admin` / `iamscope-benchmark-env09-20260425T012013Z`
- `env10_trust_condition_removed_validated_admin` / `iamscope-benchmark-env10-20260425T015458Z`
- `env11_broad_trust_condition_blocked_admin` / `iamscope-benchmark-env11-20260425T020442Z`
- `env12_scp_blocked_assumerole` / `iamscope-benchmark-env12-20260425T032022Z`
- `env13_complete_scp_blocked_assumerole` / `iamscope-benchmark-env13-20260425T035707Z`
- `env14_permission_condition_blocked_admin` / `iamscope-benchmark-env14-24940398230`
- `env15_permission_condition_removed_validated_admin` / `iamscope-benchmark-env15-24940398230`
- `env16_identity_deny_removed_validated_group_escalation` / `iamscope-benchmark-env16-24940398230`
- `env17_scp_removed_validated_admin` / `iamscope-benchmark-env17-24940398230`
- `env18_lambda_passrole_validated` / `iamscope-benchmark-env18-24940398230`
- `env19_passedtoservice_scoped_away_nonvalidated` / `iamscope-benchmark-env19-24940398230`

### Mutation Signals
- Mutation signal present without pairwise scoring: Env05 boundary-present case remains blocked/non-validated, while Env09 boundary-removed case validates admin reachability.

### Directly Proven
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
- The exact Env15 alice->admin path is emitted as validated admin reachability.
- The exact Env15 alice->admin path is not emitted as blocked or inconclusive.
- The exact Env15 alice->admin permission edge exists structurally.
- The exact Env15 alice->admin permission edge has no aws:MultiFactorAuthPresent condition evidence.
- The exact Env15 alice->admin trust edge exists structurally.
- The exact Env16 alice->admins path has no identity_deny blocker evidence.
- The exact Env16 alice->admins path is emitted as validated group membership escalation.
- The exact Env16 alice->admins path is not emitted as blocked or inconclusive.
- The exact Env17 alice->admin path has no SCP blocker evidence.
- The exact Env17 alice->admin path is emitted as validated admin reachability.
- The exact Env17 alice->admin path is not emitted as blocked or inconclusive.
- The exact Env17 alice->admin permission edge exists structurally.
- The exact Env17 alice->admin trust edge exists structurally.
- The exact Env17 alice->admin trust edge is not bound to an SCP constraint.
- The exact Env18 Lambda CreateFunction permission edge exists structurally.
- The exact Env18 Lambda service trust edge exists structurally.
- The exact Env18 alice->lambda-admin path is emitted as validated passrole_lambda.
- The exact Env18 alice->lambda-admin path is not emitted as blocked, inconclusive, or precondition_only.
- The exact Env18 iam:PassRole permission edge exists structurally.
- The exact Env19 Lambda CreateFunction permission edge exists structurally.
- The exact Env19 Lambda service trust edge exists structurally.
- The exact Env19 alice->lambda-admin path is emitted as precondition_only passrole_lambda under current reasoner semantics.
- The exact Env19 alice->lambda-admin path is not emitted as validated passrole_lambda.
- The exact Env19 iam:PassRole permission edge exists structurally and carries iam:PassedToService condition evidence.
- The permission edge carries aws:MultiFactorAuthPresent condition evidence.
- The trust edge carries TRUST_CONDITION evidence for aws:MultiFactorAuthPresent.
- This exact blocked group-escalation path is truthfully detected as blocked.
- This exact boundary-blocked admin path is not overclaimed as validated.
- This exact mutated admin path is emitted as validated.
- This exact mutated admin path is not emitted as blocked or inconclusive.
- This exact positive admin path is emitted as validated.
- This exact positive admin path is not emitted as blocked or inconclusive.

### Still Unknown
- False-negative behavior for partially parsed or malformed deny policies remains unknown here.
- How SCP, permission-boundary, and identity-Deny blockers interact with Lambda PassRole remains outside this case.
- How boundary handling behaves across longer chains or richer policy shapes remains unproven here.
- How consistent the same guarded behavior is across richer multi-condition trust policies remains unknown here.
- How every iam:PassedToService condition shape behaves remains outside this case.
- How richer permission-condition operators behave remains unknown here.
- How stable the same positive result is across richer trust-policy shapes remains unknown here.
- How stable the same positive result is across richer two-hop policy shapes remains unknown here.
- How stable the same positive-path result is across more complex mixed-signal environments remains unknown here.
- How stable the same structural/non-admin behavior is across richer policy shapes remains unknown here.
- How the same deny logic behaves in more complex multi-hop paths remains unproven here.
- How unsupported iam:PassedToService operators behave remains outside this case.
- How validated admin reachability behaves across longer chains or richer trust-policy shapes remains unproven here.
- Reasoner interactions outside the Env05 path family remain unknown here.
- Whether assume_role_chain consistently validates the same positive path remains unproven here.
- Whether broader PassRole families validate the same way remains unknown here.
- Whether broader PassRole mutation families behave the same way remains unknown here.
- Whether broader non-admin path families should become first-class findings remains unproven here.
- Whether every complete SCP removal should validate remains unproven here.
- Whether every permission-condition removal should validate remains unproven here.
- Whether every trust-condition removal should validate remains unproven here.
- Whether multi-account AssumeRole paths interact with SCP removal the same way remains outside this case.
- Whether multi-account cross-account AssumeRole paths interact with SCPs the same way remains outside this case.
- Whether other SCP condition and exception forms produce the intended truth states remains outside this case.
- Whether other broad trust principal shapes behave the same way remains unknown here.
- Whether other condition operators should resolve to blocked rather than inconclusive remains unknown here.
- Whether other reasoner families should expose permission-condition evidence differently remains unknown here.
- Whether other trust-condition shapes should resolve to blocked rather than inconclusive remains unknown here.
- Whether the management caller PrincipalArn carveout works for every credential sourcing shape remains outside this case.

## phase0-20260429-env20

- Corpus decision: `hold_review`
- Total cases evaluated: `17`
- Passes: `17`
- Failures: `0`
- Blocked promotions: `0`
- Artifact insufficient count: `0`
- Human review required count: `17`
- README: `benchmarks/snapshots/phase0-20260429-env20/README.md`
- Corpus report: `benchmarks/snapshots/phase0-20260429-env20/corpus/corpus_report.md`

### Included Cases / Runs
- `env03_identity_deny_group_escalation` / `iamscope-benchmark-env03-20260424T025701Z`
- `env05_permission_boundary_blocked_chain` / `iamscope-benchmark-env05-20260424T203548Z`
- `env06_validated_admin_reachability` / `iamscope-benchmark-env06-20260425T003000Z`
- `env07_validated_non_admin_reachability` / `iamscope-benchmark-env07-20260424T222444Z`
- `env08_trust_condition_blocked_admin` / `iamscope-benchmark-env08-20260425T002835Z`
- `env09_boundary_removed_validated_admin` / `iamscope-benchmark-env09-20260425T012013Z`
- `env10_trust_condition_removed_validated_admin` / `iamscope-benchmark-env10-20260425T015458Z`
- `env11_broad_trust_condition_blocked_admin` / `iamscope-benchmark-env11-20260425T020442Z`
- `env12_scp_blocked_assumerole` / `iamscope-benchmark-env12-20260425T032022Z`
- `env13_complete_scp_blocked_assumerole` / `iamscope-benchmark-env13-20260425T035707Z`
- `env14_permission_condition_blocked_admin` / `iamscope-benchmark-env14-24940398230`
- `env15_permission_condition_removed_validated_admin` / `iamscope-benchmark-env15-24940398230`
- `env16_identity_deny_removed_validated_group_escalation` / `iamscope-benchmark-env16-24940398230`
- `env17_scp_removed_validated_admin` / `iamscope-benchmark-env17-24940398230`
- `env18_lambda_passrole_validated` / `iamscope-benchmark-env18-24940398230`
- `env19_passedtoservice_scoped_away_nonvalidated` / `iamscope-benchmark-env19-24940398230`
- `env20_ecs_passrole_validated` / `iamscope-benchmark-env20-24940398230`

### Mutation Signals
- Mutation signal present without pairwise scoring: Env05 boundary-present case remains blocked/non-validated, while Env09 boundary-removed case validates admin reachability.

### Directly Proven
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
- The exact Env15 alice->admin path is emitted as validated admin reachability.
- The exact Env15 alice->admin path is not emitted as blocked or inconclusive.
- The exact Env15 alice->admin permission edge exists structurally.
- The exact Env15 alice->admin permission edge has no aws:MultiFactorAuthPresent condition evidence.
- The exact Env15 alice->admin trust edge exists structurally.
- The exact Env16 alice->admins path has no identity_deny blocker evidence.
- The exact Env16 alice->admins path is emitted as validated group membership escalation.
- The exact Env16 alice->admins path is not emitted as blocked or inconclusive.
- The exact Env17 alice->admin path has no SCP blocker evidence.
- The exact Env17 alice->admin path is emitted as validated admin reachability.
- The exact Env17 alice->admin path is not emitted as blocked or inconclusive.
- The exact Env17 alice->admin permission edge exists structurally.
- The exact Env17 alice->admin trust edge exists structurally.
- The exact Env17 alice->admin trust edge is not bound to an SCP constraint.
- The exact Env18 Lambda CreateFunction permission edge exists structurally.
- The exact Env18 Lambda service trust edge exists structurally.
- The exact Env18 alice->lambda-admin path is emitted as validated passrole_lambda.
- The exact Env18 alice->lambda-admin path is not emitted as blocked, inconclusive, or precondition_only.
- The exact Env18 iam:PassRole permission edge exists structurally.
- The exact Env19 Lambda CreateFunction permission edge exists structurally.
- The exact Env19 Lambda service trust edge exists structurally.
- The exact Env19 alice->lambda-admin path is emitted as precondition_only passrole_lambda under current reasoner semantics.
- The exact Env19 alice->lambda-admin path is not emitted as validated passrole_lambda.
- The exact Env19 iam:PassRole permission edge exists structurally and carries iam:PassedToService condition evidence.
- The exact Env20 ECS RegisterTaskDefinition permission edge exists structurally.
- The exact Env20 ECS RunTask permission edge exists structurally.
- The exact Env20 ECS task service trust edge exists structurally.
- The exact Env20 alice->ecs-admin-task path is emitted as validated passrole_ecs.
- The exact Env20 alice->ecs-admin-task path is not emitted as blocked, inconclusive, or precondition_only.
- The exact Env20 iam:PassRole permission edge exists structurally.
- The permission edge carries aws:MultiFactorAuthPresent condition evidence.
- The trust edge carries TRUST_CONDITION evidence for aws:MultiFactorAuthPresent.
- This exact blocked group-escalation path is truthfully detected as blocked.
- This exact boundary-blocked admin path is not overclaimed as validated.
- This exact mutated admin path is emitted as validated.
- This exact mutated admin path is not emitted as blocked or inconclusive.
- This exact positive admin path is emitted as validated.
- This exact positive admin path is not emitted as blocked or inconclusive.

### Still Unknown
- False-negative behavior for partially parsed or malformed deny policies remains unknown here.
- How SCP, permission-boundary, and identity-Deny blockers interact with ECS PassRole remains outside this case.
- How SCP, permission-boundary, and identity-Deny blockers interact with Lambda PassRole remains outside this case.
- How boundary handling behaves across longer chains or richer policy shapes remains unproven here.
- How consistent the same guarded behavior is across richer multi-condition trust policies remains unknown here.
- How every iam:PassedToService condition shape behaves remains outside this case.
- How richer permission-condition operators behave remains unknown here.
- How stable the same positive result is across richer trust-policy shapes remains unknown here.
- How stable the same positive result is across richer two-hop policy shapes remains unknown here.
- How stable the same positive-path result is across more complex mixed-signal environments remains unknown here.
- How stable the same structural/non-admin behavior is across richer policy shapes remains unknown here.
- How the same deny logic behaves in more complex multi-hop paths remains unproven here.
- How unsupported iam:PassedToService operators behave remains outside this case.
- How validated admin reachability behaves across longer chains or richer trust-policy shapes remains unproven here.
- Reasoner interactions outside the Env05 path family remain unknown here.
- Whether assume_role_chain consistently validates the same positive path remains unproven here.
- Whether broader PassRole families validate the same way remains unknown here.
- Whether broader PassRole mutation families behave the same way remains unknown here.
- Whether broader non-admin path families should become first-class findings remains unproven here.
- Whether every complete SCP removal should validate remains unproven here.
- Whether every permission-condition removal should validate remains unproven here.
- Whether every trust-condition removal should validate remains unproven here.
- Whether multi-account AssumeRole paths interact with SCP removal the same way remains outside this case.
- Whether multi-account cross-account AssumeRole paths interact with SCPs the same way remains outside this case.
- Whether other SCP condition and exception forms produce the intended truth states remains outside this case.
- Whether other broad trust principal shapes behave the same way remains unknown here.
- Whether other condition operators should resolve to blocked rather than inconclusive remains unknown here.
- Whether other reasoner families should expose permission-condition evidence differently remains unknown here.
- Whether other trust-condition shapes should resolve to blocked rather than inconclusive remains unknown here.
- Whether the management caller PrincipalArn carveout works for every credential sourcing shape remains outside this case.

## phase0-20260429-env21

- Corpus decision: `hold_review`
- Total cases evaluated: `18`
- Passes: `18`
- Failures: `0`
- Blocked promotions: `0`
- Artifact insufficient count: `0`
- Human review required count: `18`
- README: `benchmarks/snapshots/phase0-20260429-env21/README.md`
- Corpus report: `benchmarks/snapshots/phase0-20260429-env21/corpus/corpus_report.md`

### Included Cases / Runs
- `env03_identity_deny_group_escalation` / `iamscope-benchmark-env03-20260424T025701Z`
- `env05_permission_boundary_blocked_chain` / `iamscope-benchmark-env05-20260424T203548Z`
- `env06_validated_admin_reachability` / `iamscope-benchmark-env06-20260425T003000Z`
- `env07_validated_non_admin_reachability` / `iamscope-benchmark-env07-20260424T222444Z`
- `env08_trust_condition_blocked_admin` / `iamscope-benchmark-env08-20260425T002835Z`
- `env09_boundary_removed_validated_admin` / `iamscope-benchmark-env09-20260425T012013Z`
- `env10_trust_condition_removed_validated_admin` / `iamscope-benchmark-env10-20260425T015458Z`
- `env11_broad_trust_condition_blocked_admin` / `iamscope-benchmark-env11-20260425T020442Z`
- `env12_scp_blocked_assumerole` / `iamscope-benchmark-env12-20260425T032022Z`
- `env13_complete_scp_blocked_assumerole` / `iamscope-benchmark-env13-20260425T035707Z`
- `env14_permission_condition_blocked_admin` / `iamscope-benchmark-env14-24940398230`
- `env15_permission_condition_removed_validated_admin` / `iamscope-benchmark-env15-24940398230`
- `env16_identity_deny_removed_validated_group_escalation` / `iamscope-benchmark-env16-24940398230`
- `env17_scp_removed_validated_admin` / `iamscope-benchmark-env17-24940398230`
- `env18_lambda_passrole_validated` / `iamscope-benchmark-env18-24940398230`
- `env19_passedtoservice_scoped_away_nonvalidated` / `iamscope-benchmark-env19-24940398230`
- `env20_ecs_passrole_validated` / `iamscope-benchmark-env20-24940398230`
- `env21_ecs_passedtoservice_scoped_away_nonvalidated` / `iamscope-benchmark-env21-24940398230`

### Mutation Signals
- Mutation signal present without pairwise scoring: Env05 boundary-present case remains blocked/non-validated, while Env09 boundary-removed case validates admin reachability.

### Directly Proven
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
- The exact Env15 alice->admin path is emitted as validated admin reachability.
- The exact Env15 alice->admin path is not emitted as blocked or inconclusive.
- The exact Env15 alice->admin permission edge exists structurally.
- The exact Env15 alice->admin permission edge has no aws:MultiFactorAuthPresent condition evidence.
- The exact Env15 alice->admin trust edge exists structurally.
- The exact Env16 alice->admins path has no identity_deny blocker evidence.
- The exact Env16 alice->admins path is emitted as validated group membership escalation.
- The exact Env16 alice->admins path is not emitted as blocked or inconclusive.
- The exact Env17 alice->admin path has no SCP blocker evidence.
- The exact Env17 alice->admin path is emitted as validated admin reachability.
- The exact Env17 alice->admin path is not emitted as blocked or inconclusive.
- The exact Env17 alice->admin permission edge exists structurally.
- The exact Env17 alice->admin trust edge exists structurally.
- The exact Env17 alice->admin trust edge is not bound to an SCP constraint.
- The exact Env18 Lambda CreateFunction permission edge exists structurally.
- The exact Env18 Lambda service trust edge exists structurally.
- The exact Env18 alice->lambda-admin path is emitted as validated passrole_lambda.
- The exact Env18 alice->lambda-admin path is not emitted as blocked, inconclusive, or precondition_only.
- The exact Env18 iam:PassRole permission edge exists structurally.
- The exact Env19 Lambda CreateFunction permission edge exists structurally.
- The exact Env19 Lambda service trust edge exists structurally.
- The exact Env19 alice->lambda-admin path is emitted as precondition_only passrole_lambda under current reasoner semantics.
- The exact Env19 alice->lambda-admin path is not emitted as validated passrole_lambda.
- The exact Env19 iam:PassRole permission edge exists structurally and carries iam:PassedToService condition evidence.
- The exact Env20 ECS RegisterTaskDefinition permission edge exists structurally.
- The exact Env20 ECS RunTask permission edge exists structurally.
- The exact Env20 ECS task service trust edge exists structurally.
- The exact Env20 alice->ecs-admin-task path is emitted as validated passrole_ecs.
- The exact Env20 alice->ecs-admin-task path is not emitted as blocked, inconclusive, or precondition_only.
- The exact Env20 iam:PassRole permission edge exists structurally.
- The exact Env21 ECS RegisterTaskDefinition permission edge exists structurally.
- The exact Env21 ECS RunTask permission edge exists structurally.
- The exact Env21 ECS task service trust edge exists structurally.
- The exact Env21 alice->ecs-admin-task path is emitted as precondition_only passrole_ecs under current reasoner semantics.
- The exact Env21 alice->ecs-admin-task path is not emitted as validated passrole_ecs.
- The exact Env21 iam:PassRole permission edge exists structurally and carries iam:PassedToService condition evidence.
- The permission edge carries aws:MultiFactorAuthPresent condition evidence.
- The trust edge carries TRUST_CONDITION evidence for aws:MultiFactorAuthPresent.
- This exact blocked group-escalation path is truthfully detected as blocked.
- This exact boundary-blocked admin path is not overclaimed as validated.
- This exact mutated admin path is emitted as validated.
- This exact mutated admin path is not emitted as blocked or inconclusive.
- This exact positive admin path is emitted as validated.
- This exact positive admin path is not emitted as blocked or inconclusive.

### Still Unknown
- False-negative behavior for partially parsed or malformed deny policies remains unknown here.
- How SCP, permission-boundary, and identity-Deny blockers interact with ECS PassRole remains outside this case.
- How SCP, permission-boundary, and identity-Deny blockers interact with Lambda PassRole remains outside this case.
- How boundary handling behaves across longer chains or richer policy shapes remains unproven here.
- How consistent the same guarded behavior is across richer multi-condition trust policies remains unknown here.
- How every iam:PassedToService condition shape behaves remains outside this case.
- How richer permission-condition operators behave remains unknown here.
- How stable the same positive result is across richer trust-policy shapes remains unknown here.
- How stable the same positive result is across richer two-hop policy shapes remains unknown here.
- How stable the same positive-path result is across more complex mixed-signal environments remains unknown here.
- How stable the same structural/non-admin behavior is across richer policy shapes remains unknown here.
- How the same deny logic behaves in more complex multi-hop paths remains unproven here.
- How unsupported iam:PassedToService operators behave remains outside this case.
- How validated admin reachability behaves across longer chains or richer trust-policy shapes remains unproven here.
- Reasoner interactions outside the Env05 path family remain unknown here.
- Whether assume_role_chain consistently validates the same positive path remains unproven here.
- Whether broader PassRole families validate the same way remains unknown here.
- Whether broader PassRole mutation families behave the same way remains unknown here.
- Whether broader non-admin path families should become first-class findings remains unproven here.
- Whether every complete SCP removal should validate remains unproven here.
- Whether every permission-condition removal should validate remains unproven here.
- Whether every trust-condition removal should validate remains unproven here.
- Whether multi-account AssumeRole paths interact with SCP removal the same way remains outside this case.
- Whether multi-account cross-account AssumeRole paths interact with SCPs the same way remains outside this case.
- Whether other SCP condition and exception forms produce the intended truth states remains outside this case.
- Whether other broad trust principal shapes behave the same way remains unknown here.
- Whether other condition operators should resolve to blocked rather than inconclusive remains unknown here.
- Whether other reasoner families should expose permission-condition evidence differently remains unknown here.
- Whether other trust-condition shapes should resolve to blocked rather than inconclusive remains unknown here.
- Whether the management caller PrincipalArn carveout works for every credential sourcing shape remains outside this case.

## phase0-20260505-env22

- Corpus decision: `hold_review`
- Total cases evaluated: `19`
- Passes: `19`
- Failures: `0`
- Blocked promotions: `0`
- Artifact insufficient count: `0`
- Human review required count: `19`
- README: `benchmarks/snapshots/phase0-20260505-env22/README.md`
- Corpus report: `benchmarks/snapshots/phase0-20260505-env22/corpus/corpus_report.md`

### Included Cases / Runs
- `env03_identity_deny_group_escalation` / `iamscope-benchmark-env03-20260424T025701Z`
- `env05_permission_boundary_blocked_chain` / `iamscope-benchmark-env05-20260424T203548Z`
- `env06_validated_admin_reachability` / `iamscope-benchmark-env06-20260425T003000Z`
- `env07_validated_non_admin_reachability` / `iamscope-benchmark-env07-20260424T222444Z`
- `env08_trust_condition_blocked_admin` / `iamscope-benchmark-env08-20260425T002835Z`
- `env09_boundary_removed_validated_admin` / `iamscope-benchmark-env09-20260425T012013Z`
- `env10_trust_condition_removed_validated_admin` / `iamscope-benchmark-env10-20260425T015458Z`
- `env11_broad_trust_condition_blocked_admin` / `iamscope-benchmark-env11-20260425T020442Z`
- `env12_scp_blocked_assumerole` / `iamscope-benchmark-env12-20260425T032022Z`
- `env13_complete_scp_blocked_assumerole` / `iamscope-benchmark-env13-20260425T035707Z`
- `env14_permission_condition_blocked_admin` / `iamscope-benchmark-env14-24940398230`
- `env15_permission_condition_removed_validated_admin` / `iamscope-benchmark-env15-24940398230`
- `env16_identity_deny_removed_validated_group_escalation` / `iamscope-benchmark-env16-24940398230`
- `env17_scp_removed_validated_admin` / `iamscope-benchmark-env17-24940398230`
- `env18_lambda_passrole_validated` / `iamscope-benchmark-env18-24940398230`
- `env19_passedtoservice_scoped_away_nonvalidated` / `iamscope-benchmark-env19-24940398230`
- `env20_ecs_passrole_validated` / `iamscope-benchmark-env20-24940398230`
- `env21_ecs_passedtoservice_scoped_away_nonvalidated` / `iamscope-benchmark-env21-24940398230`
- `env22_cross_account_validated_admin` / `iamscope-benchmark-env22-20260505T210729Z`

### Mutation Signals
- Mutation signal present without pairwise scoring: Env05 boundary-present case remains blocked/non-validated, while Env09 boundary-removed case validates admin reachability.

### Directly Proven
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
- The exact Env15 alice->admin path is emitted as validated admin reachability.
- The exact Env15 alice->admin path is not emitted as blocked or inconclusive.
- The exact Env15 alice->admin permission edge exists structurally.
- The exact Env15 alice->admin permission edge has no aws:MultiFactorAuthPresent condition evidence.
- The exact Env15 alice->admin trust edge exists structurally.
- The exact Env16 alice->admins path has no identity_deny blocker evidence.
- The exact Env16 alice->admins path is emitted as validated group membership escalation.
- The exact Env16 alice->admins path is not emitted as blocked or inconclusive.
- The exact Env17 alice->admin path has no SCP blocker evidence.
- The exact Env17 alice->admin path is emitted as validated admin reachability.
- The exact Env17 alice->admin path is not emitted as blocked or inconclusive.
- The exact Env17 alice->admin permission edge exists structurally.
- The exact Env17 alice->admin trust edge exists structurally.
- The exact Env17 alice->admin trust edge is not bound to an SCP constraint.
- The exact Env18 Lambda CreateFunction permission edge exists structurally.
- The exact Env18 Lambda service trust edge exists structurally.
- The exact Env18 alice->lambda-admin path is emitted as validated passrole_lambda.
- The exact Env18 alice->lambda-admin path is not emitted as blocked, inconclusive, or precondition_only.
- The exact Env18 iam:PassRole permission edge exists structurally.
- The exact Env19 Lambda CreateFunction permission edge exists structurally.
- The exact Env19 Lambda service trust edge exists structurally.
- The exact Env19 alice->lambda-admin path is emitted as precondition_only passrole_lambda under current reasoner semantics.
- The exact Env19 alice->lambda-admin path is not emitted as validated passrole_lambda.
- The exact Env19 iam:PassRole permission edge exists structurally and carries iam:PassedToService condition evidence.
- The exact Env20 ECS RegisterTaskDefinition permission edge exists structurally.
- The exact Env20 ECS RunTask permission edge exists structurally.
- The exact Env20 ECS task service trust edge exists structurally.
- The exact Env20 alice->ecs-admin-task path is emitted as validated passrole_ecs.
- The exact Env20 alice->ecs-admin-task path is not emitted as blocked, inconclusive, or precondition_only.
- The exact Env20 iam:PassRole permission edge exists structurally.
- The exact Env21 ECS RegisterTaskDefinition permission edge exists structurally.
- The exact Env21 ECS RunTask permission edge exists structurally.
- The exact Env21 ECS task service trust edge exists structurally.
- The exact Env21 alice->ecs-admin-task path is emitted as precondition_only passrole_ecs under current reasoner semantics.
- The exact Env21 alice->ecs-admin-task path is not emitted as validated passrole_ecs.
- The exact Env21 iam:PassRole permission edge exists structurally and carries iam:PassedToService condition evidence.
- The exact Env22 alice->cross-account-admin path is emitted as validated admin_reachability.
- The exact Env22 alice->cross-account-admin path is emitted as validated cross_account_trust.
- The exact Env22 alice->cross-account-admin path is not emitted as blocked or inconclusive.
- The exact Env22 cross-account permission edge exists structurally.
- The exact Env22 cross-account trust edge exists structurally.
- The permission edge carries aws:MultiFactorAuthPresent condition evidence.
- The trust edge carries TRUST_CONDITION evidence for aws:MultiFactorAuthPresent.
- This exact blocked group-escalation path is truthfully detected as blocked.
- This exact boundary-blocked admin path is not overclaimed as validated.
- This exact mutated admin path is emitted as validated.
- This exact mutated admin path is not emitted as blocked or inconclusive.
- This exact positive admin path is emitted as validated.
- This exact positive admin path is not emitted as blocked or inconclusive.

### Still Unknown
- Env23 and later mutations should test principal-scoped-away and conditioned cross-account trust paths.
- False-negative behavior for partially parsed or malformed deny policies remains unknown here.
- How SCP, permission-boundary, and identity-Deny blockers interact with ECS PassRole remains outside this case.
- How SCP, permission-boundary, and identity-Deny blockers interact with Lambda PassRole remains outside this case.
- How boundary handling behaves across longer chains or richer policy shapes remains unproven here.
- How consistent the same guarded behavior is across richer multi-condition trust policies remains unknown here.
- How every iam:PassedToService condition shape behaves remains outside this case.
- How richer permission-condition operators behave remains unknown here.
- How stable the same positive result is across richer trust-policy shapes remains unknown here.
- How stable the same positive result is across richer two-hop policy shapes remains unknown here.
- How stable the same positive-path result is across more complex mixed-signal environments remains unknown here.
- How stable the same structural/non-admin behavior is across richer policy shapes remains unknown here.
- How the same deny logic behaves in more complex multi-hop paths remains unproven here.
- How unsupported iam:PassedToService operators behave remains outside this case.
- How validated admin reachability behaves across longer chains or richer trust-policy shapes remains unproven here.
- Longer cross-account chains remain outside this case.
- Reasoner interactions outside the Env05 path family remain unknown here.
- Resource-policy Allow and generic resource-policy Deny remain outside this case.
- Whether assume_role_chain consistently validates the same positive path remains unproven here.
- Whether broader PassRole families validate the same way remains unknown here.
- Whether broader PassRole mutation families behave the same way remains unknown here.
- Whether broader non-admin path families should become first-class findings remains unproven here.
- Whether every complete SCP removal should validate remains unproven here.
- Whether every permission-condition removal should validate remains unproven here.
- Whether every trust-condition removal should validate remains unproven here.
- Whether multi-account AssumeRole paths interact with SCP removal the same way remains outside this case.
- Whether multi-account cross-account AssumeRole paths interact with SCPs the same way remains outside this case.
- Whether other SCP condition and exception forms produce the intended truth states remains outside this case.
- Whether other broad trust principal shapes behave the same way remains unknown here.
- Whether other condition operators should resolve to blocked rather than inconclusive remains unknown here.
- Whether other reasoner families should expose permission-condition evidence differently remains unknown here.
- Whether other trust-condition shapes should resolve to blocked rather than inconclusive remains unknown here.
- Whether the management caller PrincipalArn carveout works for every credential sourcing shape remains outside this case.

## phase0-20260506-env23

- Corpus decision: `hold_review`
- Total cases evaluated: `20`
- Passes: `20`
- Failures: `0`
- Blocked promotions: `0`
- Artifact insufficient count: `0`
- Human review required count: `20`
- README: `benchmarks/snapshots/phase0-20260506-env23/README.md`
- Corpus report: `benchmarks/snapshots/phase0-20260506-env23/corpus/corpus_report.md`

### Included Cases / Runs
- `env03_identity_deny_group_escalation` / `iamscope-benchmark-env03-20260424T025701Z`
- `env05_permission_boundary_blocked_chain` / `iamscope-benchmark-env05-20260424T203548Z`
- `env06_validated_admin_reachability` / `iamscope-benchmark-env06-20260425T003000Z`
- `env07_validated_non_admin_reachability` / `iamscope-benchmark-env07-20260424T222444Z`
- `env08_trust_condition_blocked_admin` / `iamscope-benchmark-env08-20260425T002835Z`
- `env09_boundary_removed_validated_admin` / `iamscope-benchmark-env09-20260425T012013Z`
- `env10_trust_condition_removed_validated_admin` / `iamscope-benchmark-env10-20260425T015458Z`
- `env11_broad_trust_condition_blocked_admin` / `iamscope-benchmark-env11-20260425T020442Z`
- `env12_scp_blocked_assumerole` / `iamscope-benchmark-env12-20260425T032022Z`
- `env13_complete_scp_blocked_assumerole` / `iamscope-benchmark-env13-20260425T035707Z`
- `env14_permission_condition_blocked_admin` / `iamscope-benchmark-env14-24940398230`
- `env15_permission_condition_removed_validated_admin` / `iamscope-benchmark-env15-24940398230`
- `env16_identity_deny_removed_validated_group_escalation` / `iamscope-benchmark-env16-24940398230`
- `env17_scp_removed_validated_admin` / `iamscope-benchmark-env17-24940398230`
- `env18_lambda_passrole_validated` / `iamscope-benchmark-env18-24940398230`
- `env19_passedtoservice_scoped_away_nonvalidated` / `iamscope-benchmark-env19-24940398230`
- `env20_ecs_passrole_validated` / `iamscope-benchmark-env20-24940398230`
- `env21_ecs_passedtoservice_scoped_away_nonvalidated` / `iamscope-benchmark-env21-24940398230`
- `env22_cross_account_validated_admin` / `iamscope-benchmark-env22-20260505T210729Z`
- `env23_cross_account_trust_scoped_away_nonvalidated` / `iamscope-benchmark-env23-20260506T020925Z`

### Mutation Signals
- Mutation signal present without pairwise scoring: Env05 boundary-present case remains blocked/non-validated, while Env09 boundary-removed case validates admin reachability.

### Directly Proven
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
- The exact Env15 alice->admin path is emitted as validated admin reachability.
- The exact Env15 alice->admin path is not emitted as blocked or inconclusive.
- The exact Env15 alice->admin permission edge exists structurally.
- The exact Env15 alice->admin permission edge has no aws:MultiFactorAuthPresent condition evidence.
- The exact Env15 alice->admin trust edge exists structurally.
- The exact Env16 alice->admins path has no identity_deny blocker evidence.
- The exact Env16 alice->admins path is emitted as validated group membership escalation.
- The exact Env16 alice->admins path is not emitted as blocked or inconclusive.
- The exact Env17 alice->admin path has no SCP blocker evidence.
- The exact Env17 alice->admin path is emitted as validated admin reachability.
- The exact Env17 alice->admin path is not emitted as blocked or inconclusive.
- The exact Env17 alice->admin permission edge exists structurally.
- The exact Env17 alice->admin trust edge exists structurally.
- The exact Env17 alice->admin trust edge is not bound to an SCP constraint.
- The exact Env18 Lambda CreateFunction permission edge exists structurally.
- The exact Env18 Lambda service trust edge exists structurally.
- The exact Env18 alice->lambda-admin path is emitted as validated passrole_lambda.
- The exact Env18 alice->lambda-admin path is not emitted as blocked, inconclusive, or precondition_only.
- The exact Env18 iam:PassRole permission edge exists structurally.
- The exact Env19 Lambda CreateFunction permission edge exists structurally.
- The exact Env19 Lambda service trust edge exists structurally.
- The exact Env19 alice->lambda-admin path is emitted as precondition_only passrole_lambda under current reasoner semantics.
- The exact Env19 alice->lambda-admin path is not emitted as validated passrole_lambda.
- The exact Env19 iam:PassRole permission edge exists structurally and carries iam:PassedToService condition evidence.
- The exact Env20 ECS RegisterTaskDefinition permission edge exists structurally.
- The exact Env20 ECS RunTask permission edge exists structurally.
- The exact Env20 ECS task service trust edge exists structurally.
- The exact Env20 alice->ecs-admin-task path is emitted as validated passrole_ecs.
- The exact Env20 alice->ecs-admin-task path is not emitted as blocked, inconclusive, or precondition_only.
- The exact Env20 iam:PassRole permission edge exists structurally.
- The exact Env21 ECS RegisterTaskDefinition permission edge exists structurally.
- The exact Env21 ECS RunTask permission edge exists structurally.
- The exact Env21 ECS task service trust edge exists structurally.
- The exact Env21 alice->ecs-admin-task path is emitted as precondition_only passrole_ecs under current reasoner semantics.
- The exact Env21 alice->ecs-admin-task path is not emitted as validated passrole_ecs.
- The exact Env21 iam:PassRole permission edge exists structurally and carries iam:PassedToService condition evidence.
- The exact Env22 alice->cross-account-admin path is emitted as validated admin_reachability.
- The exact Env22 alice->cross-account-admin path is emitted as validated cross_account_trust.
- The exact Env22 alice->cross-account-admin path is not emitted as blocked or inconclusive.
- The exact Env22 cross-account permission edge exists structurally.
- The exact Env22 cross-account trust edge exists structurally.
- The exact Env23 alice->cross-account-admin path has no matching trust edge.
- The exact Env23 alice->cross-account-admin path is not emitted as validated admin_reachability.
- The exact Env23 alice->cross-account-admin path is not emitted as validated cross_account_trust.
- The exact Env23 cross-account permission edge exists structurally.
- The permission edge carries aws:MultiFactorAuthPresent condition evidence.
- The trust edge carries TRUST_CONDITION evidence for aws:MultiFactorAuthPresent.
- This exact blocked group-escalation path is truthfully detected as blocked.
- This exact boundary-blocked admin path is not overclaimed as validated.
- This exact mutated admin path is emitted as validated.
- This exact mutated admin path is not emitted as blocked or inconclusive.
- This exact positive admin path is emitted as validated.
- This exact positive admin path is not emitted as blocked or inconclusive.

### Still Unknown
- Conditioned cross-account trust paths remain outside this case.
- Env23 and later mutations should test principal-scoped-away and conditioned cross-account trust paths.
- False-negative behavior for partially parsed or malformed deny policies remains unknown here.
- How SCP, permission-boundary, and identity-Deny blockers interact with ECS PassRole remains outside this case.
- How SCP, permission-boundary, and identity-Deny blockers interact with Lambda PassRole remains outside this case.
- How boundary handling behaves across longer chains or richer policy shapes remains unproven here.
- How consistent the same guarded behavior is across richer multi-condition trust policies remains unknown here.
- How every iam:PassedToService condition shape behaves remains outside this case.
- How richer permission-condition operators behave remains unknown here.
- How stable the same positive result is across richer trust-policy shapes remains unknown here.
- How stable the same positive result is across richer two-hop policy shapes remains unknown here.
- How stable the same positive-path result is across more complex mixed-signal environments remains unknown here.
- How stable the same structural/non-admin behavior is across richer policy shapes remains unknown here.
- How the same deny logic behaves in more complex multi-hop paths remains unproven here.
- How unsupported iam:PassedToService operators behave remains outside this case.
- How validated admin reachability behaves across longer chains or richer trust-policy shapes remains unproven here.
- Longer cross-account chains remain outside this case.
- Reasoner interactions outside the Env05 path family remain unknown here.
- Resource-policy Allow and generic resource-policy Deny remain outside this case.
- Whether assume_role_chain consistently validates the same positive path remains unproven here.
- Whether broader PassRole families validate the same way remains unknown here.
- Whether broader PassRole mutation families behave the same way remains unknown here.
- Whether broader non-admin path families should become first-class findings remains unproven here.
- Whether every complete SCP removal should validate remains unproven here.
- Whether every permission-condition removal should validate remains unproven here.
- Whether every trust-condition removal should validate remains unproven here.
- Whether multi-account AssumeRole paths interact with SCP removal the same way remains outside this case.
- Whether multi-account cross-account AssumeRole paths interact with SCPs the same way remains outside this case.
- Whether other SCP condition and exception forms produce the intended truth states remains outside this case.
- Whether other broad trust principal shapes behave the same way remains unknown here.
- Whether other condition operators should resolve to blocked rather than inconclusive remains unknown here.
- Whether other reasoner families should expose permission-condition evidence differently remains unknown here.
- Whether other trust-condition shapes should resolve to blocked rather than inconclusive remains unknown here.
- Whether the management caller PrincipalArn carveout works for every credential sourcing shape remains outside this case.

## phase0-20260508-env24

- Corpus decision: `hold_review`
- Total cases evaluated: `21`
- Passes: `21`
- Failures: `0`
- Blocked promotions: `0`
- Artifact insufficient count: `0`
- Human review required count: `21`
- README: `benchmarks/snapshots/phase0-20260508-env24/README.md`
- Corpus report: `benchmarks/snapshots/phase0-20260508-env24/corpus/corpus_report.md`

### Included Cases / Runs
- `env03_identity_deny_group_escalation` / `iamscope-benchmark-env03-20260424T025701Z`
- `env05_permission_boundary_blocked_chain` / `iamscope-benchmark-env05-20260424T203548Z`
- `env06_validated_admin_reachability` / `iamscope-benchmark-env06-20260425T003000Z`
- `env07_validated_non_admin_reachability` / `iamscope-benchmark-env07-20260424T222444Z`
- `env08_trust_condition_blocked_admin` / `iamscope-benchmark-env08-20260425T002835Z`
- `env09_boundary_removed_validated_admin` / `iamscope-benchmark-env09-20260425T012013Z`
- `env10_trust_condition_removed_validated_admin` / `iamscope-benchmark-env10-20260425T015458Z`
- `env11_broad_trust_condition_blocked_admin` / `iamscope-benchmark-env11-20260425T020442Z`
- `env12_scp_blocked_assumerole` / `iamscope-benchmark-env12-20260425T032022Z`
- `env13_complete_scp_blocked_assumerole` / `iamscope-benchmark-env13-20260425T035707Z`
- `env14_permission_condition_blocked_admin` / `iamscope-benchmark-env14-24940398230`
- `env15_permission_condition_removed_validated_admin` / `iamscope-benchmark-env15-24940398230`
- `env16_identity_deny_removed_validated_group_escalation` / `iamscope-benchmark-env16-24940398230`
- `env17_scp_removed_validated_admin` / `iamscope-benchmark-env17-24940398230`
- `env18_lambda_passrole_validated` / `iamscope-benchmark-env18-24940398230`
- `env19_passedtoservice_scoped_away_nonvalidated` / `iamscope-benchmark-env19-24940398230`
- `env20_ecs_passrole_validated` / `iamscope-benchmark-env20-24940398230`
- `env21_ecs_passedtoservice_scoped_away_nonvalidated` / `iamscope-benchmark-env21-24940398230`
- `env22_cross_account_validated_admin` / `iamscope-benchmark-env22-20260505T210729Z`
- `env23_cross_account_trust_scoped_away_nonvalidated` / `iamscope-benchmark-env23-20260506T020925Z`
- `env24_s3_resource_policy_allow` / `iamscope-benchmark-env24-20260508T151202Z`

### Mutation Signals
- Mutation signal present without pairwise scoring: Env05 boundary-present case remains blocked/non-validated, while Env09 boundary-removed case validates admin reachability.

### Directly Proven
- A live Organizations SCP denying sts:AssumeRole on env12-admin is present in scenario.json.
- A live Organizations SCP denying sts:AssumeRole with wildcard Resource is present in scenario.json.
- No generic RESOURCE_POLICY_DENY constraint is emitted.
- The Env10 trust edge is not bound to aws:MultiFactorAuthPresent TRUST_CONDITION evidence.
- The Env11 target role has broad-looking trust structure.
- The Env12 trust edge is bound to an SCP constraint.
- The Env13 trust edge is bound to an SCP constraint.
- The Env24 target path is not accidentally witnessed by an identity-policy s3:GetObject edge.
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
- The exact Env15 alice->admin path is emitted as validated admin reachability.
- The exact Env15 alice->admin path is not emitted as blocked or inconclusive.
- The exact Env15 alice->admin permission edge exists structurally.
- The exact Env15 alice->admin permission edge has no aws:MultiFactorAuthPresent condition evidence.
- The exact Env15 alice->admin trust edge exists structurally.
- The exact Env16 alice->admins path has no identity_deny blocker evidence.
- The exact Env16 alice->admins path is emitted as validated group membership escalation.
- The exact Env16 alice->admins path is not emitted as blocked or inconclusive.
- The exact Env17 alice->admin path has no SCP blocker evidence.
- The exact Env17 alice->admin path is emitted as validated admin reachability.
- The exact Env17 alice->admin path is not emitted as blocked or inconclusive.
- The exact Env17 alice->admin permission edge exists structurally.
- The exact Env17 alice->admin trust edge exists structurally.
- The exact Env17 alice->admin trust edge is not bound to an SCP constraint.
- The exact Env18 Lambda CreateFunction permission edge exists structurally.
- The exact Env18 Lambda service trust edge exists structurally.
- The exact Env18 alice->lambda-admin path is emitted as validated passrole_lambda.
- The exact Env18 alice->lambda-admin path is not emitted as blocked, inconclusive, or precondition_only.
- The exact Env18 iam:PassRole permission edge exists structurally.
- The exact Env19 Lambda CreateFunction permission edge exists structurally.
- The exact Env19 Lambda service trust edge exists structurally.
- The exact Env19 alice->lambda-admin path is emitted as precondition_only passrole_lambda under current reasoner semantics.
- The exact Env19 alice->lambda-admin path is not emitted as validated passrole_lambda.
- The exact Env19 iam:PassRole permission edge exists structurally and carries iam:PassedToService condition evidence.
- The exact Env20 ECS RegisterTaskDefinition permission edge exists structurally.
- The exact Env20 ECS RunTask permission edge exists structurally.
- The exact Env20 ECS task service trust edge exists structurally.
- The exact Env20 alice->ecs-admin-task path is emitted as validated passrole_ecs.
- The exact Env20 alice->ecs-admin-task path is not emitted as blocked, inconclusive, or precondition_only.
- The exact Env20 iam:PassRole permission edge exists structurally.
- The exact Env21 ECS RegisterTaskDefinition permission edge exists structurally.
- The exact Env21 ECS RunTask permission edge exists structurally.
- The exact Env21 ECS task service trust edge exists structurally.
- The exact Env21 alice->ecs-admin-task path is emitted as precondition_only passrole_ecs under current reasoner semantics.
- The exact Env21 alice->ecs-admin-task path is not emitted as validated passrole_ecs.
- The exact Env21 iam:PassRole permission edge exists structurally and carries iam:PassedToService condition evidence.
- The exact Env22 alice->cross-account-admin path is emitted as validated admin_reachability.
- The exact Env22 alice->cross-account-admin path is emitted as validated cross_account_trust.
- The exact Env22 alice->cross-account-admin path is not emitted as blocked or inconclusive.
- The exact Env22 cross-account permission edge exists structurally.
- The exact Env22 cross-account trust edge exists structurally.
- The exact Env23 alice->cross-account-admin path has no matching trust edge.
- The exact Env23 alice->cross-account-admin path is not emitted as validated admin_reachability.
- The exact Env23 alice->cross-account-admin path is not emitted as validated cross_account_trust.
- The exact Env23 cross-account permission edge exists structurally.
- The exact Env24 edge is unconditioned and has resource-policy provenance.
- The exact Env24 resource-policy Allow edge exists structurally.
- The permission edge carries aws:MultiFactorAuthPresent condition evidence.
- The trust edge carries TRUST_CONDITION evidence for aws:MultiFactorAuthPresent.
- This exact blocked group-escalation path is truthfully detected as blocked.
- This exact boundary-blocked admin path is not overclaimed as validated.
- This exact mutated admin path is emitted as validated.
- This exact mutated admin path is not emitted as blocked or inconclusive.
- This exact positive admin path is emitted as validated.
- This exact positive admin path is not emitted as blocked or inconclusive.

### Still Unknown
- Conditioned cross-account trust paths remain outside this case.
- Conditioned resource-policy Allow statements remain outside this case.
- Env23 and later mutations should test principal-scoped-away and conditioned cross-account trust paths.
- Env25 scoped-away mutation remains future work.
- False-negative behavior for partially parsed or malformed deny policies remains unknown here.
- Finding-level resource-policy Allow semantics remain outside this case.
- Generic resource-policy Deny remains explicitly de-scoped.
- How SCP, permission-boundary, and identity-Deny blockers interact with ECS PassRole remains outside this case.
- How SCP, permission-boundary, and identity-Deny blockers interact with Lambda PassRole remains outside this case.
- How boundary handling behaves across longer chains or richer policy shapes remains unproven here.
- How consistent the same guarded behavior is across richer multi-condition trust policies remains unknown here.
- How every iam:PassedToService condition shape behaves remains outside this case.
- How richer permission-condition operators behave remains unknown here.
- How stable the same positive result is across richer trust-policy shapes remains unknown here.
- How stable the same positive result is across richer two-hop policy shapes remains unknown here.
- How stable the same positive-path result is across more complex mixed-signal environments remains unknown here.
- How stable the same structural/non-admin behavior is across richer policy shapes remains unknown here.
- How the same deny logic behaves in more complex multi-hop paths remains unproven here.
- How unsupported iam:PassedToService operators behave remains outside this case.
- How validated admin reachability behaves across longer chains or richer trust-policy shapes remains unproven here.
- Longer cross-account chains remain outside this case.
- Reasoner interactions outside the Env05 path family remain unknown here.
- Resource-policy Allow and generic resource-policy Deny remain outside this case.
- Whether assume_role_chain consistently validates the same positive path remains unproven here.
- Whether broader PassRole families validate the same way remains unknown here.
- Whether broader PassRole mutation families behave the same way remains unknown here.
- Whether broader non-admin path families should become first-class findings remains unproven here.
- Whether every complete SCP removal should validate remains unproven here.
- Whether every permission-condition removal should validate remains unproven here.
- Whether every trust-condition removal should validate remains unproven here.
- Whether multi-account AssumeRole paths interact with SCP removal the same way remains outside this case.
- Whether multi-account cross-account AssumeRole paths interact with SCPs the same way remains outside this case.
- Whether other SCP condition and exception forms produce the intended truth states remains outside this case.
- Whether other broad trust principal shapes behave the same way remains unknown here.
- Whether other condition operators should resolve to blocked rather than inconclusive remains unknown here.
- Whether other reasoner families should expose permission-condition evidence differently remains unknown here.
- Whether other trust-condition shapes should resolve to blocked rather than inconclusive remains unknown here.
- Whether the management caller PrincipalArn carveout works for every credential sourcing shape remains outside this case.

## phase0-20260508-env25

- Corpus decision: `hold_review`
- Total cases evaluated: `22`
- Passes: `22`
- Failures: `0`
- Blocked promotions: `0`
- Artifact insufficient count: `0`
- Human review required count: `22`
- README: `benchmarks/snapshots/phase0-20260508-env25/README.md`
- Corpus report: `benchmarks/snapshots/phase0-20260508-env25/corpus/corpus_report.md`

### Included Cases / Runs
- `env03_identity_deny_group_escalation` / `iamscope-benchmark-env03-20260424T025701Z`
- `env05_permission_boundary_blocked_chain` / `iamscope-benchmark-env05-20260424T203548Z`
- `env06_validated_admin_reachability` / `iamscope-benchmark-env06-20260425T003000Z`
- `env07_validated_non_admin_reachability` / `iamscope-benchmark-env07-20260424T222444Z`
- `env08_trust_condition_blocked_admin` / `iamscope-benchmark-env08-20260425T002835Z`
- `env09_boundary_removed_validated_admin` / `iamscope-benchmark-env09-20260425T012013Z`
- `env10_trust_condition_removed_validated_admin` / `iamscope-benchmark-env10-20260425T015458Z`
- `env11_broad_trust_condition_blocked_admin` / `iamscope-benchmark-env11-20260425T020442Z`
- `env12_scp_blocked_assumerole` / `iamscope-benchmark-env12-20260425T032022Z`
- `env13_complete_scp_blocked_assumerole` / `iamscope-benchmark-env13-20260425T035707Z`
- `env14_permission_condition_blocked_admin` / `iamscope-benchmark-env14-24940398230`
- `env15_permission_condition_removed_validated_admin` / `iamscope-benchmark-env15-24940398230`
- `env16_identity_deny_removed_validated_group_escalation` / `iamscope-benchmark-env16-24940398230`
- `env17_scp_removed_validated_admin` / `iamscope-benchmark-env17-24940398230`
- `env18_lambda_passrole_validated` / `iamscope-benchmark-env18-24940398230`
- `env19_passedtoservice_scoped_away_nonvalidated` / `iamscope-benchmark-env19-24940398230`
- `env20_ecs_passrole_validated` / `iamscope-benchmark-env20-24940398230`
- `env21_ecs_passedtoservice_scoped_away_nonvalidated` / `iamscope-benchmark-env21-24940398230`
- `env22_cross_account_validated_admin` / `iamscope-benchmark-env22-20260505T210729Z`
- `env23_cross_account_trust_scoped_away_nonvalidated` / `iamscope-benchmark-env23-20260506T020925Z`
- `env24_s3_resource_policy_allow` / `iamscope-benchmark-env24-20260508T151202Z`
- `env25_s3_resource_policy_allow_scoped_away_nonvalidated` / `iamscope-benchmark-env25-20260508T210637Z`

### Mutation Signals
- Mutation signal present without pairwise scoring: Env05 boundary-present case remains blocked/non-validated, while Env09 boundary-removed case validates admin reachability.

### Directly Proven
- A live Organizations SCP denying sts:AssumeRole on env12-admin is present in scenario.json.
- A live Organizations SCP denying sts:AssumeRole with wildcard Resource is present in scenario.json.
- No generic RESOURCE_POLICY_DENY constraint is emitted.
- The Env10 trust edge is not bound to aws:MultiFactorAuthPresent TRUST_CONDITION evidence.
- The Env11 target role has broad-looking trust structure.
- The Env12 trust edge is bound to an SCP constraint.
- The Env13 trust edge is bound to an SCP constraint.
- The Env24 target path is not accidentally witnessed by an identity-policy s3:GetObject edge.
- The Env25 decoy edge is unconditioned and has resource-policy provenance.
- The Env25 reader path is not accidentally witnessed by an identity-policy s3:GetObject edge.
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
- The exact Env15 alice->admin path is emitted as validated admin reachability.
- The exact Env15 alice->admin path is not emitted as blocked or inconclusive.
- The exact Env15 alice->admin permission edge exists structurally.
- The exact Env15 alice->admin permission edge has no aws:MultiFactorAuthPresent condition evidence.
- The exact Env15 alice->admin trust edge exists structurally.
- The exact Env16 alice->admins path has no identity_deny blocker evidence.
- The exact Env16 alice->admins path is emitted as validated group membership escalation.
- The exact Env16 alice->admins path is not emitted as blocked or inconclusive.
- The exact Env17 alice->admin path has no SCP blocker evidence.
- The exact Env17 alice->admin path is emitted as validated admin reachability.
- The exact Env17 alice->admin path is not emitted as blocked or inconclusive.
- The exact Env17 alice->admin permission edge exists structurally.
- The exact Env17 alice->admin trust edge exists structurally.
- The exact Env17 alice->admin trust edge is not bound to an SCP constraint.
- The exact Env18 Lambda CreateFunction permission edge exists structurally.
- The exact Env18 Lambda service trust edge exists structurally.
- The exact Env18 alice->lambda-admin path is emitted as validated passrole_lambda.
- The exact Env18 alice->lambda-admin path is not emitted as blocked, inconclusive, or precondition_only.
- The exact Env18 iam:PassRole permission edge exists structurally.
- The exact Env19 Lambda CreateFunction permission edge exists structurally.
- The exact Env19 Lambda service trust edge exists structurally.
- The exact Env19 alice->lambda-admin path is emitted as precondition_only passrole_lambda under current reasoner semantics.
- The exact Env19 alice->lambda-admin path is not emitted as validated passrole_lambda.
- The exact Env19 iam:PassRole permission edge exists structurally and carries iam:PassedToService condition evidence.
- The exact Env20 ECS RegisterTaskDefinition permission edge exists structurally.
- The exact Env20 ECS RunTask permission edge exists structurally.
- The exact Env20 ECS task service trust edge exists structurally.
- The exact Env20 alice->ecs-admin-task path is emitted as validated passrole_ecs.
- The exact Env20 alice->ecs-admin-task path is not emitted as blocked, inconclusive, or precondition_only.
- The exact Env20 iam:PassRole permission edge exists structurally.
- The exact Env21 ECS RegisterTaskDefinition permission edge exists structurally.
- The exact Env21 ECS RunTask permission edge exists structurally.
- The exact Env21 ECS task service trust edge exists structurally.
- The exact Env21 alice->ecs-admin-task path is emitted as precondition_only passrole_ecs under current reasoner semantics.
- The exact Env21 alice->ecs-admin-task path is not emitted as validated passrole_ecs.
- The exact Env21 iam:PassRole permission edge exists structurally and carries iam:PassedToService condition evidence.
- The exact Env22 alice->cross-account-admin path is emitted as validated admin_reachability.
- The exact Env22 alice->cross-account-admin path is emitted as validated cross_account_trust.
- The exact Env22 alice->cross-account-admin path is not emitted as blocked or inconclusive.
- The exact Env22 cross-account permission edge exists structurally.
- The exact Env22 cross-account trust edge exists structurally.
- The exact Env23 alice->cross-account-admin path has no matching trust edge.
- The exact Env23 alice->cross-account-admin path is not emitted as validated admin_reachability.
- The exact Env23 alice->cross-account-admin path is not emitted as validated cross_account_trust.
- The exact Env23 cross-account permission edge exists structurally.
- The exact Env24 edge is unconditioned and has resource-policy provenance.
- The exact Env24 resource-policy Allow edge exists structurally.
- The exact Env25 decoy resource-policy Allow edge exists structurally.
- The exact Env25 reader resource-policy Allow edge is absent.
- The permission edge carries aws:MultiFactorAuthPresent condition evidence.
- The trust edge carries TRUST_CONDITION evidence for aws:MultiFactorAuthPresent.
- This exact blocked group-escalation path is truthfully detected as blocked.
- This exact boundary-blocked admin path is not overclaimed as validated.
- This exact mutated admin path is emitted as validated.
- This exact mutated admin path is not emitted as blocked or inconclusive.
- This exact positive admin path is emitted as validated.
- This exact positive admin path is not emitted as blocked or inconclusive.

### Still Unknown
- Conditioned cross-account trust paths remain outside this case.
- Conditioned resource-policy Allow statements remain outside this case.
- Env23 and later mutations should test principal-scoped-away and conditioned cross-account trust paths.
- Env25 scoped-away mutation remains future work.
- False-negative behavior for partially parsed or malformed deny policies remains unknown here.
- Finding-level resource-policy Allow semantics remain outside this case.
- Generic resource-policy Deny remains explicitly de-scoped.
- How SCP, permission-boundary, and identity-Deny blockers interact with ECS PassRole remains outside this case.
- How SCP, permission-boundary, and identity-Deny blockers interact with Lambda PassRole remains outside this case.
- How boundary handling behaves across longer chains or richer policy shapes remains unproven here.
- How consistent the same guarded behavior is across richer multi-condition trust policies remains unknown here.
- How every iam:PassedToService condition shape behaves remains outside this case.
- How richer permission-condition operators behave remains unknown here.
- How stable the same positive result is across richer trust-policy shapes remains unknown here.
- How stable the same positive result is across richer two-hop policy shapes remains unknown here.
- How stable the same positive-path result is across more complex mixed-signal environments remains unknown here.
- How stable the same structural/non-admin behavior is across richer policy shapes remains unknown here.
- How the same deny logic behaves in more complex multi-hop paths remains unproven here.
- How unsupported iam:PassedToService operators behave remains outside this case.
- How validated admin reachability behaves across longer chains or richer trust-policy shapes remains unproven here.
- Longer cross-account chains remain outside this case.
- Reasoner interactions outside the Env05 path family remain unknown here.
- Resource-policy Allow and generic resource-policy Deny remain outside this case.
- Whether assume_role_chain consistently validates the same positive path remains unproven here.
- Whether broader PassRole families validate the same way remains unknown here.
- Whether broader PassRole mutation families behave the same way remains unknown here.
- Whether broader non-admin path families should become first-class findings remains unproven here.
- Whether every complete SCP removal should validate remains unproven here.
- Whether every permission-condition removal should validate remains unproven here.
- Whether every trust-condition removal should validate remains unproven here.
- Whether multi-account AssumeRole paths interact with SCP removal the same way remains outside this case.
- Whether multi-account cross-account AssumeRole paths interact with SCPs the same way remains outside this case.
- Whether other SCP condition and exception forms produce the intended truth states remains outside this case.
- Whether other broad trust principal shapes behave the same way remains unknown here.
- Whether other condition operators should resolve to blocked rather than inconclusive remains unknown here.
- Whether other reasoner families should expose permission-condition evidence differently remains unknown here.
- Whether other trust-condition shapes should resolve to blocked rather than inconclusive remains unknown here.
- Whether the management caller PrincipalArn carveout works for every credential sourcing shape remains outside this case.

## phase0-20260509-env26

- Corpus decision: `hold_review`
- Total cases evaluated: `23`
- Passes: `23`
- Failures: `0`
- Blocked promotions: `0`
- Artifact insufficient count: `0`
- Human review required count: `23`
- README: `benchmarks/snapshots/phase0-20260509-env26/README.md`
- Corpus report: `benchmarks/snapshots/phase0-20260509-env26/corpus/corpus_report.md`

### Included Cases / Runs
- `env03_identity_deny_group_escalation` / `iamscope-benchmark-env03-20260424T025701Z`
- `env05_permission_boundary_blocked_chain` / `iamscope-benchmark-env05-20260424T203548Z`
- `env06_validated_admin_reachability` / `iamscope-benchmark-env06-20260425T003000Z`
- `env07_validated_non_admin_reachability` / `iamscope-benchmark-env07-20260424T222444Z`
- `env08_trust_condition_blocked_admin` / `iamscope-benchmark-env08-20260425T002835Z`
- `env09_boundary_removed_validated_admin` / `iamscope-benchmark-env09-20260425T012013Z`
- `env10_trust_condition_removed_validated_admin` / `iamscope-benchmark-env10-20260425T015458Z`
- `env11_broad_trust_condition_blocked_admin` / `iamscope-benchmark-env11-20260425T020442Z`
- `env12_scp_blocked_assumerole` / `iamscope-benchmark-env12-20260425T032022Z`
- `env13_complete_scp_blocked_assumerole` / `iamscope-benchmark-env13-20260425T035707Z`
- `env14_permission_condition_blocked_admin` / `iamscope-benchmark-env14-24940398230`
- `env15_permission_condition_removed_validated_admin` / `iamscope-benchmark-env15-24940398230`
- `env16_identity_deny_removed_validated_group_escalation` / `iamscope-benchmark-env16-24940398230`
- `env17_scp_removed_validated_admin` / `iamscope-benchmark-env17-24940398230`
- `env18_lambda_passrole_validated` / `iamscope-benchmark-env18-24940398230`
- `env19_passedtoservice_scoped_away_nonvalidated` / `iamscope-benchmark-env19-24940398230`
- `env20_ecs_passrole_validated` / `iamscope-benchmark-env20-24940398230`
- `env21_ecs_passedtoservice_scoped_away_nonvalidated` / `iamscope-benchmark-env21-24940398230`
- `env22_cross_account_validated_admin` / `iamscope-benchmark-env22-20260505T210729Z`
- `env23_cross_account_trust_scoped_away_nonvalidated` / `iamscope-benchmark-env23-20260506T020925Z`
- `env24_s3_resource_policy_allow` / `iamscope-benchmark-env24-20260508T151202Z`
- `env25_s3_resource_policy_allow_scoped_away_nonvalidated` / `iamscope-benchmark-env25-20260508T210637Z`
- `env26_multihop_chain_validated_admin` / `iamscope-benchmark-env26-20260509T012216Z`

### Mutation Signals
- Mutation signal present without pairwise scoring: Env05 boundary-present case remains blocked/non-validated, while Env09 boundary-removed case validates admin reachability.

### Directly Proven
- A live Organizations SCP denying sts:AssumeRole on env12-admin is present in scenario.json.
- A live Organizations SCP denying sts:AssumeRole with wildcard Resource is present in scenario.json.
- No generic RESOURCE_POLICY_DENY constraint is emitted.
- The Env10 trust edge is not bound to aws:MultiFactorAuthPresent TRUST_CONDITION evidence.
- The Env11 target role has broad-looking trust structure.
- The Env12 trust edge is bound to an SCP constraint.
- The Env13 trust edge is bound to an SCP constraint.
- The Env24 target path is not accidentally witnessed by an identity-policy s3:GetObject edge.
- The Env25 decoy edge is unconditioned and has resource-policy provenance.
- The Env25 reader path is not accidentally witnessed by an identity-policy s3:GetObject edge.
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
- The exact Env15 alice->admin path is emitted as validated admin reachability.
- The exact Env15 alice->admin path is not emitted as blocked or inconclusive.
- The exact Env15 alice->admin permission edge exists structurally.
- The exact Env15 alice->admin permission edge has no aws:MultiFactorAuthPresent condition evidence.
- The exact Env15 alice->admin trust edge exists structurally.
- The exact Env16 alice->admins path has no identity_deny blocker evidence.
- The exact Env16 alice->admins path is emitted as validated group membership escalation.
- The exact Env16 alice->admins path is not emitted as blocked or inconclusive.
- The exact Env17 alice->admin path has no SCP blocker evidence.
- The exact Env17 alice->admin path is emitted as validated admin reachability.
- The exact Env17 alice->admin path is not emitted as blocked or inconclusive.
- The exact Env17 alice->admin permission edge exists structurally.
- The exact Env17 alice->admin trust edge exists structurally.
- The exact Env17 alice->admin trust edge is not bound to an SCP constraint.
- The exact Env18 Lambda CreateFunction permission edge exists structurally.
- The exact Env18 Lambda service trust edge exists structurally.
- The exact Env18 alice->lambda-admin path is emitted as validated passrole_lambda.
- The exact Env18 alice->lambda-admin path is not emitted as blocked, inconclusive, or precondition_only.
- The exact Env18 iam:PassRole permission edge exists structurally.
- The exact Env19 Lambda CreateFunction permission edge exists structurally.
- The exact Env19 Lambda service trust edge exists structurally.
- The exact Env19 alice->lambda-admin path is emitted as precondition_only passrole_lambda under current reasoner semantics.
- The exact Env19 alice->lambda-admin path is not emitted as validated passrole_lambda.
- The exact Env19 iam:PassRole permission edge exists structurally and carries iam:PassedToService condition evidence.
- The exact Env20 ECS RegisterTaskDefinition permission edge exists structurally.
- The exact Env20 ECS RunTask permission edge exists structurally.
- The exact Env20 ECS task service trust edge exists structurally.
- The exact Env20 alice->ecs-admin-task path is emitted as validated passrole_ecs.
- The exact Env20 alice->ecs-admin-task path is not emitted as blocked, inconclusive, or precondition_only.
- The exact Env20 iam:PassRole permission edge exists structurally.
- The exact Env21 ECS RegisterTaskDefinition permission edge exists structurally.
- The exact Env21 ECS RunTask permission edge exists structurally.
- The exact Env21 ECS task service trust edge exists structurally.
- The exact Env21 alice->ecs-admin-task path is emitted as precondition_only passrole_ecs under current reasoner semantics.
- The exact Env21 alice->ecs-admin-task path is not emitted as validated passrole_ecs.
- The exact Env21 iam:PassRole permission edge exists structurally and carries iam:PassedToService condition evidence.
- The exact Env22 alice->cross-account-admin path is emitted as validated admin_reachability.
- The exact Env22 alice->cross-account-admin path is emitted as validated cross_account_trust.
- The exact Env22 alice->cross-account-admin path is not emitted as blocked or inconclusive.
- The exact Env22 cross-account permission edge exists structurally.
- The exact Env22 cross-account trust edge exists structurally.
- The exact Env23 alice->cross-account-admin path has no matching trust edge.
- The exact Env23 alice->cross-account-admin path is not emitted as validated admin_reachability.
- The exact Env23 alice->cross-account-admin path is not emitted as validated cross_account_trust.
- The exact Env23 cross-account permission edge exists structurally.
- The exact Env24 edge is unconditioned and has resource-policy provenance.
- The exact Env24 resource-policy Allow edge exists structurally.
- The exact Env25 decoy resource-policy Allow edge exists structurally.
- The exact Env25 reader resource-policy Allow edge is absent.
- The exact Env26 Alice-to-admin path is emitted as validated admin_reachability.
- The exact Env26 Alice-to-admin path is emitted as validated assume_role_chain.
- The exact Env26 Alice-to-admin path is not emitted as blocked or inconclusive.
- The exact Env26 three-hop permission/trust chain exists structurally.
- The permission edge carries aws:MultiFactorAuthPresent condition evidence.
- The trust edge carries TRUST_CONDITION evidence for aws:MultiFactorAuthPresent.
- This exact blocked group-escalation path is truthfully detected as blocked.
- This exact boundary-blocked admin path is not overclaimed as validated.
- This exact mutated admin path is emitted as validated.
- This exact mutated admin path is not emitted as blocked or inconclusive.
- This exact positive admin path is emitted as validated.
- This exact positive admin path is not emitted as blocked or inconclusive.

### Still Unknown
- Conditioned cross-account trust paths remain outside this case.
- Conditioned resource-policy Allow statements remain outside this case.
- Cross-account multi-hop chains remain outside this case.
- Env23 and later mutations should test principal-scoped-away and conditioned cross-account trust paths.
- Env25 scoped-away mutation remains future work.
- Env27 should test the scoped-away middle-trust mutation.
- False-negative behavior for partially parsed or malformed deny policies remains unknown here.
- Finding-level resource-policy Allow semantics remain outside this case.
- Generic resource-policy Deny remains explicitly de-scoped.
- How SCP, permission-boundary, and identity-Deny blockers interact with ECS PassRole remains outside this case.
- How SCP, permission-boundary, and identity-Deny blockers interact with Lambda PassRole remains outside this case.
- How boundary handling behaves across longer chains or richer policy shapes remains unproven here.
- How consistent the same guarded behavior is across richer multi-condition trust policies remains unknown here.
- How every iam:PassedToService condition shape behaves remains outside this case.
- How richer permission-condition operators behave remains unknown here.
- How stable the same positive result is across richer trust-policy shapes remains unknown here.
- How stable the same positive result is across richer two-hop policy shapes remains unknown here.
- How stable the same positive-path result is across more complex mixed-signal environments remains unknown here.
- How stable the same structural/non-admin behavior is across richer policy shapes remains unknown here.
- How the same deny logic behaves in more complex multi-hop paths remains unproven here.
- How unsupported iam:PassedToService operators behave remains outside this case.
- How validated admin reachability behaves across longer chains or richer trust-policy shapes remains unproven here.
- Longer chains and conditioned middle-hop controls remain outside this case.
- Longer cross-account chains remain outside this case.
- Reasoner interactions outside the Env05 path family remain unknown here.
- Resource-policy Allow and generic resource-policy Deny remain outside this case.
- Whether assume_role_chain consistently validates the same positive path remains unproven here.
- Whether broader PassRole families validate the same way remains unknown here.
- Whether broader PassRole mutation families behave the same way remains unknown here.
- Whether broader non-admin path families should become first-class findings remains unproven here.
- Whether every complete SCP removal should validate remains unproven here.
- Whether every permission-condition removal should validate remains unproven here.
- Whether every trust-condition removal should validate remains unproven here.
- Whether multi-account AssumeRole paths interact with SCP removal the same way remains outside this case.
- Whether multi-account cross-account AssumeRole paths interact with SCPs the same way remains outside this case.
- Whether other SCP condition and exception forms produce the intended truth states remains outside this case.
- Whether other broad trust principal shapes behave the same way remains unknown here.
- Whether other condition operators should resolve to blocked rather than inconclusive remains unknown here.
- Whether other reasoner families should expose permission-condition evidence differently remains unknown here.
- Whether other trust-condition shapes should resolve to blocked rather than inconclusive remains unknown here.
- Whether the management caller PrincipalArn carveout works for every credential sourcing shape remains outside this case.

## phase0-20260509-env27

- Corpus decision: `hold_review`
- Total cases evaluated: `24`
- Passes: `24`
- Failures: `0`
- Blocked promotions: `0`
- Artifact insufficient count: `0`
- Human review required count: `24`
- README: `benchmarks/snapshots/phase0-20260509-env27/README.md`
- Corpus report: `benchmarks/snapshots/phase0-20260509-env27/corpus/corpus_report.md`

### Included Cases / Runs
- `env03_identity_deny_group_escalation` / `iamscope-benchmark-env03-20260424T025701Z`
- `env05_permission_boundary_blocked_chain` / `iamscope-benchmark-env05-20260424T203548Z`
- `env06_validated_admin_reachability` / `iamscope-benchmark-env06-20260425T003000Z`
- `env07_validated_non_admin_reachability` / `iamscope-benchmark-env07-20260424T222444Z`
- `env08_trust_condition_blocked_admin` / `iamscope-benchmark-env08-20260425T002835Z`
- `env09_boundary_removed_validated_admin` / `iamscope-benchmark-env09-20260425T012013Z`
- `env10_trust_condition_removed_validated_admin` / `iamscope-benchmark-env10-20260425T015458Z`
- `env11_broad_trust_condition_blocked_admin` / `iamscope-benchmark-env11-20260425T020442Z`
- `env12_scp_blocked_assumerole` / `iamscope-benchmark-env12-20260425T032022Z`
- `env13_complete_scp_blocked_assumerole` / `iamscope-benchmark-env13-20260425T035707Z`
- `env14_permission_condition_blocked_admin` / `iamscope-benchmark-env14-24940398230`
- `env15_permission_condition_removed_validated_admin` / `iamscope-benchmark-env15-24940398230`
- `env16_identity_deny_removed_validated_group_escalation` / `iamscope-benchmark-env16-24940398230`
- `env17_scp_removed_validated_admin` / `iamscope-benchmark-env17-24940398230`
- `env18_lambda_passrole_validated` / `iamscope-benchmark-env18-24940398230`
- `env19_passedtoservice_scoped_away_nonvalidated` / `iamscope-benchmark-env19-24940398230`
- `env20_ecs_passrole_validated` / `iamscope-benchmark-env20-24940398230`
- `env21_ecs_passedtoservice_scoped_away_nonvalidated` / `iamscope-benchmark-env21-24940398230`
- `env22_cross_account_validated_admin` / `iamscope-benchmark-env22-20260505T210729Z`
- `env23_cross_account_trust_scoped_away_nonvalidated` / `iamscope-benchmark-env23-20260506T020925Z`
- `env24_s3_resource_policy_allow` / `iamscope-benchmark-env24-20260508T151202Z`
- `env25_s3_resource_policy_allow_scoped_away_nonvalidated` / `iamscope-benchmark-env25-20260508T210637Z`
- `env26_multihop_chain_validated_admin` / `iamscope-benchmark-env26-20260509T012216Z`
- `env27_multihop_trust_scoped_away_nonvalidated` / `iamscope-benchmark-env27-20260509T212354Z`

### Mutation Signals
- Mutation signal present without pairwise scoring: Env05 boundary-present case remains blocked/non-validated, while Env09 boundary-removed case validates admin reachability.

### Directly Proven
- A live Organizations SCP denying sts:AssumeRole on env12-admin is present in scenario.json.
- A live Organizations SCP denying sts:AssumeRole with wildcard Resource is present in scenario.json.
- No generic RESOURCE_POLICY_DENY constraint is emitted.
- The Env10 trust edge is not bound to aws:MultiFactorAuthPresent TRUST_CONDITION evidence.
- The Env11 target role has broad-looking trust structure.
- The Env12 trust edge is bound to an SCP constraint.
- The Env13 trust edge is bound to an SCP constraint.
- The Env24 target path is not accidentally witnessed by an identity-policy s3:GetObject edge.
- The Env25 decoy edge is unconditioned and has resource-policy provenance.
- The Env25 reader path is not accidentally witnessed by an identity-policy s3:GetObject edge.
- The Env27 decoy-to-hop2 trust edge exists.
- The Env27 downstream hop2-to-admin structure exists.
- The Env27 first-hop permission/trust structure exists.
- The Env27 hop1-to-hop2 matching trust edge is absent.
- The Env27 hop1-to-hop2 permission edge exists.
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
- The exact Env15 alice->admin path is emitted as validated admin reachability.
- The exact Env15 alice->admin path is not emitted as blocked or inconclusive.
- The exact Env15 alice->admin permission edge exists structurally.
- The exact Env15 alice->admin permission edge has no aws:MultiFactorAuthPresent condition evidence.
- The exact Env15 alice->admin trust edge exists structurally.
- The exact Env16 alice->admins path has no identity_deny blocker evidence.
- The exact Env16 alice->admins path is emitted as validated group membership escalation.
- The exact Env16 alice->admins path is not emitted as blocked or inconclusive.
- The exact Env17 alice->admin path has no SCP blocker evidence.
- The exact Env17 alice->admin path is emitted as validated admin reachability.
- The exact Env17 alice->admin path is not emitted as blocked or inconclusive.
- The exact Env17 alice->admin permission edge exists structurally.
- The exact Env17 alice->admin trust edge exists structurally.
- The exact Env17 alice->admin trust edge is not bound to an SCP constraint.
- The exact Env18 Lambda CreateFunction permission edge exists structurally.
- The exact Env18 Lambda service trust edge exists structurally.
- The exact Env18 alice->lambda-admin path is emitted as validated passrole_lambda.
- The exact Env18 alice->lambda-admin path is not emitted as blocked, inconclusive, or precondition_only.
- The exact Env18 iam:PassRole permission edge exists structurally.
- The exact Env19 Lambda CreateFunction permission edge exists structurally.
- The exact Env19 Lambda service trust edge exists structurally.
- The exact Env19 alice->lambda-admin path is emitted as precondition_only passrole_lambda under current reasoner semantics.
- The exact Env19 alice->lambda-admin path is not emitted as validated passrole_lambda.
- The exact Env19 iam:PassRole permission edge exists structurally and carries iam:PassedToService condition evidence.
- The exact Env20 ECS RegisterTaskDefinition permission edge exists structurally.
- The exact Env20 ECS RunTask permission edge exists structurally.
- The exact Env20 ECS task service trust edge exists structurally.
- The exact Env20 alice->ecs-admin-task path is emitted as validated passrole_ecs.
- The exact Env20 alice->ecs-admin-task path is not emitted as blocked, inconclusive, or precondition_only.
- The exact Env20 iam:PassRole permission edge exists structurally.
- The exact Env21 ECS RegisterTaskDefinition permission edge exists structurally.
- The exact Env21 ECS RunTask permission edge exists structurally.
- The exact Env21 ECS task service trust edge exists structurally.
- The exact Env21 alice->ecs-admin-task path is emitted as precondition_only passrole_ecs under current reasoner semantics.
- The exact Env21 alice->ecs-admin-task path is not emitted as validated passrole_ecs.
- The exact Env21 iam:PassRole permission edge exists structurally and carries iam:PassedToService condition evidence.
- The exact Env22 alice->cross-account-admin path is emitted as validated admin_reachability.
- The exact Env22 alice->cross-account-admin path is emitted as validated cross_account_trust.
- The exact Env22 alice->cross-account-admin path is not emitted as blocked or inconclusive.
- The exact Env22 cross-account permission edge exists structurally.
- The exact Env22 cross-account trust edge exists structurally.
- The exact Env23 alice->cross-account-admin path has no matching trust edge.
- The exact Env23 alice->cross-account-admin path is not emitted as validated admin_reachability.
- The exact Env23 alice->cross-account-admin path is not emitted as validated cross_account_trust.
- The exact Env23 cross-account permission edge exists structurally.
- The exact Env24 edge is unconditioned and has resource-policy provenance.
- The exact Env24 resource-policy Allow edge exists structurally.
- The exact Env25 decoy resource-policy Allow edge exists structurally.
- The exact Env25 reader resource-policy Allow edge is absent.
- The exact Env26 Alice-to-admin path is emitted as validated admin_reachability.
- The exact Env26 Alice-to-admin path is emitted as validated assume_role_chain.
- The exact Env26 Alice-to-admin path is not emitted as blocked or inconclusive.
- The exact Env26 three-hop permission/trust chain exists structurally.
- The exact Env27 Alice-to-admin path is not emitted as validated admin_reachability.
- The exact Env27 Alice-to-admin path is not emitted as validated assume_role_chain.
- The permission edge carries aws:MultiFactorAuthPresent condition evidence.
- The trust edge carries TRUST_CONDITION evidence for aws:MultiFactorAuthPresent.
- This exact blocked group-escalation path is truthfully detected as blocked.
- This exact boundary-blocked admin path is not overclaimed as validated.
- This exact mutated admin path is emitted as validated.
- This exact mutated admin path is not emitted as blocked or inconclusive.
- This exact positive admin path is emitted as validated.
- This exact positive admin path is not emitted as blocked or inconclusive.

### Still Unknown
- Conditioned cross-account trust paths remain outside this case.
- Conditioned middle-hop controls remain outside this case.
- Conditioned resource-policy Allow statements remain outside this case.
- Cross-account multi-hop chains remain outside this case.
- Env23 and later mutations should test principal-scoped-away and conditioned cross-account trust paths.
- Env25 scoped-away mutation remains future work.
- Env27 should test the scoped-away middle-trust mutation.
- False-negative behavior for partially parsed or malformed deny policies remains unknown here.
- Finding-level resource-policy Allow semantics remain outside this case.
- Generic resource-policy Deny remains explicitly de-scoped.
- How SCP, permission-boundary, and identity-Deny blockers interact with ECS PassRole remains outside this case.
- How SCP, permission-boundary, and identity-Deny blockers interact with Lambda PassRole remains outside this case.
- How boundary handling behaves across longer chains or richer policy shapes remains unproven here.
- How consistent the same guarded behavior is across richer multi-condition trust policies remains unknown here.
- How every iam:PassedToService condition shape behaves remains outside this case.
- How richer permission-condition operators behave remains unknown here.
- How stable the same positive result is across richer trust-policy shapes remains unknown here.
- How stable the same positive result is across richer two-hop policy shapes remains unknown here.
- How stable the same positive-path result is across more complex mixed-signal environments remains unknown here.
- How stable the same structural/non-admin behavior is across richer policy shapes remains unknown here.
- How the same deny logic behaves in more complex multi-hop paths remains unproven here.
- How unsupported iam:PassedToService operators behave remains outside this case.
- How validated admin reachability behaves across longer chains or richer trust-policy shapes remains unproven here.
- Longer chains and conditioned middle-hop controls remain outside this case.
- Longer chains remain outside this case.
- Longer cross-account chains remain outside this case.
- Reasoner interactions outside the Env05 path family remain unknown here.
- Resource-policy Allow and generic resource-policy Deny remain outside this case.
- Whether assume_role_chain consistently validates the same positive path remains unproven here.
- Whether broader PassRole families validate the same way remains unknown here.
- Whether broader PassRole mutation families behave the same way remains unknown here.
- Whether broader non-admin path families should become first-class findings remains unproven here.
- Whether every complete SCP removal should validate remains unproven here.
- Whether every permission-condition removal should validate remains unproven here.
- Whether every trust-condition removal should validate remains unproven here.
- Whether multi-account AssumeRole paths interact with SCP removal the same way remains outside this case.
- Whether multi-account cross-account AssumeRole paths interact with SCPs the same way remains outside this case.
- Whether other SCP condition and exception forms produce the intended truth states remains outside this case.
- Whether other broad trust principal shapes behave the same way remains unknown here.
- Whether other condition operators should resolve to blocked rather than inconclusive remains unknown here.
- Whether other reasoner families should expose permission-condition evidence differently remains unknown here.
- Whether other trust-condition shapes should resolve to blocked rather than inconclusive remains unknown here.
- Whether the management caller PrincipalArn carveout works for every credential sourcing shape remains outside this case.
