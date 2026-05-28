# Phase 0 Benchmark Corpus Summary

This summary applies only to the evaluated corpus cases listed below. It does not claim broad IAMScope correctness.

- Total cases evaluated: `3`
- Passes: `3`
- Failures: `0`
- Blocked promotions: `0`
- Artifact insufficient count: `0`
- Human review required count: `3`
- Promotion decision: `hold_review`

## Directly Proven
- The blocked chain and blocked admin reachability are both observed for the benchmark path.
- The blocker attribution includes identity_deny evidence.
- This exact blocked group-escalation path is truthfully detected as blocked.
- This exact boundary-blocked admin path is not overclaimed as validated.
- This exact positive admin path is emitted as validated.
- This exact positive admin path is not emitted as blocked or inconclusive.

## Strongly Supported
- The current boundary resolution path is coherent for this narrow real-AWS case.
- The current deny binder + reasoner path is coherent for this narrow real-AWS case.
- The current positive admin-reachability path is coherent for this narrow real-AWS case.

## Only Implied
- Broader deny coverage outside this exact path family is only implied, not directly proven.
- Broader positive-path coverage outside this exact case remains only implied.
- Broader positive-vs-blocked admin reachability behavior outside this path family is only implied.

## Still Unknown
- False-negative behavior for partially parsed or malformed deny policies remains unknown here.
- How boundary handling behaves across longer chains or richer policy shapes remains unproven here.
- How stable the same positive-path result is across more complex mixed-signal environments remains unknown here.
- How the same deny logic behaves in more complex multi-hop paths remains unproven here.
- How validated admin reachability behaves across longer chains or richer trust-policy shapes remains unproven here.
- Reasoner interactions outside the Env05 path family remain unknown here.

## Cases
- `env03_identity_deny_group_escalation` / `iamscope-benchmark-env03-20260424T025701Z`: score_passed=`true`, promotion_blocked=`false`, artifact_sufficient=`true`, human_review_required=`true`, defect_classes=none
- `env05_permission_boundary_blocked_chain` / `iamscope-benchmark-env05-20260424T203548Z`: score_passed=`true`, promotion_blocked=`false`, artifact_sufficient=`true`, human_review_required=`true`, defect_classes=none
- `env06_validated_admin_reachability` / `iamscope-benchmark-env06-20260424T044157Z`: score_passed=`true`, promotion_blocked=`false`, artifact_sufficient=`true`, human_review_required=`true`, defect_classes=none

## Aggregate Defects
- None
