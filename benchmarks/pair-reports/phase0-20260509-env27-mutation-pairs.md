# Benchmark Mutation Pair Report: phase0-20260509-env27

This report summarizes expected vs observed deltas for known benchmark mutation pairs only. It does not emit a composite score and does not claim broad IAMScope correctness or production readiness.

- Snapshot: `benchmarks/snapshots/phase0-20260509-env27`
- Known pairs: `10`
- Complete pairs: `10`
- Pair deltas passed: `10`

No composite score is emitted.

## Pairs

### env03_env16_identity_deny_removed

- Control family: `identity_deny`
- Control-present case: `env03_identity_deny_group_escalation`
- Removed/mutated case: `env16_identity_deny_removed_validated_group_escalation`
- Expected control-present verdict: `blocked iam_group_membership_escalation`
- Expected mutation verdict: `validated iam_group_membership_escalation`
- Pair complete: `true`
- Pair delta passed: `true`
- Evidence boundary: Only compares the Env03/Env16 identity-Deny group-escalation path; it does not prove broad identity-Deny correctness.

#### Observed Control-Present Summary
- Status: `present`
- Run ID: `iamscope-benchmark-env03-20260424T025701Z`
- Score passed: `true`
- Artifact sufficient: `true`
- Promotion blocked: `false`
- Assertions passed: `true`

#### Observed Mutation Summary
- Status: `present`
- Run ID: `iamscope-benchmark-env16-24940398230`
- Score passed: `true`
- Artifact sufficient: `true`
- Promotion blocked: `false`
- Assertions passed: `true`

### env05_env09_permission_boundary_removed

- Control family: `permission_boundary`
- Control-present case: `env05_permission_boundary_blocked_chain`
- Removed/mutated case: `env09_boundary_removed_validated_admin`
- Expected control-present verdict: `blocked admin_reachability and blocked assume_role_chain`
- Expected mutation verdict: `validated admin_reachability`
- Pair complete: `true`
- Pair delta passed: `true`
- Evidence boundary: Only compares the Env05/Env09 permission-boundary assume-role/admin path; it does not prove broad boundary handling.

#### Observed Control-Present Summary
- Status: `present`
- Run ID: `iamscope-benchmark-env05-20260424T203548Z`
- Score passed: `true`
- Artifact sufficient: `true`
- Promotion blocked: `false`
- Assertions passed: `true`

#### Observed Mutation Summary
- Status: `present`
- Run ID: `iamscope-benchmark-env09-20260425T012013Z`
- Score passed: `true`
- Artifact sufficient: `true`
- Promotion blocked: `false`
- Assertions passed: `true`

### env08_env10_trust_condition_removed

- Control family: `trust_condition`
- Control-present case: `env08_trust_condition_blocked_admin`
- Removed/mutated case: `env10_trust_condition_removed_validated_admin`
- Expected control-present verdict: `non-validated admin_reachability`
- Expected mutation verdict: `validated admin_reachability`
- Pair complete: `true`
- Pair delta passed: `true`
- Evidence boundary: Only compares the Env08/Env10 trust-condition path; it does not prove every trust-condition shape.

#### Observed Control-Present Summary
- Status: `present`
- Run ID: `iamscope-benchmark-env08-20260425T002835Z`
- Score passed: `true`
- Artifact sufficient: `true`
- Promotion blocked: `false`
- Assertions passed: `true`

#### Observed Mutation Summary
- Status: `present`
- Run ID: `iamscope-benchmark-env10-20260425T015458Z`
- Score passed: `true`
- Artifact sufficient: `true`
- Promotion blocked: `false`
- Assertions passed: `true`

### env14_env15_permission_condition_removed

- Control family: `permission_condition`
- Control-present case: `env14_permission_condition_blocked_admin`
- Removed/mutated case: `env15_permission_condition_removed_validated_admin`
- Expected control-present verdict: `non-validated admin_reachability`
- Expected mutation verdict: `validated admin_reachability`
- Pair complete: `true`
- Pair delta passed: `true`
- Evidence boundary: Only compares the Env14/Env15 permission-side MFA-condition path; it does not prove every permission-condition shape.

#### Observed Control-Present Summary
- Status: `present`
- Run ID: `iamscope-benchmark-env14-24940398230`
- Score passed: `true`
- Artifact sufficient: `true`
- Promotion blocked: `false`
- Assertions passed: `true`

#### Observed Mutation Summary
- Status: `present`
- Run ID: `iamscope-benchmark-env15-24940398230`
- Score passed: `true`
- Artifact sufficient: `true`
- Promotion blocked: `false`
- Assertions passed: `true`

### env13_env17_scp_removed

- Control family: `scp`
- Control-present case: `env13_complete_scp_blocked_assumerole`
- Removed/mutated case: `env17_scp_removed_validated_admin`
- Expected control-present verdict: `blocked admin_reachability`
- Expected mutation verdict: `validated admin_reachability`
- Pair complete: `true`
- Pair delta passed: `true`
- Evidence boundary: Only compares the Env13/Env17 complete-SCP target path; it does not prove every SCP attachment or condition form.

#### Observed Control-Present Summary
- Status: `present`
- Run ID: `iamscope-benchmark-env13-20260425T035707Z`
- Score passed: `true`
- Artifact sufficient: `true`
- Promotion blocked: `false`
- Assertions passed: `true`

#### Observed Mutation Summary
- Status: `present`
- Run ID: `iamscope-benchmark-env17-24940398230`
- Score passed: `true`
- Artifact sufficient: `true`
- Promotion blocked: `false`
- Assertions passed: `true`

### env18_env19_lambda_passedtoservice_scoped_away

- Control family: `lambda_passrole_passedtoservice`
- Control-present case: `env18_lambda_passrole_validated`
- Removed/mutated case: `env19_passedtoservice_scoped_away_nonvalidated`
- Expected control-present verdict: `validated passrole_lambda`
- Expected mutation verdict: `precondition_only passrole_lambda`
- Pair complete: `true`
- Pair delta passed: `true`
- Evidence boundary: Only compares the Env18/Env19 Lambda PassRole path; it does not prove every iam:PassedToService operator or Lambda PassRole shape.

#### Observed Control-Present Summary
- Status: `present`
- Run ID: `iamscope-benchmark-env18-24940398230`
- Score passed: `true`
- Artifact sufficient: `true`
- Promotion blocked: `false`
- Assertions passed: `true`

#### Observed Mutation Summary
- Status: `present`
- Run ID: `iamscope-benchmark-env19-24940398230`
- Score passed: `true`
- Artifact sufficient: `true`
- Promotion blocked: `false`
- Assertions passed: `true`

### env20_env21_ecs_passedtoservice_scoped_away

- Control family: `ecs_passrole_passedtoservice`
- Control-present case: `env20_ecs_passrole_validated`
- Removed/mutated case: `env21_ecs_passedtoservice_scoped_away_nonvalidated`
- Expected control-present verdict: `validated passrole_ecs`
- Expected mutation verdict: `precondition_only passrole_ecs`
- Pair complete: `true`
- Pair delta passed: `true`
- Evidence boundary: Only compares the Env20/Env21 ECS PassRole path; it does not prove every iam:PassedToService operator or ECS PassRole shape.

#### Observed Control-Present Summary
- Status: `present`
- Run ID: `iamscope-benchmark-env20-24940398230`
- Score passed: `true`
- Artifact sufficient: `true`
- Promotion blocked: `false`
- Assertions passed: `true`

#### Observed Mutation Summary
- Status: `present`
- Run ID: `iamscope-benchmark-env21-24940398230`
- Score passed: `true`
- Artifact sufficient: `true`
- Promotion blocked: `false`
- Assertions passed: `true`

### env22_env23_cross_account_trust_scoped_away

- Control family: `cross_account_trust`
- Control-present case: `env22_cross_account_validated_admin`
- Removed/mutated case: `env23_cross_account_trust_scoped_away_nonvalidated`
- Expected control-present verdict: `validated admin_reachability and validated cross_account_trust`
- Expected mutation verdict: `non-validated admin_reachability and non-validated cross_account_trust`
- Pair complete: `true`
- Pair delta passed: `true`
- Evidence boundary: Only compares the Env22/Env23 cross-account AssumeRole path; it does not prove every cross-account trust principal shape.

#### Observed Control-Present Summary
- Status: `present`
- Run ID: `iamscope-benchmark-env22-20260505T210729Z`
- Score passed: `true`
- Artifact sufficient: `true`
- Promotion blocked: `false`
- Assertions passed: `true`

#### Observed Mutation Summary
- Status: `present`
- Run ID: `iamscope-benchmark-env23-20260506T020925Z`
- Score passed: `true`
- Artifact sufficient: `true`
- Promotion blocked: `false`
- Assertions passed: `true`

### env24_env25_s3_resource_policy_allow_scoped_away

- Control family: `s3_resource_policy_allow`
- Control-present case: `env24_s3_resource_policy_allow`
- Removed/mutated case: `env25_s3_resource_policy_allow_scoped_away_nonvalidated`
- Expected control-present verdict: `scenario-edge resource-policy Allow edge present for reader`
- Expected mutation verdict: `reader resource-policy Allow edge absent; decoy resource-policy Allow edge present`
- Pair complete: `true`
- Pair delta passed: `true`
- Evidence boundary: Only compares the Env24/Env25 S3 resource-policy Allow scenario-edge path; it does not prove finding-level resource-policy reachability or generic resource-policy Deny support.

#### Observed Control-Present Summary
- Status: `present`
- Run ID: `iamscope-benchmark-env24-20260508T151202Z`
- Score passed: `true`
- Artifact sufficient: `true`
- Promotion blocked: `false`
- Assertions passed: `true`

#### Observed Mutation Summary
- Status: `present`
- Run ID: `iamscope-benchmark-env25-20260508T210637Z`
- Score passed: `true`
- Artifact sufficient: `true`
- Promotion blocked: `false`
- Assertions passed: `true`

### env26_env27_multihop_trust_scoped_away

- Control family: `same_account_multihop_trust`
- Control-present case: `env26_multihop_chain_validated_admin`
- Removed/mutated case: `env27_multihop_trust_scoped_away_nonvalidated`
- Expected control-present verdict: `validated assume_role_chain and validated admin_reachability`
- Expected mutation verdict: `non-validated assume_role_chain and non-validated admin_reachability`
- Pair complete: `true`
- Pair delta passed: `true`
- Evidence boundary: Only compares the Env26/Env27 controlled same-account multihop AssumeRole path; it does not prove arbitrary enterprise graph correctness or broader multihop-chain behavior.

#### Observed Control-Present Summary
- Status: `present`
- Run ID: `iamscope-benchmark-env26-20260509T012216Z`
- Score passed: `true`
- Artifact sufficient: `true`
- Promotion blocked: `false`
- Assertions passed: `true`

#### Observed Mutation Summary
- Status: `present`
- Run ID: `iamscope-benchmark-env27-20260509T212354Z`
- Score passed: `true`
- Artifact sufficient: `true`
- Promotion blocked: `false`
- Assertions passed: `true`
