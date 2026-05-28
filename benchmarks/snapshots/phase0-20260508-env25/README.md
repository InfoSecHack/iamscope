# Phase 0 Benchmark Snapshot: phase0-20260508-env25

- snapshot_id: `phase0-20260508-env25`
- created_at: `2026-05-08T21:18:46Z`
- source runs dir: `/tmp/iamscope-env25-freeze-runs`
- source corpus dir: `/tmp/iamscope-env25-freeze-corpus`
- corpus decision: `hold_review`
- total evaluated cases: `22`
- passed cases: `22`
- failed cases: `0`

## Included Cases / Runs
- env03_identity_deny_group_escalation / iamscope-benchmark-env03-20260424T025701Z -> runs/env03-20260424T025701Z
- env05_permission_boundary_blocked_chain / iamscope-benchmark-env05-20260424T203548Z -> runs/env05-20260424T203548Z
- env06_validated_admin_reachability / iamscope-benchmark-env06-20260425T003000Z -> runs/env06-20260425T003000Z
- env07_validated_non_admin_reachability / iamscope-benchmark-env07-20260424T222444Z -> runs/env07-20260424T222444Z
- env08_trust_condition_blocked_admin / iamscope-benchmark-env08-20260425T002835Z -> runs/env08-20260425T002835Z
- env09_boundary_removed_validated_admin / iamscope-benchmark-env09-20260425T012013Z -> runs/env09-20260425T012013Z
- env10_trust_condition_removed_validated_admin / iamscope-benchmark-env10-20260425T015458Z -> runs/env10-20260425T015458Z
- env11_broad_trust_condition_blocked_admin / iamscope-benchmark-env11-20260425T020442Z -> runs/env11-20260425T020442Z
- env12_scp_blocked_assumerole / iamscope-benchmark-env12-20260425T032022Z -> runs/env12-20260425T032022Z
- env13_complete_scp_blocked_assumerole / iamscope-benchmark-env13-20260425T035707Z -> runs/env13-20260425T035707Z
- env14_permission_condition_blocked_admin / iamscope-benchmark-env14-24940398230 -> runs/env14-24940398230
- env15_permission_condition_removed_validated_admin / iamscope-benchmark-env15-24940398230 -> runs/env15-24940398230
- env16_identity_deny_removed_validated_group_escalation / iamscope-benchmark-env16-24940398230 -> runs/env16-24940398230
- env17_scp_removed_validated_admin / iamscope-benchmark-env17-24940398230 -> runs/env17-24940398230
- env18_lambda_passrole_validated / iamscope-benchmark-env18-24940398230 -> runs/env18-24940398230
- env19_passedtoservice_scoped_away_nonvalidated / iamscope-benchmark-env19-24940398230 -> runs/env19-24940398230
- env20_ecs_passrole_validated / iamscope-benchmark-env20-24940398230 -> runs/env20-24940398230
- env21_ecs_passedtoservice_scoped_away_nonvalidated / iamscope-benchmark-env21-24940398230 -> runs/env21-24940398230
- env22_cross_account_validated_admin / iamscope-benchmark-env22-20260505T210729Z -> runs/env22-20260505T210729Z
- env23_cross_account_trust_scoped_away_nonvalidated / iamscope-benchmark-env23-20260506T020925Z -> runs/env23-20260506T020925Z
- env24_s3_resource_policy_allow / iamscope-benchmark-env24-20260508T151202Z -> runs/env24-20260508T151202Z
- env25_s3_resource_policy_allow_scoped_away_nonvalidated / iamscope-benchmark-env25-20260508T210637Z -> runs/env25-20260508T210637Z

## Env25 Scenario-Edge Evidence

- `env25_s3_resource_policy_allow_scoped_away_nonvalidated` is included from `iamscope-benchmark-env25-20260508T210637Z`.
- Env25 records one reader IAMUser node, one decoy IAMUser node, and one S3Bucket node for the benchmark path.
- Env25 records one `s3:GetObject_resource_policy` edge from `env25-decoy` to the bucket.
- Env25 records zero `s3:GetObject_resource_policy` edges from `env25-reader` to the bucket.
- Env25 records zero `s3:GetObject_permission` identity edges from `env25-reader` to the bucket.
- Env25 records zero Env25-path `RESOURCE_POLICY_CONDITION` constraints and zero `RESOURCE_POLICY_DENY` constraints.

## Evidence Boundary

- Env24 and Env25 are scenario-edge-level resource-policy Allow benchmarks, not finding-level reachability benchmarks.
- This snapshot does not claim generic resource-policy Deny support.
- This snapshot is bounded live AWS benchmark evidence only; it is not broad IAMScope correctness evidence or production-readiness evidence.

## Artifact Hygiene

This snapshot stores evaluated benchmark artifacts only: `run_manifest.json`, `scorer_result.json`, `gate_result.json`, `report.md`, corpus summary/report files, and snapshot documentation. It intentionally does not store raw AWS archives, Terraform state/cache/provider files, `collect/` directories, `scenario.json`, `findings.json`, `binding_metadata.json`, or `run.log`.
