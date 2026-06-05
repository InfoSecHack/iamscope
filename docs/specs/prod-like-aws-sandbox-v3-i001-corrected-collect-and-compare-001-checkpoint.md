# Prod-Like AWS Sandbox v3 I001 Corrected Collect and Compare 001 Checkpoint

## Purpose

Document the sanitized result from one controlled prod-like IAM sandbox run
completed under v3/current main after the `oracle-i-001` fixture correction.

This checkpoint records lifecycle, collection, v3 ID metadata, local comparator
summary, artifact hygiene, and cleanup facts only. It does not claim broad
IAMScope correctness, production readiness, or full oracle success.

## Scope

- Prod-like IAM sandbox Terraform source under
  tests/live/aws/prod_like_accuracy_sandbox/terraform/.
- Corrected `oracle-i-001` fixture shape with split uncertainty source
  principal.
- Controlled live run executed from /tmp, not from the repository tree.
- IAM-only sandbox resources created by Terraform.
- IAMScope collection used current repository code.
- Sanitized scenario, binding metadata, findings, and comparator summaries.
- Sanitized checkpoint only.

No raw logs, Terraform state, lock files, plan files, output JSON, live
findings JSON, raw AWS outputs, raw account IDs, or raw IAM ARNs are committed.

## Preconditions

- Run was performed in an explicitly authorized dedicated IAMScope sandbox
  account.
- Terraform source had account/profile/prefix acknowledgement guards.
- Terraform plan previously showed IAM-only resources.
- Raw run artifacts stayed under /tmp.
- The `oracle-i-001` local fixture correction had split the wildcard
  resource-scope uncertainty source from the boundary/session uncertainty
  source.
- The repository artifact scan after the run was clean.
- The repository working tree was clean after the run.
- This is the new best current evidence point for the corrected prod-like
  sandbox comparison.

## Sanitized Observed Result

Terraform lifecycle:

    Apply complete! Resources: 41 added, 0 changed, 0 destroyed.
    Destroy complete! Resources: 41 destroyed.

IAMScope collection:

    collect succeeded
    id_algorithm: sha256_null_separated_v3_case_sensitive_provider_ids
    scenario.json emitted
    binding_metadata.json emitted
    findings.json emitted

Collected artifact summary:

- scenario: 45 nodes, 103 edges, 14 constraints, 24 edge_constraints;
- findings: 20;
- verdicts: 3 validated, 2 blocked, 15 inconclusive;
- patterns: 16 passrole_lambda, 4 passrole_ecs;
- findings_with_prodlike_prefix: 20;
- nodes_with_prodlike_prefix: 19;
- edges_with_prodlike_prefix: 41.

Sanitized collection summary:

```json
{
  "terraform_apply_result": "41_added_0_changed_0_destroyed",
  "collect_succeeded": true,
  "id_algorithm": "sha256_null_separated_v3_case_sensitive_provider_ids",
  "scenario_json_emitted": true,
  "binding_metadata_json_emitted": true,
  "findings_json_emitted": true,
  "scenario": {
    "nodes": 45,
    "edges": 103,
    "constraints": 14,
    "edge_constraints": 24
  },
  "findings": {
    "total": 20,
    "verdicts": {
      "validated": 3,
      "blocked": 2,
      "inconclusive": 15
    },
    "patterns": {
      "passrole_lambda": 16,
      "passrole_ecs": 4
    }
  },
  "prodlike_prefix_counts": {
    "findings_with_prodlike_prefix": 20,
    "nodes_with_prodlike_prefix": 19,
    "edges_with_prodlike_prefix": 41
  },
  "terraform_destroy_result": "41_destroyed"
}
```

## Comparator Result

The corrected local comparator separated currently comparable oracle rows from
unsupported, not-currently-live-comparable, environmental, and unmapped rows.

Comparator summary:

- oracle row count: 24;
- emitted finding count: 20;
- sandbox-source finding count: 8;
- environmental extra finding count: 12;
- unmapped sandbox extra finding count: 2;
- oracle_match: 6;
- oracle_mismatch: 0;
- environmental_extra: 12;
- unmapped_sandbox_extra: 2;
- not_currently_live_comparable: 14;
- unsupported_static_only: 4;
- verdict counts: 3 validated, 2 blocked, 15 inconclusive;
- pattern counts: 16 passrole_lambda, 4 passrole_ecs.

Sanitized comparator summary:

```json
{
  "oracle_row_count": 24,
  "emitted_finding_count": 20,
  "sandbox_source_finding_count": 8,
  "environmental_extra_finding_count": 12,
  "unmapped_sandbox_extra_finding_count": 2,
  "oracle_match": 6,
  "oracle_mismatch": 0,
  "environmental_extra": 12,
  "unmapped_sandbox_extra": 2,
  "not_currently_live_comparable": 14,
  "unsupported_static_only": 4,
  "verdict_counts": {
    "validated": 3,
    "blocked": 2,
    "inconclusive": 15
  },
  "pattern_counts": {
    "passrole_lambda": 16,
    "passrole_ecs": 4
  }
}
```

## Corrected Oracle I001 Result

`oracle-i-001` matched as inconclusive after the fixture correction:

```text
iamscope-prodlike-v1-uncertainty-resource-probe -> iamscope-prodlike-v1-lambda-exec-scoped
```

The fixture correction moved `oracle-i-001` from mismatch to match without
changing the oracle expectation. The row remains an inconclusive wildcard
resource-scope uncertainty case.

## Comparator Interpretation

This checkpoint is the new best current evidence point. The prior pre-correction
v3 run remains historical evidence, but it should not be used as the current
comparison result for `oracle-i-001`.

The two remaining unmapped sandbox extras are inconclusive wildcard-resource
paths from `uncertainty-resource-probe` to other sandbox targets.

Environmental extras remain messy-account signals from non-sandbox source
principals to sandbox target roles. Unsupported/static-only rows remain
excluded from false-positive and false-negative treatment. Not-currently-live-
comparable rows remain not counted as failures.

## Cleanup Verification

Prefix cleanup checks for prod-like sandbox IAM users, IAM roles, and local
policies returned empty output.

The cleanup verification covered:

- no remaining prod-like IAM users;
- no remaining prod-like IAM roles;
- no remaining prod-like local policies.

The observed Terraform destroy summary was:

    Destroy complete. Resources: 41 destroyed.

## Artifact Hygiene

Raw artifacts remained under /tmp and were not committed:

- raw apply logs;
- raw collect logs;
- raw destroy logs;
- Terraform state;
- Terraform lock file;
- Terraform plan file;
- Terraform output JSON;
- raw AWS outputs;
- raw scenario JSON;
- raw binding metadata JSON;
- raw findings JSON;
- raw comparator output.

Post-run repository artifact scan was clean, git status --short was clean after
the run, and repo hygiene was clean.

## Supported Claim

For one controlled prod-like IAM sandbox run under v3/current main after the
oracle-i-001 fixture correction, Terraform created 41 IAM-only resources,
IAMScope collected the live sandbox with v3 deterministic IDs, emitted
scenario/binding/findings artifacts and 20 findings involving sandbox-prefixed
targets, the local comparator matched 6 currently comparable oracle rows with 0
oracle mismatches while separating 12 environmental extras, 2 unmapped sandbox
extras, 14 not-currently-live-comparable rows, and 4 unsupported static-only
rows, and Terraform destroyed 41 resources with cleanup checks returning no
remaining sandbox users, roles, or local policies.

## Non-Claims

- not broad IAMScope correctness
- not production readiness
- not full oracle success
- not production AWS
- not exploitability proof
- not downstream authorization proof
- not Lambda invocation behavior
- not generic Deny correctness
- not v2/v3 cross-version ID compatibility
- no composite benchmark score
- no pass/fail benchmark label
