# Prod-Like AWS Sandbox v3 Collect and Compare 001 Checkpoint

## Purpose

Document the sanitized result from one controlled prod-like IAM sandbox run
completed under current main after the v3 deterministic ID migration.

This checkpoint records lifecycle, collection, v3 ID metadata, local comparator
summary, artifact hygiene, and cleanup facts only. It does not claim broad
IAMScope correctness, production readiness, or full oracle success.

## Scope

- Prod-like IAM sandbox Terraform source under
  tests/live/aws/prod_like_accuracy_sandbox/terraform/.
- Controlled live run executed from /tmp, not from the repository tree.
- IAM-only sandbox resources created by Terraform.
- IAMScope collection used current repository code via PYTHONPATH.
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
- The repository artifact scan after the run was clean.
- The repository working tree was clean after the run.
- The old pre-v3 /tmp collection is stale and is not used for current claims.

## Sanitized Observed Result

Terraform lifecycle:

    Apply complete! Resources: 39 added, 0 changed, 0 destroyed.
    Destroy complete! Resources: 39 destroyed.

IAMScope collection:

    collect succeeded
    id_algorithm: sha256_null_separated_v3_case_sensitive_provider_ids
    scenario.json emitted
    binding_metadata.json emitted
    findings.json emitted

Collected artifact summary:

- scenario: 44 nodes, 103 edges, 14 constraints, 26 edge_constraints;
- findings: 20;
- verdicts: 3 validated, 5 blocked, 12 inconclusive;
- patterns: 16 passrole_lambda, 4 passrole_ecs;
- findings_with_prodlike_prefix: 20;
- nodes_with_prodlike_prefix: 18;
- edges_with_prodlike_prefix: 41.

Sanitized collection summary:

```json
{
  "terraform_apply_result": "39_added_0_changed_0_destroyed",
  "collect_succeeded": true,
  "id_algorithm": "sha256_null_separated_v3_case_sensitive_provider_ids",
  "scenario_json_emitted": true,
  "binding_metadata_json_emitted": true,
  "findings_json_emitted": true,
  "scenario": {
    "nodes": 44,
    "edges": 103,
    "constraints": 14,
    "edge_constraints": 26
  },
  "findings": {
    "total": 20,
    "verdicts": {
      "validated": 3,
      "blocked": 5,
      "inconclusive": 12
    },
    "patterns": {
      "passrole_lambda": 16,
      "passrole_ecs": 4
    }
  },
  "prodlike_prefix_counts": {
    "findings_with_prodlike_prefix": 20,
    "nodes_with_prodlike_prefix": 18,
    "edges_with_prodlike_prefix": 41
  },
  "terraform_destroy_result": "39_destroyed"
}
```

## Comparator Result

The local comparator separated currently comparable oracle rows from
unsupported, not-currently-live-comparable, environmental, and unmapped rows.

Comparator summary:

- oracle row count: 24;
- emitted finding count: 20;
- sandbox-source finding count: 8;
- environmental extra finding count: 12;
- unmapped sandbox extra finding count: 2;
- oracle_match: 5;
- oracle_mismatch: 1;
- environmental_extra: 12;
- unmapped_sandbox_extra: 2;
- not_currently_live_comparable: 14;
- unsupported_static_only: 4;
- verdict counts: 3 validated, 5 blocked, 12 inconclusive;
- pattern counts: 16 passrole_lambda, 4 passrole_ecs.

Sanitized comparator summary:

```json
{
  "oracle_row_count": 24,
  "emitted_finding_count": 20,
  "sandbox_source_finding_count": 8,
  "environmental_extra_finding_count": 12,
  "unmapped_sandbox_extra_finding_count": 2,
  "oracle_match": 5,
  "oracle_mismatch": 1,
  "environmental_extra": 12,
  "unmapped_sandbox_extra": 2,
  "not_currently_live_comparable": 14,
  "unsupported_static_only": 4,
  "verdict_counts": {
    "validated": 3,
    "blocked": 5,
    "inconclusive": 12
  },
  "pattern_counts": {
    "passrole_lambda": 16,
    "passrole_ecs": 4
  }
}
```

## Comparator Interpretation

This checkpoint records current v3/current-main evidence. The old pre-v3 /tmp
collection is stale and must not be used for current claims.

The single comparator mismatch is oracle-i-001: expected inconclusive, emitted
blocked. Follow-up triage in
docs/specs/prod-like-oracle-i001-mismatch-triage.md records the decision:
`fixture_should_change_to_make_row_truly_inconclusive`. Complete-confidence
boundary evidence reflects a fixture/oracle expectation conflict, not
automatically an IAMScope false positive.

Environmental extras are messy-account findings from non-sandbox source
principals to sandbox target roles. Unsupported rows are static-only and must
not count as false positives or false negatives.

## Cleanup Verification

Prefix cleanup checks for prod-like sandbox users, roles, and local policies
returned empty output.

The cleanup verification covered:

- no remaining prod-like IAM users;
- no remaining prod-like IAM roles;
- no remaining prod-like local policies.

The observed Terraform destroy summary was:

    Destroy complete. Resources: 39 destroyed.

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

For one controlled prod-like IAM sandbox run under v3/current main, Terraform
created 39 IAM-only resources, IAMScope collected the live sandbox with v3
deterministic IDs, emitted scenario/binding/findings artifacts and 20 findings
involving sandbox-prefixed targets, the local comparator matched 5 currently
comparable oracle rows while separating 12 environmental extras, 2 unmapped
sandbox extras, 14 not-currently-live-comparable rows, and 4 unsupported
static-only rows, and Terraform destroyed 39 resources with cleanup checks
returning no remaining sandbox users, roles, or local policies.

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
