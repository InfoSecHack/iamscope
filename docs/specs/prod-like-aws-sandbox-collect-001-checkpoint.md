# Prod-Like AWS Sandbox Collect 001 Checkpoint

## Purpose

Document the sanitized result from one controlled prod-like IAM sandbox run
where Terraform created the sandbox, IAMScope collected it into local artifacts,
and Terraform destroyed the sandbox.

This checkpoint records lifecycle, collection, artifact-shape, and cleanup facts
only. It does not claim IAMScope accuracy or oracle comparison.

## Scope

- Prod-like IAM sandbox Terraform source under
  tests/live/aws/prod_like_accuracy_sandbox/terraform/.
- Controlled live run executed from /tmp, not from the repository tree.
- IAM-only sandbox resources created by Terraform.
- IAMScope collection emitted sanitized scenario, binding metadata, and findings
  artifacts.
- Sanitized checkpoint only.

No raw logs, Terraform state, lock files, plan files, output JSON, raw AWS
outputs, raw account IDs, or raw IAM ARNs are committed.

## Preconditions

- Run was performed in an explicitly authorized dedicated IAMScope sandbox
  account.
- Terraform source had account/profile/prefix acknowledgement guards.
- Terraform plan previously showed IAM-only resources.
- Raw run artifacts stayed under /tmp.
- The repository artifact scan after the run was clean.
- The repository working tree was clean after the run.

## Sanitized Observed Result

Terraform lifecycle:

    Apply complete! Resources: 39 added, 0 changed, 0 destroyed.
    Destroy complete! Resources: 39 destroyed.

IAMScope collection:

    collect succeeded
    scenario.json emitted, 153,578 bytes
    binding_metadata.json emitted
    findings.json emitted, 173,733 bytes

Collected artifact summary:

- scenario: 44 nodes, 103 edges, 14 constraints, 26 edge_constraints;
- findings: 20;
- verdicts: 3 validated, 5 blocked, 12 inconclusive;
- patterns: 16 passrole_lambda, 4 passrole_ecs;
- findings_with_prodlike_prefix: 20;
- nodes_with_prodlike_prefix: 18;
- edges_with_prodlike_prefix: 41;
- dangling_nodes: 0.

Sanitized collection summary:

    {
      "terraform_apply_result": "39_added_0_changed_0_destroyed",
      "collect_succeeded": true,
      "scenario_json_bytes": 153578,
      "binding_metadata_json_emitted": true,
      "findings_json_bytes": 173733,
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
      "dangling_nodes": 0,
      "terraform_destroy_result": "39_destroyed"
    }

## Cleanup Verification

Prefix cleanup checks for iamscope-prodlike-v1- returned empty output for IAM
users, IAM roles, and local IAM policies.

The cleanup verification covered:

- no remaining IAM users with the sandbox prefix;
- no remaining IAM roles with the sandbox prefix;
- no remaining local policies with the sandbox prefix.

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
- raw scenario, binding metadata, and findings artifacts.

Post-run repository artifact scan was clean, git status --short was clean after
the run, and repo hygiene was clean.

## Supported Claim

For one controlled prod-like IAM sandbox run, Terraform created 39 IAM-only resources, IAMScope collected the live sandbox into scenario, binding, and findings artifacts, emitted 20 findings over prod-like-prefixed resources, and Terraform destroyed 39 resources with cleanup checks returning no remaining sandbox users, roles, or local policies.

## Non-Claims

- not oracle comparison
- not IAMScope accuracy
- not broad IAMScope correctness
- not production readiness
- not exploitability proof
- not downstream authorization proof
- not Lambda invocation behavior
- not generic Deny correctness
- no composite benchmark score
- no pass/fail benchmark label
