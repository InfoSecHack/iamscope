# Env17 SCP-Removed Mutation Benchmark Design

## Purpose
Env17 is the positive mutation pair for Env13.

Env13 proves that an otherwise IAM-allowed `env13-alice -> env13-admin` admin path is blocked when a complete live Organizations SCP Deny applies to `sts:AssumeRole`. Env17 should preserve the same target IAM/trust/admin shape, remove the SCP entirely, and prove that IAMScope validates the admin path when no SCP blocker is present.

Expected mutation delta:
- Env13: complete SCP Deny attached to the member account -> `admin_reachability.blocked >= 1`.
- Env17: no SCP created or attached -> `admin_reachability.validated >= 1`.

This benchmark is not a new SCP feature. It is the positive control for Env13's target path.

## Chosen Design
Use the lowest-risk implementation: a single-account IAM fixture collected with the normal benchmark profile.

Env17 does not need AWS Organizations, a management profile, a member profile, an SCP, or a cross-account collection role. Those pieces are required in Env13 only because Env13 mutates Organizations state and must preserve collection access through an SCP carveout. Env17 intentionally has no Organizations mutation, so same-account collection is enough.

Recommended acceptance environment:
- `acceptance/env17_env13_scp_removed/`
- runner: `scripts/run_env17_scp_removed_mutation.sh`
- case manifest: `benchmarks/cases/env17_scp_removed_validated_admin.json`

## IAM Fixture Shape
Create only IAM resources in one account:
- IAM user `env17-alice` under `/iamscope-test/`.
- IAM role `env17-admin` under `/iamscope-test/`.
- `env17-admin` trust policy allows `env17-alice` to call `sts:AssumeRole`.
- Inline policy on `env17-alice` allows `sts:AssumeRole` on `env17-admin`.
- `env17-admin` has `arn:aws:iam::aws:policy/AdministratorAccess`.

The benchmark target path is:
- `env17-alice -> env17-admin`

Do not create:
- any AWS Organizations policy;
- any SCP attachment;
- any collection carveout;
- any management-account collection role.

## Profiles And Collection
Organizations/management profile is not needed.

Recommended run inputs:
- `AWS_PROFILE`, defaulting to the repo's normal single-account benchmark profile if the existing benchmark harness conventions allow it.
- `AWS_REGION`, defaulting to `us-east-1`.
- Optional `IAMSCOPE_BENCHMARK_OUT` and `RUN_ID`, matching the other benchmark runners.

Collection should use same-account IAMScope collection, not cross-account role assumption. This makes live AWS risk lower than Env13 because the run creates and destroys only IAM resources and does not attach policy controls that can lock out collection.

## Expected Scenario Artifacts
Expected `scenario.json`:
- one `sts:AssumeRole_permission` edge for `env17-alice -> env17-admin`;
- one `sts:AssumeRole_trust` edge for `env17-alice -> env17-admin`;
- no Env17-created `SCP` constraint;
- no target-path edge constraint binding to an `SCP`.

If the account has unrelated organization metadata available to the collector, the benchmark should not assert global absence of every SCP in the account. It should assert that the Env17 target path has no SCP blocker or target edge binding. The fixture itself must create no SCP.

Expected `binding_metadata.json`:
- target permission/trust bindings are sufficient to identify the Env17 path;
- no target-path complete SCP blocking binding for `env17-alice -> env17-admin`.

Expected `run.log`:
- source ARN for `env17-alice`;
- target ARN for `env17-admin`;
- scenario validation status;
- benchmark semantic assertion status.

## Expected Findings
Expected `findings.json` for the Env17 target path:
- `admin_reachability.validated >= 1`;
- `admin_reachability.blocked == 0`;
- `admin_reachability.inconclusive == 0`;
- the validated target finding has no `blockers_observed`.

The primary assertion surface is `admin_reachability`. Because the target path is single-hop, `assume_role_chain` should not be treated as the primary truth surface.

## Semantic Assertions
The case manifest should use existing scorer assertion types where possible:
- `scenario_edge_count` for `sts:AssumeRole_permission` from source to target, `gte 1`;
- `scenario_edge_count` for `sts:AssumeRole_trust` from source to target, `gte 1`;
- `finding_count` for `admin_reachability.validated`, `gte 1`;
- `finding_count` for `admin_reachability.blocked`, `eq 0`;
- `finding_count` for `admin_reachability.inconclusive`, `eq 0`;
- `blocker_present` for `kind: scp` on validated target findings, `eq 0`.

The shell runner should also assert the stricter live-harness contract:
- zero `blockers_observed` of any kind on the validated target finding.

Do not add benchmark framework support only to express generic blocker absence unless the build pass finds that shell-level validation is insufficient for review. If minimal support is added later, keep it narrowly tied to counting blockers on already matched findings.

## Materializer And Manifest Needs
Add Env17 consistently with existing optional benchmark archive support:
- `scripts/materialize_phase0_corpus.sh` should accept `--env17-archive`.
- Env17 should map to case ID `env17_scp_removed_validated_admin`.
- Output directory pattern should be `env17-<run_id>`.
- Omitted Env17 should behave like other optional env archives.

The case manifest should state:
- family: `scp_removed_mutation`;
- tier: `tier1_live_aws`;
- ground truth reachable: `true`;
- benchmark proves only the exact Env17 target path validates when the Env13 SCP blocker is absent.

## Setup And Teardown Risks
Live AWS risk is lower than Env13:
- no SCP is created;
- no SCP is attached;
- no Organizations permissions are required;
- no management/member cross-account role preflight is required;
- cleanup is ordinary Terraform destroy of IAM user, role, inline policy, and managed policy attachment.

Remaining risks:
- IAM eventual consistency may delay collection after Terraform apply.
- A pre-existing account-level or organizational control outside the Env17 fixture could affect live results. The run should use a controlled benchmark account where no external SCP blocks `sts:AssumeRole` for this path.
- Name collisions can occur if a previous failed run left `env17-*` IAM resources behind.

The runner should:
- trap Terraform destroy;
- fail hard if `scenario.json` or `findings.json` is missing;
- run `iamscope validate` before semantic assertions;
- print artifact paths and target ARNs for review.

## Why No SCP Is Created
Env17 is designed to isolate the Env13 mutation:
- Env13 creates and attaches the SCP to prove complete SCP blocking.
- Env17 removes that control to prove the same IAM/trust/admin path validates without the SCP.

Creating an allow-list SCP, detaching an inherited SCP, or creating then removing an SCP would add Organizations risk and turn Env17 into another SCP mutation harness. That is unnecessary for the positive control and would make the benchmark harder to run safely.

## What This Proves
If Env17 passes, it directly proves:
- the exact Env17 `alice -> admin` permission edge exists;
- the exact Env17 `alice -> admin` trust edge exists;
- IAMScope emits validated `admin_reachability` for this target path;
- IAMScope does not emit blocked or inconclusive `admin_reachability` for this target path;
- the validated target finding has no blocker evidence in the live harness;
- Env13's target IAM shape can validate when the SCP blocker is absent.

It strongly supports:
- IAMScope responds to the narrow Env13 SCP removal mutation in a controlled live benchmark.

## What This Does Not Prove
Env17 does not prove:
- broader SCP correctness;
- inherited SCP handling;
- OU/root SCP behavior;
- SCP detach/delete safety;
- complex Organizations exception semantics;
- multi-account AssumeRole behavior;
- every possible positive admin reachability shape.

It also does not prove Env13 was blocked only by SCP by itself. The pairwise evidence comes from reviewing Env13 and Env17 together.

## Exact Build Prompt For Next Pass
Build Env17 as the positive mutation pair for Env13. Create `acceptance/env17_env13_scp_removed/` with `main.tf`, `run.sh`, `README.md`, and `expected_findings.json`; create `scripts/run_env17_scp_removed_mutation.sh`; create `docs/specs/env17-mutation-benchmark-harness.md`; create `benchmarks/cases/env17_scp_removed_validated_admin.json`; and add optional `--env17-archive` materializer support if it follows the existing Env14-Env16 pattern. Preserve the Env13 target IAM shape with `env17-alice`, `env17-admin`, clean trust, Alice `sts:AssumeRole` permission, and `AdministratorAccess` on the admin role. Do not create or attach any SCP. Do not require Organizations or a management profile. Expected result: scenario validation PASS, permission edge present, trust edge present, `admin_reachability.validated >= 1`, blocked `0`, inconclusive `0`, and no blockers on the validated target finding. Do not change IAMScope reasoner logic unless the live benchmark exposes a real bug. Do not run live AWS unless explicitly asked.
