# Env22 Cross-Account Trust Benchmark Design

## Purpose

Env22 starts the cross-account AssumeRole benchmark family. The current corpus proves several same-account AssumeRole, SCP, condition, PassRole, mutation-pair, stability, and degradation contracts. It does not yet prove that IAMScope can truthfully reason about a caller in one AWS account reaching an admin-equivalent role in another account.

This family should prove the narrow cross-account path shape first:

```text
caller account user -> sts:AssumeRole permission -> target account admin role
caller account user -> target role trust principal -> target account admin role
```

The first implementation should stay IAM-only. It should not create SCPs, resource policies, Lambda functions, ECS clusters, access keys, or production identities.

## Account And Profile Prerequisites

Use two existing dedicated non-production AWS accounts in the same AWS Organization:

- Caller account: hosts the benchmark caller principal.
- Target account: hosts the benchmark admin-equivalent role.

Required profiles:

- `MANAGEMENT_PROFILE`: Organizations management account profile used only for IAMScope collection.
- `CALLER_PROFILE`: admin-capable setup profile for the caller test account.
- `TARGET_PROFILE`: admin-capable setup profile for the target test account.
- `AWS_REGION`: benchmark region, expected to default to `us-east-1`.

Required account IDs:

- `CALLER_ACCOUNT_ID`
- `TARGET_ACCOUNT_ID`
- `MANAGEMENT_ACCOUNT_ID`, derived from `MANAGEMENT_PROFILE` during preflight.

Preflight must stop before Terraform if:

- either account ID is missing or not 12 digits;
- caller and target account IDs are equal;
- either setup profile resolves to the wrong account ID;
- `MANAGEMENT_PROFILE` cannot list or describe both accounts through Organizations;
- either account is not active in the Organization;
- management cannot assume the collection role in both accounts after Terraform creates it.

Before any build pass, run the read-only prerequisite script documented in
`docs/specs/env22-cross-account-prereq-check.md`:

```bash
bash scripts/check_env22_cross_account_prereqs.sh \
  --management-profile "$MANAGEMENT_PROFILE" \
  --caller-profile "$CALLER_PROFILE" \
  --target-profile "$TARGET_PROFILE" \
  --caller-account-id "$CALLER_ACCOUNT_ID" \
  --target-account-id "$TARGET_ACCOUNT_ID" \
  --region "$AWS_REGION"
```

The build should proceed only if the script prints `SAFE_TO_BUILD`.

This design intentionally uses the existing management-profile collection flow. IAMScope does not currently have a single command that merges two independent standalone profile collections into one scenario, so direct two-profile collection should be rejected for Env22/Env23 unless a separate collection-design slice adds that capability.

## Fixture Shape

### Env22 Validated Cross-Account Admin Path

Caller account resources:

- IAM user: `env22-alice`
- Inline identity policy: allows `sts:AssumeRole` on the target role ARN only
- Collection role: `env22-iamscope-reader`, trusted by the management account collection caller

Target account resources:

- IAM role: `env22-admin`
- Trust policy: allows exact principal `arn:aws:iam::<CALLER_ACCOUNT_ID>:user/env22-alice`
- Permission attachment: AWS managed `AdministratorAccess`
- Collection role: `env22-iamscope-reader`, trusted by the management account collection caller

The trust policy should be intentionally simple and unconditioned:

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Principal": {
        "AWS": "arn:aws:iam::<CALLER_ACCOUNT_ID>:user/env22-alice"
      },
      "Action": "sts:AssumeRole"
    }
  ]
}
```

The identity permission should be resource-scoped to the target role:

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": "sts:AssumeRole",
      "Resource": "arn:aws:iam::<TARGET_ACCOUNT_ID>:role/env22-admin"
    }
  ]
}
```

No access key should be created for `env22-alice`. The benchmark proves graph truth from collected IAM policy state, not live credential exploitation.

## Collection Plan

Collection should run once from `MANAGEMENT_PROFILE` across exactly the caller and target accounts:

```bash
iamscope collect \
  --profile "$MANAGEMENT_PROFILE" \
  --region "$AWS_REGION" \
  --accounts "$CALLER_ACCOUNT_ID,$TARGET_ACCOUNT_ID" \
  --role-name "$COLLECTION_ROLE_NAME" \
  --output "$OUTPUT_DIR/scenario.json"
```

The initial build may use `COLLECTION_ROLE_NAME=env22-iamscope-reader` or a shared benchmark collection role if the repo already standardizes one. The runner must print the resolved account IDs and collection role ARNs to `run.log`.

## Expected Collected Nodes And Edges

Env22 expected `scenario.json` evidence:

- Node for `arn:aws:iam::<CALLER_ACCOUNT_ID>:user/env22-alice`
- Node for `arn:aws:iam::<TARGET_ACCOUNT_ID>:role/env22-admin`
- `sts:AssumeRole_permission` edge from Alice to `env22-admin`
- `sts:AssumeRole_trust` edge from Alice to `env22-admin`
- Trust edge feature `cross_account=true`
- Trust edge has a risky naked-trust classification consistent with exact cross-account principal trust and no strong condition
- Admin-equivalent witness edges for `env22-admin` from `AdministratorAccess`
- No SCP blocker binding on the target trust edge
- No permission-boundary blocker on the target permission edge

Expected `findings.json` evidence:

- `admin_reachability.validated >= 1` for Alice -> `env22-admin`
- `admin_reachability.blocked == 0` for Alice -> `env22-admin`
- `admin_reachability.inconclusive == 0` for Alice -> `env22-admin`
- `cross_account_trust.validated >= 1` for Alice -> `env22-admin`
- validated target findings have no blockers

Because both accounts are expected to be in the same Organization, `cross_account_trust` may downgrade severity through its same-org side channel. The benchmark should assert verdict and edge truth, not a fixed severity.

## Env22 Semantic Assertions

Machine-scored assertions should include:

- scenario validation passes;
- scenario contains the Alice -> admin `sts:AssumeRole_permission` edge;
- scenario contains the Alice -> admin `sts:AssumeRole_trust` edge;
- the trust edge has `cross_account=true`;
- the trust edge carries no MFA, OrgID, ExternalId, SourceAccount, SourceIp, or SourceVpc condition evidence;
- `admin_reachability.validated >= 1` for Alice -> admin;
- `admin_reachability.blocked == 0` for Alice -> admin;
- `admin_reachability.inconclusive == 0` for Alice -> admin;
- `cross_account_trust.validated >= 1` for Alice -> admin;
- no blocker is present on the validated target path.

If the current scorer cannot express `cross_account=true` or condition-feature absence directly, the first build should add only the smallest structural predicate needed, mirroring the existing feature and condition predicates. It must not become a general graph engine.

## Env23 Negative Mutation Proposal

Env23 should be the non-validated mutation pair for Env22.

Recommended mutation: principal scoped away.

Caller account resources:

- IAM user: `env23-alice`
- IAM user: `env23-decoy`
- Alice identity policy still allows `sts:AssumeRole` on `env23-admin`
- Decoy has no `sts:AssumeRole` identity permission for `env23-admin`
- Collection role: `env23-iamscope-reader`

Target account resources:

- IAM role: `env23-admin`
- Trust policy allows exact principal `arn:aws:iam::<CALLER_ACCOUNT_ID>:user/env23-decoy`
- `env23-admin` has `AdministratorAccess`
- Collection role: `env23-iamscope-reader`

Expected Env23 truth:

- Alice has the caller-side permission edge.
- The target admin role exists and is admin-equivalent.
- A cross-account trust edge exists for decoy -> admin.
- No trust edge exists for Alice -> admin.
- `admin_reachability.validated == 0` for Alice -> admin.
- A false validated Alice -> admin finding blocks promotion as `false_admin_claim`.

Env23 may still produce a `cross_account_trust.validated` finding for decoy -> admin. That is acceptable and should not fail the case, because the target mutation is about whether IAMScope matches the correct caller on the AssumeRole path. The benchmark must not claim Env23 blocks or invalidates every cross-account trust in the fixture.

Rejected Env23 alternatives for the first pair:

- Missing caller identity permission: useful later, but DEG02 already covers the missing-permission degradation shape synthetically, and it does not stress trust-principal matching as directly.
- ExternalId condition: valuable later, but it introduces runtime context ambiguity and current cross-account trust severity/classification nuances that could obscure the first pair.
- Trust MFA or OrgID condition: valuable later, but this would overlap with the existing trust-condition family before the basic cross-account principal match is proven.
- SCP mutation: out of scope; this design must not create SCPs.

## Materializer And Case Manifest Needs

Expected benchmark artifacts:

- `acceptance/env22_cross_account_trust_validated/`
- `acceptance/env23_env22_principal_scoped_away/`
- `scripts/run_env22_cross_account_trust_benchmark.sh`
- `scripts/run_env23_cross_account_principal_scoped_away_benchmark.sh`
- `benchmarks/cases/env22_cross_account_trust_validated.json`
- `benchmarks/cases/env23_cross_account_principal_scoped_away_nonvalidated.json`
- `docs/specs/env22-benchmark-harness.md`
- `docs/specs/env23-mutation-benchmark-harness.md`

Materializer support should be added only after live runs pass:

- `--env22-archive` -> `env22_cross_account_trust_validated`
- `--env23-archive` -> `env23_cross_account_principal_scoped_away_nonvalidated`
- output directory patterns `env22-<run_id>` and `env23-<run_id>`

Do not freeze new corpus snapshots until live evidence exists.

## Live AWS Safety Notes

Env22/Env23 should have lower live AWS risk than SCP benchmarks because they do not mutate Organizations policy. The remaining risks are IAM fixture and collection-role risks:

- The setup profiles can create IAM users, roles, inline policies, and managed policy attachments in dedicated test accounts.
- No access keys are created.
- No production identities are referenced.
- No SCPs, permission boundaries, resource policies, Lambda functions, ECS resources, or network resources are created.
- Target admin roles are under a benchmark path or unique name prefix and are destroyed during cleanup.
- Collection roles are scoped to IAMScope read-only collection needs where possible.
- The runner must refuse to run unless caller and target account IDs match the profiles and are explicitly provided.

## Cleanup Notes

Terraform should own all Env22/Env23 IAM resources in both accounts and should destroy them on exit:

- caller user;
- decoy user for Env23;
- caller identity policies;
- target admin role;
- target admin policy attachment;
- collection roles in both accounts, unless the benchmark intentionally reuses a pre-existing shared benchmark collection role.

Cleanup should not delete or alter accounts, OUs, SCPs, production roles, or shared non-benchmark collection roles.

If cleanup fails, the runner should print exact resource names and account IDs for manual cleanup.

## What This Proves

If Env22 passes, it proves:

- IAMScope can collect both sides of one same-org cross-account IAM fixture in a single scenario.
- IAMScope can emit the exact cross-account `sts:AssumeRole_permission` and `sts:AssumeRole_trust` edges.
- IAMScope can validate admin reachability across that exact cross-account Alice -> admin path.
- IAMScope can emit a validated `cross_account_trust` finding for the exact target trust edge.

If Env23 passes, it proves:

- IAMScope does not treat a cross-account trust for a different caller as proof that Alice can assume the target role.
- IAMScope does not emit validated admin reachability for the Alice -> admin path when the matching trust edge is absent.

## What This Does Not Prove

This family does not prove:

- arbitrary cross-account trust correctness;
- external-account behavior outside the Organization;
- account-root wildcard trust behavior;
- ExternalId, MFA, OrgID, SourceIp, SourceVpc, or other condition handling;
- SCP interactions with cross-account trust;
- resource-policy Allow behavior;
- long multi-hop cross-account chains;
- live credential exploitability;
- production readiness.

## Exact Build Prompt For Next Pass

Work from current `origin/main` in a fresh branch.

Mission: build Env22, the validated cross-account AssumeRole trust benchmark, from `docs/specs/env22-cross-account-trust-benchmark-design.md`.

Goal: create the smallest IAM-only live AWS benchmark proving IAMScope can validate a same-organization cross-account Alice -> admin AssumeRole path when caller-side permission, target trust, and admin-equivalent target role evidence all align.

Guardrails:

- Do not create or attach SCPs.
- Do not create access keys.
- Do not use production identities.
- Do not run live AWS unless explicitly asked.
- Do not change IAMScope reasoner logic unless the benchmark exposes a real bug.
- Do not add raw artifacts or freeze a corpus snapshot.

Required first build files:

- `acceptance/env22_cross_account_trust_validated/main.tf`
- `acceptance/env22_cross_account_trust_validated/run.sh`
- `acceptance/env22_cross_account_trust_validated/README.md`
- `acceptance/env22_cross_account_trust_validated/expected_findings.json`
- `scripts/run_env22_cross_account_trust_benchmark.sh`
- `docs/specs/env22-benchmark-harness.md`
- `benchmarks/cases/env22_cross_account_trust_validated.json`
- materializer support only if small and consistent, but do not freeze until live Env22 evidence exists

Preflight:

- Require `MANAGEMENT_PROFILE`, `CALLER_PROFILE`, `TARGET_PROFILE`, `CALLER_ACCOUNT_ID`, `TARGET_ACCOUNT_ID`, and `AWS_REGION`.
- Run `bash scripts/check_env22_cross_account_prereqs.sh` and require `SAFE_TO_BUILD`.
- Prove caller/target profiles resolve to the declared account IDs.
- Prove accounts differ.
- Prove management can see both accounts and assume the benchmark collection role in both accounts after Terraform apply.

Expected Env22 semantics:

- scenario validation PASS;
- `sts:AssumeRole_permission` edge Alice -> target admin exists;
- `sts:AssumeRole_trust` edge Alice -> target admin exists;
- trust edge is cross-account and unconditioned;
- target role is admin-equivalent;
- `admin_reachability.validated >= 1` for Alice -> admin;
- `admin_reachability.blocked == 0`;
- `admin_reachability.inconclusive == 0`;
- `cross_account_trust.validated >= 1` for Alice -> admin;
- validated target findings have no blockers.

Validation:

- `bash -n` new shell scripts.
- Targeted benchmark tests if case manifest or scorer predicates change.
- `./scripts/check.sh`.
- `./scripts/test_fast.sh`.
