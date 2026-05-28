# Env13 Complete SCP Blocked Benchmark Design

## Purpose
Env13 is the second SCP benchmark. Env12 proved that resource-scoped SCP Deny evidence is partial in IAMScope today and must demote reachability rather than validate it. Env13 should use an SCP shape that IAMScope can model as complete blocking, so the expected truth state can be `blocked`.

## Feasibility Judgment
Env13 is feasible now if the SCP uses:
- `Effect: "Deny"`
- `Action: "sts:AssumeRole"`
- `Resource: "*"`
- an `ArnNotLike` exception on `aws:PrincipalArn` for the management-side collection caller

This shape is supported by the current SCP parser/binder contract:
- `Action` plus `Resource: "*"` parses as `complete`.
- `ArnNotLike` on `aws:PrincipalArn` is a recognized principal exception and does not downgrade parse status.
- The binder emits `likely_blocking=true` and `governance_confidence=complete` for non-excepted principals.
- The binder emits nonblocking exception evidence for principals matching the collection caller exception.

## Proposed SCP Policy
```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "Env13DenyAssumeRoleExceptCollector",
      "Effect": "Deny",
      "Action": "sts:AssumeRole",
      "Resource": "*",
      "Condition": {
        "ArnNotLike": {
          "aws:PrincipalArn": [
            "<management_collection_caller_principal_arn>",
            "<optional_management_collection_role_arn>",
            "arn:aws:sts::<management_account_id>:assumed-role/<optional_management_collection_role_name>/*"
          ]
        }
      }
    }
  ]
}
```

The exact exception list must be generated from the management profile used for the run. The run harness should print and archive the chosen exception principals in `run.log`.

## Why This Should Be Complete Blocking
The current parser marks this as complete because:
- it uses `Action`, not `NotAction`;
- it uses wildcard `Resource: "*"`;
- the only condition key is `aws:PrincipalArn`;
- the condition operator is `ArnNotLike`, which the parser recognizes as a principal exception extractor.

The current binder should bind the SCP to the benchmark trust edge as complete blocking because:
- the edge action is `sts:AssumeRole`;
- the target resource is covered by `Resource: "*"`;
- `env13-alice` does not match the management collection caller exception;
- no org/account exception is present, so the SCP-1 unresolved-exception downgrade should not apply.

Expected binding metadata for the benchmark path:
- `constraint_type`: `SCP`
- `parse_status`: `complete`
- `governance_confidence`: `complete`
- `likely_blocking`: `true`
- `confidence_q`: complete-blocking value

## Collection Role Access Preservation
The SCP must not block IAMScope collection. Env13 should preserve collection access by excepting the management-side collection caller principal from the Deny with `ArnNotLike aws:PrincipalArn`.

Required harness preflights:
1. Create the member-account IAM fixture, including `env13-iamscope-reader`.
2. Resolve the actual `collection_role_arn` from Terraform output.
3. Resolve the management caller identity with `aws sts get-caller-identity --profile "$MANAGEMENT_PROFILE"`.
4. Generate the SCP exception list from that caller identity and any derived IAM role ARN needed for assumed-role profiles.
5. Before SCP creation, prove management can assume `collection_role_arn`.
6. Attach the SCP.
7. After SCP attachment, prove management can still assume `collection_role_arn`.
8. If either collection preflight fails, detach/delete the SCP and destroy the member fixture; do not run IAMScope collection.

This benchmark should not use `Resource: "*"` without a collection caller exception.

## IAM Path Shape
Use the smallest single-account member fixture:
- `env13-alice` IAM user.
- `env13-admin` IAM role under path `/iamscope-test/`.
- `env13-admin` has `AdministratorAccess`.
- `env13-admin` trust policy allows `env13-alice`.
- `env13-alice` identity policy allows `sts:AssumeRole` on `env13-admin`.
- `env13-iamscope-reader` collection role under path `/iamscope-test/`, trusted by the management-side collection caller.

The benchmark target path is:
- `env13-alice -> env13-admin`

The collection path is:
- management collection caller -> `env13-iamscope-reader`

The SCP should block the benchmark path but not the collection path.

## Expected IAMScope Artifacts
Expected `scenario.json`:
- one `sts:AssumeRole_permission` edge for `env13-alice -> env13-admin`;
- one `sts:AssumeRole_trust` edge for `env13-alice -> env13-admin`;
- at least one top-level `SCP` constraint with `parse_status=complete`;
- at least one `edge_constraints` binding from the Env13 SCP to the `env13-alice -> env13-admin` trust edge.

Expected `binding_metadata.json`:
- `scp_complete_blocking >= 1`;
- Env13 SCP binding for the target trust edge has `likely_blocking=true`;
- no collection failure; `accounts_collected >= 1`.

Expected `findings.json`:
- `admin_reachability.blocked >= 1` for `env13-alice -> env13-admin`;
- `admin_reachability.validated == 0` for `env13-alice -> env13-admin`;
- `admin_reachability.inconclusive == 0` for `env13-alice -> env13-admin`;
- blocker evidence includes `scp`.

Because the path is single-hop, `assume_role_chain` is not the primary assertion surface; that reasoner intentionally requires at least two AssumeRole hops.

## Semantic Assertions
Machine-scored Env13 assertions should include:
- scenario validation passes;
- `scenario_edge_count` permission edge `env13-alice -> env13-admin` `gte 1`;
- `scenario_edge_count` trust edge `env13-alice -> env13-admin` `gte 1`;
- `scenario_constraint_count` `SCP` containing `Env13DenyAssumeRoleExceptCollector` `gte 1`;
- `scenario_edge_constraint_count` trust edge `env13-alice -> env13-admin` bound to `SCP` `gte 1`;
- `finding_count` `admin_reachability.blocked gte 1`;
- `finding_count` `admin_reachability.validated eq 0`;
- `finding_count` `admin_reachability.inconclusive eq 0`;
- `blocker_present` kind `scp` on the target admin reachability finding.

## Risks And Cleanup Notes
- This benchmark mutates AWS Organizations by attaching an SCP to an existing member account; it must require an explicit confirmation variable.
- The SCP must be Env13-specific by name and policy description.
- The harness must trap cleanup and detach/delete the SCP even if collect or scoring fails.
- The post-attach collection-role preflight is mandatory; if collection is blocked, the run is invalid and must fail fast.
- The principal exception depends on AWS `aws:PrincipalArn` semantics for the management caller. If the management profile uses an assumed role, include both the observed caller ARN and the derived IAM role ARN pattern, then prove collection access after SCP attachment before collecting.

## Rejected Alternatives
- Exact target-role `Resource` SCP: rejected because current parser marks non-wildcard resources as partial, which should produce inconclusive, not blocked. Env12 already covers that behavior.
- `Resource: "*"` without carveout: rejected because it can block IAMScope collection-role assumption.
- `NotAction`: rejected because current parser marks it partial.
- `aws:PrincipalOrgID` or `aws:SourceAccount` carveouts: rejected for Env13 because the binder downgrades unresolved org/account exceptions to `needs_review`, preventing complete blocking.
- Unsupported condition keys such as MFA, source IP, or custom request context: rejected because they would make the benchmark inconclusive or test a different control family.
- Exception keyed to the collection role target ARN only: rejected because `aws:PrincipalArn` matches the caller principal, not the target role resource.

## Exact Build Prompt For Next Pass
Build Env13 from this design. Create `acceptance/env13_complete_scp_blocked_admin/`, `scripts/run_env13_complete_scp_blocked_benchmark.sh`, `docs/specs/env13-benchmark-harness.md`, and a machine-scored case manifest if the current scorer can express the assertions. Use management/member profiles like Env12, generate an Env13-specific SCP with `Action: sts:AssumeRole`, `Resource: "*"`, and `ArnNotLike aws:PrincipalArn` exceptions for the management collection caller. Add mandatory pre- and post-SCP collection-role assume preflights. Do not run live AWS unless explicitly asked.
