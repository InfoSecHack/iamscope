# Env12 SCP-Blocked Benchmark Design

## Purpose

Env12 is the first controlled AWS Organizations/SCP benchmark. It should test one truth-contract claim only:

> IAMScope must not validate an admin-reachability path when IAM identity permissions and role trust allow `sts:AssumeRole`, but an effective SCP blocks `sts:AssumeRole` for the target account.

This is a design-only spec. Do not build Terraform or run live AWS until the account/org assumptions are reviewed.

## AWS Account and Organization Assumptions

Safest first live shape:

- A dedicated AWS Organizations management account already exists.
- A dedicated member account already exists and can be safely targeted by test SCPs.
- The benchmark attaches an SCP directly to the dedicated member account, not to the root or a broad OU.
- The benchmark does not create or delete the Organization.
- The benchmark does not create or close member accounts.
- The member account is reserved for IAMScope testing or has an explicit allowlist tag/process outside IAMScope.

Local `master`/single-account standalone collection is not enough for this case because `iamscope collect --standalone` intentionally skips SCP collection.

## Required AWS Profiles

Use separate profiles to avoid accidental privilege bleed:

- `AWS_PROFILE=iamscope-org-management`
  - Organizations permissions to create/delete an SCP, attach/detach it to the dedicated member account, and list Organizations structure/policies.
  - IAMScope collection should use this profile for non-standalone org discovery.
- `AWS_PROFILE=iamscope-env12-member-admin` or an explicitly configured provider alias
  - IAM permissions in the member account to create/delete Env12 IAM resources.

IAMScope collection also needs a readable member-account path. The least surprising contract is:

- management profile lists the org and SCPs;
- IAMScope assumes the configured collection role in the member account via `--role-name`, or the run script documents the exact alternate profile path if that is not available.

The implemented Env12 harness creates the reader role under `/iamscope-test/` and derives the IAMScope `--role-name` value from Terraform's `collection_role_arn`. This avoids the invalid unqualified ARN shape `arn:aws:iam::<member>:role/env12-iamscope-reader`; IAMScope must assume `arn:aws:iam::<member>:role/iamscope-test/env12-iamscope-reader`.

Before building Env12, run the read-only prerequisite check:

```bash
scripts/check_env12_scp_prereqs.sh \
  --management-profile iamscope-org-management \
  --member-profile iamscope-env12-member-admin \
  --region us-east-1
```

Proceed only if it reports `SAFE_TO_BUILD`. The check verifies profile identity, Organizations visibility, distinct management/member accounts, member-account visibility in the org, SCP policy listing access, member IAM read access, and required local CLIs. It does not create or attach SCPs.

## Terraform Resource Plan

Proposed folder for the build pass:

- `acceptance/env12_scp_blocked_admin/`

Terraform should require explicit variables:

- `management_profile`
- `member_profile`
- `member_account_id`
- `aws_region`
- `confirm_dedicated_member_account`

Resources in the member account:

- IAM user: `env12-alice`
- IAM role: `env12-scp-blocked-admin`
- Role trust policy: allows `env12-alice` to assume the role.
- Role attachment: `arn:aws:iam::aws:policy/AdministratorAccess`
- User inline policy: allows `sts:AssumeRole` on `env12-scp-blocked-admin`.

Resources in the management account:

- Organizations policy: `env12-deny-assume-role`
- Policy type: `SERVICE_CONTROL_POLICY`
- Attachment target: dedicated member account ID only.

Terraform destroy must detach the SCP before deleting it.

## IAM Path Shape

The intended graph path is:

1. `arn:aws:iam::<member>:user/env12-alice`
2. identity permission edge: `sts:AssumeRole_permission`
3. `arn:aws:iam::<member>:role/env12-scp-blocked-admin`
4. trust edge: `sts:AssumeRole_trust`
5. admin-equivalent permission on target role
6. effective SCP constraint attached to the member account blocks `sts:AssumeRole`

The structural IAM path should look allowed. The SCP should be the only intended blocker.

## SCP Policy Shape

Use a target-scoped SCP so IAMScope can still assume the collection role:

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "Env12DenyAssumeEnv12Admin",
      "Effect": "Deny",
      "Action": "sts:AssumeRole",
      "Resource": "arn:aws:iam::<member-account-id>:role/iamscope-test/env12-admin"
    }
  ]
}
```

Why this shape:

- The first live attempt used `Resource: "*"`, which blocked the management account from assuming `env12-iamscope-reader` and prevented collection.
- The target-scoped resource blocks only the Env12 attack target, not the collection role.
- The current SCP parser downgrades non-wildcard SCP resources to `parse_status="partial"`, so Env12 should assert SCP evidence plus no validated admin claim, not require a complete-blocking binding.
- It avoids `NotAction` and exception conditions for the first SCP benchmark.

## Expected IAMScope Artifacts

### Scenario edges

Expected minimum:

- `sts:AssumeRole_permission` from `env12-alice` to `env12-scp-blocked-admin`
- `sts:AssumeRole_trust` from `env12-alice` or an equivalent same-account trust principal representation to `env12-scp-blocked-admin`
- admin-equivalent permission evidence for `env12-scp-blocked-admin`

### Constraints

Expected top-level constraint:

- `constraint_type="SCP"`
- `policy_id` from the live Organizations SCP
- `statement_id="Env12DenyAssumeEnv12Admin"`
- `scope_type="ACCOUNT"` if attached directly to the member account
- `scope_id=<member_account_id>`
- `properties.deny_actions=["sts:AssumeRole"]`
- `properties.resource_patterns=["arn:aws:iam::<member-account-id>:role/iamscope-test/env12-admin"]`
- `properties.parse_status="partial"` under the current parser contract for non-wildcard SCP resources
- `confidence_q` should represent partial SCP confidence under the current binder contract.

### Edge constraints

Expected binding:

- The SCP constraint binds to the relevant `sts:AssumeRole_trust` edge for the target role.
- Binding metadata should include:
  - `likely_blocking=true`
  - `governance_confidence="complete"`
  - a reason equivalent to “SCP denies sts:AssumeRole”

### Findings

Expected target semantics:

- `admin_reachability.validated == 0` for `env12-alice -> env12-scp-blocked-admin`
- `assume_role_chain.validated == 0` if the path is emitted as a chain finding
- At least one blocked finding should exist for the target path if current reasoners see the chain:
  - likely `assume_role_chain.blocked >= 1`
  - possibly `admin_reachability.blocked >= 1` if the current admin path reasoner emits blocker-aware admin findings for this shape

The benchmark should not require an `admin_reachability.blocked` finding unless a dry run shows that this is the current contract. The hard anti-overclaim assertion is no validated admin reachability.

## Semantic Assertions

Initial harness assertions:

- scenario validation passes
- permission edge `env12-alice -> env12-scp-blocked-admin` exists
- trust edge to `env12-scp-blocked-admin` exists
- top-level SCP constraint with `deny_actions` containing `sts:AssumeRole` exists
- edge-constraint binding exists between the target trust edge and the SCP constraint
- binding metadata exists for the target trust edge; complete/likely-blocking is not required because the target-scoped SCP resource is currently parsed as partial
- `admin_reachability.validated == 0`
- `assume_role_chain.validated == 0`
- require `assume_role_chain.blocked >= 1` only after confirming the live path is represented as a chain under current reasoner rules

Extra non-target findings are noise unless they claim validated admin reachability for the Env12 target path.

## Machine-Scoring Requirements

Existing scorer support should be sufficient if the manifest uses:

- `scenario_edge_count`
- `scenario_constraint_count`
- `scenario_edge_constraint_count`
- `finding_count`
- existing false-admin promotion gate behavior

Potential tiny ingest addition for the build pass:

- map case ID `env12_scp_blocked_admin`
- parse `alice_arn`, `target_role_arn`, and `member_account_id` from `run.log`

No mutation-pair or full graph scoring is required for Env12.

## Setup and Teardown Risks

Primary risks:

- SCPs affect an entire target account. A bad attachment target can block real operators.
- Organizations SCP APIs require management-account permissions.
- Detach/delete order matters on cleanup.
- SCP propagation may lag after attachment/detachment.
- IAMScope non-standalone collection must have member-account read access, not just Organizations read access.

Risk controls for the build pass:

- require explicit `member_account_id`
- require explicit confirmation variable such as `confirm_dedicated_member_account=true`
- attach SCP only to the member account, not root or shared OU
- tag/name all resources with `env12`
- destroy must always attempt SCP detach before policy delete
- run from a disposable temp copy like Env03/Env05/Env08 harnesses
- verify the management profile can assume Terraform's exact `collection_role_arn` before any SCP is created or attached

## IAM Eventual Consistency Handling

The harness should wait after:

- member IAM user/role/policy creation
- SCP policy attachment
- SCP policy detach during cleanup

Start with the existing benchmark pattern delay, then extend only if the first live run shows Organizations propagation lag. Do not hide failed collection; preserve run logs and artifacts.

## Cost and Risk Notes

Expected AWS cost is effectively zero for IAM/Organizations resources. Operational risk is not cost; it is account governance impact from an SCP. That is why Env12 should use a dedicated member account and direct account attachment.

## What This Benchmark Proves

If live Env12 passes, it directly proves:

- IAMScope can collect a live Organizations SCP in a controlled account setup.
- IAMScope can emit an SCP scenario constraint.
- IAMScope can bind that SCP to a relevant `sts:AssumeRole` trust edge.
- IAMScope avoids a false validated admin reachability claim when the SCP blocks the path.

## What This Benchmark Does Not Prove

Env12 does not prove:

- all SCP condition forms are handled
- `NotAction` SCPs are fully validated live
- resource-scoped SCPs are fully understood
- OU/root inherited SCP behavior beyond the selected direct member-account attachment
- multi-account cross-account trust correctness
- Organizations setup safety outside a dedicated test org/member account
- production readiness

## Feasibility Judgment

Live SCP benchmarking is feasible only if a dedicated Organizations management/member account pair is available. It is not safe to automate Organization/member-account creation as part of the first pass.

If a dedicated member account is not available, the safer next step is a fixture-backed scenario benchmark using the existing SCP parser/binder contracts, followed by live Env12 once account prerequisites are ready.

## Exact Build Steps for the Next Pass

1. Create `acceptance/env12_scp_blocked_admin/`.
2. Add Terraform with separate management/member provider aliases and explicit member-account confirmation.
3. Add `README.md` documenting required profiles and dedicated-account warning.
4. Add `expected_findings.json` with the semantic assertions above.
5. Add `run.sh` using the temp-copy benchmark pattern and non-standalone IAMScope collection.
6. Add `scripts/run_env12_scp_blocked_benchmark.sh`.
7. Add `benchmarks/cases/env12_scp_blocked_admin.json` if the current scorer can express the final assertions.
8. Add Env12 ingest mapping for `alice_arn`, `target_role_arn`, and `member_account_id`.
9. Add optional materializer support only after a live archive exists.
10. Run `bash -n` and targeted tests only.
11. Do not run live AWS until the dedicated org/member assumptions and profiles are confirmed.
