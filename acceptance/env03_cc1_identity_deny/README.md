# Env 3: CC-1 Identity-Policy Deny Acceptance

## Overview

This environment acceptance-tests the CC-1 fix for identity-policy `Deny` handling.
The bug: before CC-1, the parser discarded identity-policy `Deny` statements, so an
identity policy containing both `Allow` and explicit `Deny` could still produce a
false-positive `VALIDATED` finding.

The environment deploys the smallest IAM-only scenario for that behavior:

```text
env03-cc1-alice --[iam:AddUserToGroup Allow + Deny]--> env03-cc1-admins
```

`env03-cc1-admins` has `AdministratorAccess`, making it an admin-equivalent target.
AWS IAM evaluation gives explicit `Deny` precedence over `Allow`, so IAMScope should
emit a `BLOCKED` `iam_group_membership_escalation` finding, not `VALIDATED`.

## AWS Resources Created

- IAM user: `env03-cc1-alice`
- Inline IAM user policy: `env03-cc1-allow-deny-add-user-to-group`
- IAM group: `env03-cc1-admins`
- IAM group policy attachment: AWS managed `AdministratorAccess`

No paid AWS services are created.

## Prerequisites

- **Terraform >= 1.5** in PATH
- **jq** in PATH
- **iamscope venv** at `../../.venv` (the script activates it automatically)
- **AWS profiles** configured in `~/.aws/config`:
  - `iamscope-admin` - AdministratorAccess, used for `terraform apply/destroy`
  - `iamscope-test` - ReadOnlyAccess, used for `iamscope collect`

## How to Run

Run from the project root:

```bash
bash acceptance/env03_cc1_identity_deny/run.sh
```

The script runs `terraform init`, deploys the IAM resources, waits for IAM eventual
consistency, runs `iamscope collect`, performs jq assertions against
`/tmp/env03-cc1-output/findings.json`, and destroys the resources on exit.

## Exact jq Assertions

The script asserts these structural properties:

1. Exactly one blocked group-membership escalation finding exists for alice -> admins:

```bash
jq --arg src "$ALICE_ARN" --arg tgt "$ADMINS_ARN"   '[.findings[] | select(
      .pattern_id       == "iam_group_membership_escalation"
      and .source.provider_id == $src
      and .target.provider_id == $tgt
      and .verdict      == "blocked"
  )] | length'   "$FINDINGS_JSON"
```

Expected value: `1`.

2. No false-positive validated finding exists for alice -> admins:

```bash
jq --arg src "$ALICE_ARN" --arg tgt "$ADMINS_ARN"   '[.findings[] | select(
      .pattern_id       == "iam_group_membership_escalation"
      and .source.provider_id == $src
      and .target.provider_id == $tgt
      and .verdict      == "validated"
  )] | length'   "$FINDINGS_JSON"
```

Expected value: `0`.

3. The blocked finding has an `identity_deny` blocker with concrete refs:

```bash
jq --arg src "$ALICE_ARN" --arg tgt "$ADMINS_ARN"   '[.findings[] | select(
      .pattern_id       == "iam_group_membership_escalation"
      and .source.provider_id == $src
      and .target.provider_id == $tgt
      and .verdict      == "blocked"
  ) | .blockers_observed[]? | select(
      .kind == "identity_deny"
      and (.constraint_id | type == "string")
      and (.edge_id | type == "string")
  )] | length'   "$FINDINGS_JSON"
```

Expected value: at least `1`.

4. The identity-deny required check failed:

```bash
jq --arg src "$ALICE_ARN" --arg tgt "$ADMINS_ARN"   '[.findings[] | select(
      .pattern_id       == "iam_group_membership_escalation"
      and .source.provider_id == $src
      and .target.provider_id == $tgt
      and .verdict      == "blocked"
  ) | .required_checks[]? | select(
      .name == "no_identity_deny_blocks_add_user_to_group"
      and .state == "fail"
  )] | length'   "$FINDINGS_JSON"
```

Expected value: `1`.

## What PASS Means

CC-1 is working for this real-AWS case: IAMScope parsed the explicit identity-policy
`Deny`, bound it to the `iam:AddUserToGroup` permission edge, and emitted a blocked
finding with an `identity_deny` blocker instead of a validated finding.

## What FAIL Means

| Assertion | Symptom | Likely cause |
|-----------|---------|--------------|
| 1 - BLOCKED finding missing | Count != 1 | Deny parsing, resolver binding, or reasoner blocker handling regressed; or IAM eventual consistency delayed collection |
| 2 - VALIDATED finding present | Count != 0 | The original CC-1 false positive has regressed |
| 3 - blocker missing | Count < 1 | The finding may be blocked for the wrong reason, or blocker serialization changed |
| 4 - required check not failed | Count != 1 | The reasoner did not attribute the blocked verdict to the identity-policy Deny check |

## Cleanup

`run.sh` registers a shell `trap` that runs:

```bash
terraform destroy -auto-approve
```

The destroy step runs on success, assertion failure, or interrupt.

## Runtime

Approximately **2-4 minutes** end to end:

- `terraform init/apply`: ~30s
- IAM eventual consistency sleep: 30s
- `iamscope collect` single-account standalone scan: ~60-90s
- jq assertions and `terraform destroy`: ~30s
