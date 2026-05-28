# Env16 Mutation Benchmark Harness

## Purpose

Env16 is the positive mutation pair for Env03's explicit identity-policy Deny
guardrail. Env03 gives Alice both Allow and explicit Deny for
`iam:AddUserToGroup` on an AdministratorAccess-backed group, so IAMScope must
emit a blocked group-membership escalation.

Env16 removes only that explicit Deny. The Alice-to-admins group shape and
admin-equivalent target remain the same.

## Mutation Design

Env03:

- Alice has Allow and explicit Deny for `iam:AddUserToGroup` on the admins
  group
- the admins group has `AdministratorAccess`
- expected result: blocked `iam_group_membership_escalation`

Env16:

- Alice keeps the Allow for `iam:AddUserToGroup` on the admins group
- the explicit Deny is removed
- the admins group keeps `AdministratorAccess`
- expected result: validated `iam_group_membership_escalation`, with zero
  blocked or inconclusive findings for the same path

## Expected Truth

Expected IAMScope behavior:

- scenario validation passes
- Alice has Allow-derived `iam:AddUserToGroup` access to the target admin group
- no explicit identity Deny blocks the target action
- `iam_group_membership_escalation.validated >= 1`
- `iam_group_membership_escalation.blocked == 0`
- `iam_group_membership_escalation.inconclusive == 0`
- the live shell harness rejects validated findings with blockers

## Evidence Boundary

Passing Env16 proves only this narrow Env03/Env16 mutation delta. It does not
prove broad identity-policy Deny handling, malformed policy behavior, wildcard
resource handling, or richer group-escalation shapes.

## Live Command

Do not run live AWS unless explicitly requested.

```bash
bash scripts/run_env16_identity_deny_removed_mutation.sh
```
