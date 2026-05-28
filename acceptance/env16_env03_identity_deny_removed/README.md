# Env16: Env03 Identity Deny Removed

Env16 is the positive mutation pair for Env03.

Env03 gives Alice both Allow and explicit Deny for `iam:AddUserToGroup` on an
AdministratorAccess-backed group. IAM evaluation gives explicit Deny
precedence, so IAMScope should emit a blocked
`iam_group_membership_escalation` finding there.

Env16 keeps the same single-account shape:

- `env16-alice` has an identity-policy Allow for `iam:AddUserToGroup` on
  `env16-admins`
- the matching explicit Deny from Env03 is removed
- `env16-admins` has `AdministratorAccess`

Expected IAMScope behavior:

- scenario validation passes
- Alice has an Allow-derived `iam:AddUserToGroup` path to `env16-admins`
- no explicit identity Deny blocks that target action
- `iam_group_membership_escalation.validated >= 1`
- `iam_group_membership_escalation.blocked == 0`
- `iam_group_membership_escalation.inconclusive == 0`
- the validated finding has no blockers

This benchmark proves only the narrow Env03/Env16 mutation delta. It does not
prove broad identity-policy Deny coverage, malformed policy handling, or
multi-hop group-escalation behavior.

Do not run live AWS unless explicitly requested:

```bash
bash scripts/run_env16_identity_deny_removed_mutation.sh
```
