# Real Pilot Admin Reachability Calibration 001

## Purpose

Document the first real-pilot `admin_reachability` calibration finding before
changing reasoner behavior. This note records a bounded signal from a
pre-existing dev AWS account collection and frames the next implementation
question. It does not change IAMScope behavior.

## Real Pilot Context

A real pre-existing dev AWS account was collected into a local scratch path under
`/tmp`. Raw artifacts are not committed here.

Sanitized collection summary:

- `id_algorithm`: `sha256_null_separated_v3_case_sensitive_provider_ids`
- nodes: 26
- edges: 63
- constraints: 3
- edge_constraints: 6
- findings: 18
- verdicts: 15 validated, 3 inconclusive
- patterns: 15 `cross_account_trust`, 3 `admin_reachability`
- reasoners run: `admin_reachability`, `assume_role_chain`,
  `cross_account_trust`, `passrole_ecs`, `passrole_lambda`

Initial review signal:

- the first 4 `cross_account_trust` findings were reviewable and meaningful;
- all 3 `admin_reachability` findings were inconclusive for the same reason;
- no raw account IDs, IAM ARNs, raw `scenario.json`, raw `findings.json`, raw
  `binding_metadata.json`, or collection logs are committed in this checkpoint.

## Observed Finding Pattern

All 3 `admin_reachability` findings reached the same sanitized target role label:
`ProdDBAdminRole`.

The recurring shape was:

- source roles had `sts:AssumeRole` permission edges to the target role;
- target trust admitted the source through account-root trust plus
  `PrincipalArn` conditions and `ExternalId`;
- the target role appeared admin-equivalent because it had AWS-managed
  `AdministratorAccess`;
- IAMScope treated the admin witness as wildcard/hyperedge evidence;
- the check `at_least_one_reachable_chain_uses_clean_witnesses` was `UNKNOWN`;
- the resulting `admin_reachability` findings were `inconclusive`.

Calibration question:

Should AWS-managed `AdministratorAccess` be treated as a clean
admin-equivalence witness for `admin_reachability`, rather than making the path
inconclusive solely because the managed policy is represented as
wildcard/hyperedge evidence?

## Why Current Behavior Is Conservative

Current behavior avoids promoting arbitrary wildcard or hyperedge admin evidence
to a clean witness. That is usually a good default because custom wildcard
policies can be partial, conditioned, bounded, blocked, or otherwise ambiguous
once the full IAM context is considered.

For `admin_reachability`, this means a reachable role can remain inconclusive if
the only admin-equivalence witness is represented as wildcard/hyperedge evidence.
That preserves uncertainty instead of overclaiming a clean administrative path.

## Why This May Be Over-Conservative

AWS-managed `AdministratorAccess` is a special case: it is a well-known
AWS-managed policy intended to grant broad administrative permissions. If the
attached policy is exactly the AWS-managed `AdministratorAccess` policy, the
edge-builder representation may still look like wildcard/hyperedge evidence even
though the policy identity is more specific than an arbitrary custom wildcard.

In the real-pilot signal, the repeated uncertainty did not come from three
different ambiguous admin policies. It came from the same question: whether the
AWS-managed `AdministratorAccess` attachment should be treated as a clean
admin-equivalence witness when the rest of the AssumeRole path is clean.

## Candidate Fix

Documented candidate only; do not implement in this checkpoint.

Keep arbitrary wildcard/hyperedge admin witnesses conservative. Treat
AWS-managed `AdministratorAccess` as a clean admin-equivalence witness for
`admin_reachability` only when all of these are true:

- `policy_arn` is exactly `arn:aws:iam::aws:policy/AdministratorAccess`;
- `action_matched_via` is `wildcard_star`;
- `resource_pattern` is `*`;
- effect is `Allow`;
- no conditions are present.

Then `admin_reachability` may validate a clean AssumeRole path to that admin
role if the assume-role permission and trust edges are clean.

Keep custom wildcard policies conservative unless separately reviewed and
covered by focused tests.

## Risks

Potential risks before implementation:

- accidentally treating custom `Action: "*", Resource: "*"` policies as clean;
- treating a customer-managed policy named `AdministratorAccess` as equivalent
  to the AWS-managed policy;
- missing conditions, permissions boundaries, SCPs, session policies, or other
  blockers that should still prevent validation;
- broadening `admin_reachability` beyond one specific AWS-managed policy
  identity;
- destabilizing existing prod-like oracle or golden expectations without an
  explicit migration note.

## Required Tests Before Code Change

Before changing reasoner behavior, add focused local tests for:

- admin role with AWS-managed `AdministratorAccess` is a clean admin witness;
- admin role with custom `Action: "*", Resource: "*"` policy remains ambiguous
  or current behavior unless explicitly reviewed;
- clean AssumeRole path to AWS-managed `AdministratorAccess` target becomes
  `validated`;
- ambiguous AssumeRole path to AWS-managed `AdministratorAccess` target remains
  `inconclusive`;
- permission-boundary and SCP blockers still win;
- existing prod-like oracle and golden tests remain stable, or changes are
  explicitly updated and documented.

## Non-Claims

This checkpoint does not claim:

- production readiness;
- broad IAMScope correctness;
- full IAM correctness;
- exploitability proof;
- downstream authorization proof;
- generic Deny correctness;
- composite benchmark score;
- pass/fail benchmark label.

## Exact Next Slice

Recommended next slice: implement AWS-managed AdministratorAccess clean admin witness handling for admin_reachability with focused local tests.
