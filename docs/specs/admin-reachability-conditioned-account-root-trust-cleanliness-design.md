# Admin Reachability Conditioned Account-Root Trust Cleanliness Design

## Purpose

This note defines the next `admin_reachability` calibration candidate before any reasoner behavior changes: whether conditioned account-root trust can count as a clean `sts:AssumeRole` trust witness when it is explicitly narrowed by `aws:PrincipalArn`.

## Real-Pilot Trigger

After PR #74 calibrated AWS-managed `AdministratorAccess` as a clean admin-equivalence witness, replay of the frozen real-pilot dev scenario still left three `admin_reachability` findings inconclusive.

Inspection indicated that the admin witness on `ProdDBAdminRole` appears clean under the PR #74 rule:

- `policy_arn` is exactly `arn:aws:iam::aws:policy/AdministratorAccess`.
- `effect` is `Allow`.
- `resource_pattern` is `*`.
- `has_conditions` is false.
- `raw_conditions` is empty.
- `action_matched_via` is `wildcard_star`.
- the witness source is `ProdDBAdminRole`.

The remaining ambiguity appears to be the `sts:AssumeRole` trust edge into `ProdDBAdminRole`:

- `trust_scope` is `account_root`.
- `principal_type` is `AWS`.
- the trust source is account root.
- `has_conditions` is true.
- `has_external_id` is true.
- `raw_conditions` includes `ArnLike` `aws:PrincipalArn`.
- `aws:PrincipalArn` explicitly lists the source roles or their assumed-role forms, including `TerraformRole`, `ProdDeployRole`, `ProdAppRole`, and `ProdReadOnlyRole`.
- `raw_conditions` also includes `StringEquals` `sts:ExternalId`.

The design question is: can account-root trust with `aws:PrincipalArn` restrictions be treated as a clean `admin_reachability` trust witness when the condition explicitly includes the source role or its exact assumed-role form?

## Current Behavior

IAMScope currently treats the conditioned account-root trust edge conservatively. The trust edge can participate in reachability, but because the trust witness remains condition-ambiguous, the `at_least_one_reachable_chain_uses_clean_witnesses` check remains `UNKNOWN`, and the resulting `admin_reachability` finding remains inconclusive.

## Why the Existing Conservative Behavior Is Understandable

Account-root trust is broad unless conditions narrow it. `ExternalId` can reduce confused-deputy risk, but it does not identify a specific caller by itself. `aws:PrincipalArn` conditions can be precise, but wildcard semantics and condition operators are subtle. Treating all conditioned account-root trust as clean would risk over-validating admin reachability.

## Why It May Be Over-Conservative

The real-pilot shape appears more constrained than generic account-root trust. The trust condition explicitly names the source role or the exact assumed-role form for that role. If IAMScope already knows the source role identity, and the `aws:PrincipalArn` condition can be resolved to that exact role without broad role wildcards or unsupported operators, the trust witness may be clean enough for the narrow `admin_reachability` path.

## Candidate Safe Clean-Trust Rule

A conditioned account-root trust edge may count as clean for `admin_reachability` only when all of the following are true:

- `edge_type` is `sts:AssumeRole_trust`.
- `trust_scope == "account_root"`.
- `principal_type == "AWS"`.
- `is_wildcard_principal` is false.
- `effect == "Allow"`.
- `has_conditions` is true.
- `raw_conditions` contains `aws:PrincipalArn` under `ArnLike` or `ArnEquals`.
- the source role `provider_id` is explicitly included, or the equivalent assumed-role ARN pattern for that exact role is explicitly included.
- `PrincipalArn` entries do not contain broad role wildcards such as `role/*` or broad assumed-role wildcards such as `assumed-role/*`.
- unsupported condition operators are absent.
- `ExternalId` may be present, but is not by itself sufficient.
- no unresolved trust condition binding marks the edge unknown.
- same-account or intra-account trust remains separate from cross-account trust severity.

This rule should be implemented as a narrow clean-witness calibration, not as full AWS trust-condition evaluation.

## Cases That Must Remain Ambiguous

The following cases must remain ambiguous or inconclusive unless separately reviewed and tested:

- account-root trust with no `PrincipalArn` condition.
- account-root trust with only `ExternalId` and no `PrincipalArn` narrowing.
- `PrincipalArn` patterns that broadly allow `role/*`.
- `PrincipalArn` patterns that broadly allow `assumed-role/*`.
- `StringLike` or `ArnLike` patterns that cannot be resolved to the exact source role.
- wildcard principal `*`.
- unknown source role identity.
- unsupported condition operators.
- multiple statements where the matching statement cannot be isolated.
- trust edges with partial parse or missing `raw_conditions`.
- cross-account trust where org membership or caller account is unknown.
- any path with SCP, permission-boundary, or session-policy uncertainty that should still block or keep the finding inconclusive.

## Required Tests Before Implementation

Before changing code, add pipeline-shaped and replay-shaped tests that prove the calibration is narrow:

1. Clean same-account account-root trust with `ArnLike` `aws:PrincipalArn` explicitly listing the source role should allow `admin_reachability` to validate when the admin witness is AWS-managed `AdministratorAccess`.
2. The same shape with an assumed-role pattern for the exact source role should validate.
3. Account-root trust with only `ExternalId` and no `PrincipalArn` should remain inconclusive.
4. Account-root trust with broad `role/*` `PrincipalArn` should remain inconclusive.
5. Account-root trust with broad `assumed-role/*` `PrincipalArn` should remain inconclusive.
6. `ArnLike` for a different role should remain inconclusive.
7. Unsupported condition operators should remain inconclusive.
8. SCP or other blockers should still win.
9. Existing `cross_account_trust` behavior should not change unless explicitly tested.
10. A real-pilot-shaped fixture should show the three `admin_reachability` rows can move from inconclusive to validated only when the exact safe rule is satisfied.

## Expected Real-Pilot Impact

If implemented safely, the three real-pilot `admin_reachability` findings may move from inconclusive to validated because:

- source roles have exact `sts:AssumeRole` permission to `ProdDBAdminRole`;
- `ProdDBAdminRole` trust uses account-root plus `aws:PrincipalArn` restrictions that explicitly include the source roles;
- `ProdDBAdminRole` has AWS-managed `AdministratorAccess` as a clean admin witness after PR #74.

This expected impact is a calibration hypothesis. It should be confirmed only through local replay verification after the rule is implemented and tested.

## Risks / Blast Radius

- Over-trusting condition logic could produce false validated admin reachability.
- `PrincipalArn` wildcard semantics can be subtle.
- Trust matching must not collapse account-root trust into clean trust unless the exact source role is provably narrowed.
- The calibration must not be treated as full AWS trust-condition evaluation.
- The change may alter verdicts for existing local scenarios with conditioned account-root trust, so affected goldens and replay summaries must be reviewed explicitly.

## Non-Claims

This design note does not claim:

- production readiness.
- broad IAMScope correctness.
- full IAM trust policy semantics.
- full AWS authorization semantics.
- exploitability proof.
- downstream authorization proof.
- full SCP, permission-boundary, or session-policy reasoning.
- a composite score.
- a pass/fail benchmark label.

## Exact Next Slice

Recommended next slice: implement conditioned account-root trust clean-witness calibration for admin_reachability with pipeline-shaped tests and real-pilot replay verification.
