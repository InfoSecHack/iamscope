# Sanitized Finding Card

This is a sanitized presentation artifact, not raw findings.json.

It is designed for the first minute of a recorded or live no-AWS demo. It uses aliases only and intentionally omits raw account IDs, raw ARNs, raw policy JSON, and local real-pilot artifacts.

## What The Finding Is

This card represents an owner-confirmed broad-trust finding shape from the real-pilot review: a principal outside the target role's normal ownership boundary can reach a deploy-capable role through a broad trust relationship.

Use this as a concrete example of IAMScope's reviewer workflow, not as a raw export.

## Why A Reviewer Should Care

Broad trust relationships are easy to miss in large AWS estates. They may be expected, but they should be explainable, owned, and constrained. IAMScope turns the relationship into a finding with a verdict, checks, evidence references, collection context, and a human review label so the owner can decide whether to keep, narrow, or remove the trust.

## Finding Card

| Field | Sanitized demo value |
| --- | --- |
| Source | `ExternalOrBroadPrincipalAlias` |
| Target | `ProdDeployRoleAlias` |
| Pattern | `cross_account_trust` |
| Verdict | `validated` |
| Reviewer label | `valid_path` |
| Owner confirmed | `true` |
| Collection context | `complete` |
| Demo action | Owner should confirm the business need, narrow the trust if possible, and document the exception if it remains required. |

## Required Checks

| Check | State | Demo explanation |
| --- | --- | --- |
| `trust_principal_is_cross_account_or_broad` | `pass` | The trust shape is broad enough to require owner review. |
| `trust_conditions_are_strong_enough` | `pass` | No unresolved condition prevents IAMScope from making the bounded finding claim. |
| `source_membership_context_available` | `pass` | The collection context is complete for this finding. |
| `no_modeled_scp_blocker_for_trust` | `pass` | IAMScope did not find a modeled SCP blocker for this trust path. |
| `owner_review_label_present` | `pass` | A reviewer classified this representative broad-trust shape as `valid_path`. |

## What IAMScope Says Is Proven

IAMScope's modeled evidence supports this as a reviewable, validated `cross_account_trust` finding under the collected graph and current reasoner rules.

The useful reviewer statement is:

> “This trust relationship is real enough to review. The owner should confirm whether this broad trust is intentional and whether it can be narrowed.”

## What IAMScope Does Not Claim

Validated does not mean exploited.

No finding does not mean safe.

This card does not claim:

- production readiness.
- exploitability proof.
- downstream authorization proof.
- full IAM safety.
- full AWS authorization semantics.
- broad IAMScope correctness.
- that IAMScope replaces Pacu, PMapper, CNAPPs, or human review.

## Owner Action

1. Confirm whether `ProdDeployRoleAlias` should trust `ExternalOrBroadPrincipalAlias`.
2. If the trust is required, document the owner and business reason.
3. If the trust can be narrowed, replace broad trust with specific principals and strong conditions.
4. Re-run IAMScope or replay sanitized artifacts to confirm the finding changes as expected.

## Safe Wording For Demo

> “Here is one sanitized finding card. IAMScope is not saying this was exploited. It is saying the collected evidence supports a validated broad-trust finding that a cloud security reviewer and role owner can act on.”
