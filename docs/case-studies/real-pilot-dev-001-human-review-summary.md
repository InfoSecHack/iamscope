# Real Pilot Dev-001 Human Review Summary

## Purpose

This note records a bounded, sanitized human-review summary for the first real pre-existing dev-account IAMScope pilot. It is intended to show whether IAMScope findings were reviewable and useful to a human reviewer without publishing raw AWS artifacts or turning the review into a fake score.

## Input Artifacts, Sanitized/Local Only

The source collection and reviewer outputs remained local under `/tmp`:

- Collection input directory: `/tmp/iamscope-real-pilot-dev-001`
- Sanitized reviewer classification output directory: `/tmp/iamscope-real-pilot-dev-001-review-all18`

Raw `scenario.json`, `findings.json`, reviewer-label JSON, logs, account IDs, IAM/STS ARNs, and generated review artifacts are intentionally not committed. The counts and observations below are sanitized summaries only.

## Collection Summary

- Scenario graph: 26 nodes, 63 edges, 3 constraints, 6 edge constraints.
- Findings emitted: 18.
- IAMScope verdicts: 15 `validated`, 3 `inconclusive`.
- Pattern mix: 15 `cross_account_trust`, 3 `admin_reachability`.
- Severity mix: 5 `critical`, 10 `high`, 3 `medium`.
- The original findings predated PR #66, so they did not include per-finding `collection_context`; replayed current-main findings now include complete `collection_context`.

## Finding Summary

The pilot produced a small, reviewable set of findings dominated by cross-account trust observations, plus three admin-reachability findings that stayed inconclusive because the clean-admin-witness check could not be strengthened from the available representation.

The 18 findings were not treated as a score, benchmark pass/fail result, or owner-confirmed truth set. They were reviewed as evidence-bearing rows that a human could classify into useful review categories.

## Human-Review Classification Summary

- Reviewer labels: 18 labeled, 0 unlabeled.
- `valid_path`: 11.
- `expected_benign`: 3.
- `inconclusive_needs_context`: 3.
- `needs_more_evidence`: 1.

Except where explicitly noted in the owner-confirmation addendum, these labels are preliminary and not owner-confirmed. They represent a first-pass reviewer classification of sanitized finding rows, not a final authorization or risk determination.

## Current-Main Replay Addendum

The frozen real-pilot scenario was replayed on current main after the `collection_context` and trust-safety fixes. The replay preserved the same result shape: 18 findings, 15 `validated`, and 3 `inconclusive`.

The same human-review labels still applied to all 18 findings:

- 18 labeled, 0 unlabeled.
- `valid_path`: 11.
- `expected_benign`: 3.
- `inconclusive_needs_context`: 3.
- `needs_more_evidence`: 1.

The scenario counts were unchanged: 26 nodes, 63 edges, 3 constraints, and 6 edge constraints. The replayed findings now include complete per-finding `collection_context`:

- `graph_collection_complete`: true.
- `has_collection_failures`: false.
- `has_policy_parse_failures`: false.
- `related_collection_failures`: empty.
- `related_policy_parse_failures`: empty.

The sanitized review outputs had no raw 12-digit account IDs and no raw IAM/STS ARNs. Raw replay findings are local-only and may contain raw ARNs or account IDs, so no raw replay artifacts are committed. This strengthens evidence hygiene but does not change the non-claims.

## Owner-Confirmation Addendum

A local owner-confirmation inspection reviewed trust policies for five priority trust findings. The raw `get-role` output, raw account IDs, IAM/STS ARNs, updated label JSON, and generated review artifacts remain local-only and are not committed.

The inspection marked five reviewer labels as `owner_confirmed=true`: four `valid_path` wildcard-principal findings and one `expected_benign` `OrganizationAccountAccessRole` finding that remains pending confirmation that the redacted principal is the intended management/admin account.

The four wildcard-principal trust findings were confirmed as reviewable trust exposures:

- `ProdAdminRole`: `Principal "*"`, no condition.
- `ProdDeployRole`: `Principal "*"`, no condition.
- `SharedLambdaDeploy`: `Principal "*"`, no condition.
- `BillingAdminRole`: `Principal "*"`, with an `ExternalId` condition.

`OrganizationAccountAccessRole` trusted a specific AWS principal and remains expected-benign if that principal is the expected management/admin account.

This owner-confirmation step strengthens the claim from “reviewable findings” to “some findings corresponded to real trust policies worth owner review.” It does not claim exploitation, production readiness, full IAM correctness, downstream authorization, or broad IAMScope correctness.

## What the Pilot Supports

- Most findings were reviewable and meaningful to a human reviewer.
- IAMScope surfaced real trust structures that were worth inspection, including findings later classified as expected-benign.
- A bounded owner-confirmation pass found that some findings corresponded to real trust policies worth owner review.
- The reviewer workflow successfully separated meaningful findings, expected-benign trust structures, and calibration questions.
- Wildcard-principal trust findings repeatedly surfaced as valid-path, high-priority review items.
- Account-root trust findings were generally classifiable as valid-path or expected-benign depending on role context.

## What It Does Not Support

This pilot does not support broad safety or correctness claims. It does not establish that the dev account is safe, that IAMScope covers all IAM risks, or that every finding is owner-confirmed.

The pilot also does not prove the absence of findings outside IAMScope’s modeled coverage. It is one bounded human-review exercise over one collected real dev-account graph.

## Key Observations

- Wildcard-principal trust findings were repeatedly classified as `valid_path` and high-priority review.
- Account-root trust findings were mostly classified as `valid_path` or `expected_benign` depending on role context.
- StackSets, `OrganizationAccountAccessRole`, and IAMScopeReader-style findings were treated as expected-benign but still owner-confirmation targets.
- `admin_reachability` findings were `inconclusive_needs_context` because of clean witness uncertainty and AdministratorAccess/wildcard admin witness representation.
- The expected-benign findings were still useful because IAMScope surfaced real trust structures that should be confirmed with an owner.

## Calibration Candidates

The three `admin_reachability` findings exposed a calibration candidate around AWS-managed AdministratorAccess and clean admin witness handling.

The review question is whether AWS-managed AdministratorAccess should be treated as a clean admin-equivalence witness when the AssumeRole permission and trust path are otherwise clean, while keeping arbitrary custom wildcard policies conservative unless separately reviewed.

## Next Validation Step

- Owner-confirm additional trust findings beyond the five priority rows covered in this addendum.
- Separately test/admin-reachability calibration for AWS-managed AdministratorAccess as a clean admin witness.
- Use replayed current-main findings with `collection_context` for any future publication, while keeping raw replay artifacts local-only.

## Non-Claims

- Not production readiness.
- Not broad IAMScope correctness.
- Not full IAM safety.
- Not exploitability proof.
- Not downstream authorization proof.
- Not full resource-policy reasoning.
- Not full SCP, permission-boundary, or session-policy semantics.
- No composite score.
- No pass/fail benchmark label.
- Labels are not a full owner-confirmed truth set; only the five priority trust findings noted above received bounded local owner-inspection.
