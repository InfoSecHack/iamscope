# IAMScope Reviewer Guide

## Claim Boundary

IAMScope currently has a local synthetic path-overcounting teaching demo and one two-sided controlled PassRole-to-Lambda validation pair. This is not broad IAMScope correctness.

This guide is a reviewer-facing map for the current public demo/evidence chain. It does not add evidence, broaden supported claims, or change the safe local workflow.

## What To Review First

Start with the public case-study narrative, then inspect the binding checkpoints and local fixtures only if you want deeper verification. The intended review is about claim boundaries, evidence framing, and whether the docs make the safe local path clear.

## Evidence Map

- [`docs/case-studies/path-overcounting-shared-uncertainty.md`](case-studies/path-overcounting-shared-uncertainty.md): local synthetic teaching demo for path overcounting and shared uncertainty.
- [`docs/case-studies/passrole-lambda-controlled-live-validation.md`](case-studies/passrole-lambda-controlled-live-validation.md): public narrative for the two-sided controlled PassRole-to-Lambda validation pair.
- [`docs/specs/controlled-passrole-lambda-live-binding-001-checkpoint.md`](specs/controlled-passrole-lambda-live-binding-001-checkpoint.md): allowed-side binding checkpoint.
- [`docs/specs/controlled-passrole-lambda-denied-live-binding-001-checkpoint.md`](specs/controlled-passrole-lambda-denied-live-binding-001-checkpoint.md): denied-side binding checkpoint.
- [`tests/fixtures/live_binding/passrole_lambda_selected_finding/`](../tests/fixtures/live_binding/passrole_lambda_selected_finding/): selected local allowed-side fixture.
- [`tests/fixtures/live_binding/passrole_lambda_denied_missing_passrole/`](../tests/fixtures/live_binding/passrole_lambda_denied_missing_passrole/): denied missing-PassRole fixture.

## Supported Claims

- Local synthetic path-overcounting demo shows how IAMScope separates naive path-shaped candidates from validated, blocked, precondition-only, and inconclusive fixture verdicts.
- Allowed PassRole-to-Lambda case: selected local `validated` finding matched live AWS `lambda:CreateFunction` success.
- Denied missing-PassRole case: live AWS returned `access_denied`, and local IAMScope emitted no selected validated `passrole_lambda` finding for the corresponding source/target shape.

## Non-Claims

- no broad IAMScope correctness
- no broad PassRole correctness
- no generic Deny correctness
- no resource-policy Deny support
- no SCP Deny support
- no exploitability proof
- no downstream authorization proof
- no Lambda invocation behavior
- no production readiness
- no correctness for other principals, roles, accounts, regions, conditions, permission boundaries, SCPs, resource policies, or findings
- no composite benchmark score
- no pass/fail benchmark label

## Suggested Review Order

1. [`docs/START_HERE.md`](START_HERE.md)
2. [`docs/REVIEWER_GUIDE.md`](REVIEWER_GUIDE.md)
3. [`docs/case-studies/passrole-lambda-controlled-live-validation.md`](case-studies/passrole-lambda-controlled-live-validation.md)
4. [`docs/case-studies/path-overcounting-shared-uncertainty.md`](case-studies/path-overcounting-shared-uncertainty.md)
5. Binding checkpoint docs and local fixtures only if deeper verification is needed
