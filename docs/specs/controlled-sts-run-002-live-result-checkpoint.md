# Controlled STS Run #2 Live Result Checkpoint

## Purpose

This checkpoint records the sanitized live result for Controlled STS Validation Run #2.

This is docs/checkpoint only. It does not run live AWS, call STS AssumeRole, run `live_probe`, rerun the probe, commit `/tmp` outputs, copy raw `/tmp` result JSON or Markdown into the repository, ingest raw AWS artifacts, change executor logic, change validator logic, change report generator logic, change collector/reasoner/scorer/scenario-validation logic, change benchmark logic, add pass/fail labels, add composite scoring, claim production readiness, claim broad IAMScope correctness, or claim broad runtime exploitability.

## Run Summary

- `validation_run_id`: `controlled-sts-run-002-iam-admin-arf-rt-devrole-denied`
- Plan path: `/tmp/iamscope-controlled-sts-validation-run-002/controlled-sts-run-002-plan.json`
- Result JSON path: `/tmp/iamscope-controlled-sts-validation-run-002/controlled-sts-run-002-live-result.json`
- Result Markdown path: `/tmp/iamscope-controlled-sts-validation-run-002/controlled-sts-run-002-live-result.md`
- Source principal: `arn:aws:iam::516525145310:user/iamscope-admin`
- Target role: `arn:aws:iam::516525145310:role/arf-rt-DevRole`
- Expected outcome: `denied`
- Observed outcome: `denied`
- Safe error category: `access_denied`
- `live_aws_used`: `true`
- `aws_calls_made`: `true`
- `sts_assume_role_called`: `true`
- `credentials_obtained`: `false`
- `downstream_actions_performed`: `false`
- Raw credentials emitted: no

## Evidence Source

The raw `/tmp` result JSON and Markdown outputs were inspected before this checkpoint, but they are not committed here.

This checkpoint intentionally records only the sanitized summary needed for review. It does not paste the full raw JSON or Markdown output into the repository, and it does not ingest raw AWS logs, credentials, or temporary proof artifacts.

## Classification

- `outcome_classification`: `corroborated`
- Rationale: IAMScope's selected Run #2 candidate expected `denied`, and the observed live result was `denied` with safe error category `access_denied`.

## Evidence Boundary

This proves only that this one source principal could not assume this one target role under the explicit Controlled STS Run #2 test conditions.

It does not prove production readiness, broad runtime exploitability, downstream authorization, broad IAMScope correctness, arbitrary enterprise graph correctness, resource-policy Deny support, finding-level resource-policy reachability, or real-world scalability.

## Artifact Safety

Artifact safety summary:

- No credentials emitted.
- No raw credentials committed.
- No `/tmp` outputs committed.
- No raw AWS logs committed.
- No Terraform state committed.
- No composite score introduced.
- No pass/fail benchmark label introduced.
- No downstream AWS actions were performed.

## Relationship To Run #1

Controlled STS Run #1 remains classified as `environment_mismatch` and did not execute live.

Run #2 was selected because it matched a current live profile and committed sanitized evidence. It does not invalidate, replace, or repair Run #1. It is a separate single-path controlled STS validation result with its own source principal, target role, expected outcome, and evidence boundary.

## Non-Claims

This checkpoint does not claim:

- Production readiness.
- Broad runtime exploitability.
- Downstream authorization proof.
- Broad IAMScope correctness.
- Arbitrary enterprise graph correctness.
- Resource-policy Deny support.
- Finding-level resource-policy reachability.
- Real-world scalability.
- That any other source principal can or cannot assume any other target role.
- That the Run #2 result generalizes beyond this one source principal, one target role, and one explicit test condition.

## Recommended Next Slice

Decide whether to perform one matched positive controlled STS validation run or stop controlled validation after Run #2.

Do not proceed directly to another live probe, broad validation, production testing, downstream AWS actions, a new benchmark framework, CI gates, composite scoring, or multiple slices at once without a separate scoped plan and explicit approval.
