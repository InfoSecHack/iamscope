# Supported / Unsupported Evidence Matrix

## Purpose

Summarize what IAMScope currently has bounded evidence for, what is partially supported, and what is explicitly not claimed.

## Evidence Matrix

| Area | Current evidence status | Boundary / non-claim |
| --- | --- | --- |
| STS standalone denied proof | Evidenced as a standalone runtime executor proof for a denied STS path. | Useful runtime corroboration, but not broad IAMScope correctness and not all findings verified. |
| STS standalone assumed proof | Evidenced as a standalone runtime executor proof for an assumed STS path. | Useful runtime corroboration, but not the same as every selected finding/path being controlled-validated. |
| Controlled STS Run #1 | Environment mismatch detected before live execution. | No live execution and no runtime validation result for Run #1. |
| Controlled STS Run #2 | Selected live-profile-matched denied/access_denied STS path was corroborated. | One selected source/target condition only; no broad exploitability or production-readiness claim. |
| PassRole static/report validation | Controlled PassRole report schema, validator, generator, static report, and static checkpoint exist. | Static/report validation proves representation and schema/safety boundaries, not `iam:PassRole` execution or service behavior. |
| Active PassRole-to-Lambda Run #1 | Service-mediated PassRole-to-Lambda `CreateFunction` was corroborated for one test-only source, one test-only role, one Lambda function, under explicit controlled conditions. The function was not invoked and was deleted. | Does not prove exploitability, downstream authorization, production readiness, broad PassRole correctness, broad IAMScope correctness, or real-world scalability. |
| Identity Deny suppression static validation | Controlled identity Deny Run #1 static validation exists for one selected explicit identity-Deny case. The selected candidate was represented as a controlled identity Deny validation report and passed schema/safety validation. | Static sanitized evidence/report validation only; no live AWS was run, no active AWS behavior was observed, and no generic Deny correctness is claimed. |
| Frozen live AWS semantic benchmark layer | Current-scope frozen benchmark evidence exists for selected semantic cases. | Frozen evidence supports bounded reviewer discussion, not arbitrary enterprise graph correctness. |
| Mutation-pair sensitivity | Mutation-pair evidence demonstrates sensitivity to selected semantic deltas. | Does not establish comprehensive mutation coverage or broad correctness. |
| Synthetic scalability/degradation fixtures | Synthetic fixtures exist for current-scope scalability/degradation analysis. | Synthetic fixtures do not prove real-world scalability. |
| Reporting/comparison and threshold review | Reporting/comparison and report-only threshold review exist. | Threshold review remains advisory/report-only and is not a CI gate or benchmark pass/fail label. |
| Artifact hygiene | Hygiene checks cover tracked Terraform state/cache/provider artifacts, raw live artifacts in benchmark snapshots, gitlinks/submodules, and carriage-return filenames. | Hygiene checks reduce artifact risk but do not prove absence of every possible secret outside tracked scope. |

## Active PassRole-to-Lambda Evidence

The active PassRole-to-Lambda result is supported only at this narrow boundary:

- One test-only source principal: `arn:aws:iam::516525145310:user/iamscope-passrole-active-source`.
- One test-only target role: `arn:aws:iam::516525145310:role/iamscope-passrole-active-target-role`.
- One service principal: `lambda.amazonaws.com`.
- One Lambda function name: `iamscope-passrole-active-run001`.
- One region: `us-east-1`.
- Observed active result: `CreateFunction` succeeded, `GetFunctionConfiguration` succeeded, `DeleteFunction` returned status code `204`, and post-delete `GetFunction` returned `ResourceNotFoundException`.
- The function was not invoked.
- No triggers, function URL, event source mappings, aliases, versions, or downstream actions were created or used.
- Function, source user, target role, and source profile were torn down or rendered unusable.
- Outcome classification: `corroborated`.

This row should be described as service-mediated PassRole-to-Lambda evidence, not a claim of exploitability or downstream Lambda impact.

## Controlled Identity Deny Static Evidence

The controlled identity Deny Run #1 static result is supported only at this narrow boundary:

- One selected Env03 explicit identity-Deny candidate.
- One source principal: `arn:aws:iam::516525145310:user/iamscope-test/env03-cc1-alice`.
- One candidate action: `iam:AddUserToGroup`.
- One candidate resource: `arn:aws:iam::516525145310:group/iamscope-test/env03-cc1-admins`.
- One validation-layer ID: `controlled-identity-deny-run-001-env03-add-user-to-group`.
- Evidence method: `static_policy_corroboration`.
- Observed static outcome: `suppressed`.
- Outcome classification: `corroborated`.
- The selected identity-Deny candidate was represented as a controlled identity Deny validation report and passed schema/safety validation.
- `live_aws_used=false`, `aws_calls_made=false`, `destructive_action_called=false`, and `resource_modified=false`.
- No live AWS was run and no active AWS behavior was observed.
- No generic Deny correctness is claimed.

This row should be described as static controlled identity-Deny evidence, not active Deny runtime validation and not generic Deny support.

## Partially Supported / Bounded Areas

These areas have some evidence or design support but remain bounded:

- Identity Deny suppression: static controlled evidence exists for one selected explicit identity-Deny case only; active harmless Deny validation remains a future decision.
- Condition keys: selected conditions are represented in benchmark/design evidence, but IAMScope does not claim comprehensive condition-key correctness.
- Permission boundaries and session policies: related Deny-like contexts remain bounded unless separately validated.
- Cross-account variants: selected cross-account benchmark/design materials exist, but arbitrary cross-account enterprise graph correctness is not claimed.
- Broader PassRole service coverage beyond Lambda: ECS/other service designs and fixtures may exist, but active service-mediated corroboration currently covers only the selected Lambda case above.
- SCPs: selected benchmark/design evidence may discuss SCP behavior, but SCP Deny support is not claimed unless separately validated.
- Runtime validation beyond selected paths: STS and PassRole runtime evidence is selected and bounded, not a claim that every finding is runtime verified.
- Resource-policy Deny: closure/design work exists, but generic resource-policy Deny support and finding-level reachability are not claimed unless explicitly scoped in a future slice.

## Explicitly Unsupported / Not Claimed

IAMScope currently does not claim:

- Production readiness.
- Broad IAMScope correctness.
- Arbitrary enterprise graph correctness.
- Broad runtime exploitability.
- Downstream authorization proof.
- Generic Deny correctness.
- Generic resource-policy Deny support.
- SCP Deny support.
- Active Deny runtime validation.
- Finding-level reachability unless explicitly scoped.
- All findings verified.
- Real-world scalability.
- Composite benchmark score.
- Pass/fail benchmark label or CI threshold gate validity.
- Enterprise validation or complete IAM reasoning.

## Reading Links

Start with these reviewer-facing materials:

- [`README.md`](../../README.md)
- [`docs/releases/research-checkpoint-release-notes.md`](../releases/research-checkpoint-release-notes.md)
- [`docs/specs/release-hygiene-checkpoint.md`](release-hygiene-checkpoint.md)
- [`docs/specs/final-controlled-validation-maturity-checkpoint.md`](final-controlled-validation-maturity-checkpoint.md)
- [`docs/specs/controlled-identity-deny-run-001-static-validation-checkpoint.md`](controlled-identity-deny-run-001-static-validation-checkpoint.md)
- [`docs/specs/controlled-identity-deny-validation-report-schema.md`](controlled-identity-deny-validation-report-schema.md)
- [`docs/specs/controlled-identity-deny-validation-protocol.md`](controlled-identity-deny-validation-protocol.md)
- [`docs/specs/controlled-passrole-active-run-001-result-and-teardown-checkpoint.md`](controlled-passrole-active-run-001-result-and-teardown-checkpoint.md)
- [`docs/specs/controlled-passrole-run-001-static-validation-checkpoint.md`](controlled-passrole-run-001-static-validation-checkpoint.md)
- [`docs/specs/controlled-sts-run-002-live-result-checkpoint.md`](controlled-sts-run-002-live-result-checkpoint.md)
- [`docs/specs/controlled-sts-validation-report-schema.md`](controlled-sts-validation-report-schema.md)
- [`docs/specs/controlled-sts-validation-report-validator.md`](controlled-sts-validation-report-validator.md)
- [`docs/specs/controlled-sts-validation-report-generator.md`](controlled-sts-validation-report-generator.md)
- [`docs/specs/controlled-sts-validation-report-bundle-generator.md`](controlled-sts-validation-report-bundle-generator.md)
- [`docs/specs/controlled-passrole-validation-report-schema.md`](controlled-passrole-validation-report-schema.md)
- [`docs/specs/controlled-passrole-validation-report-generator-design.md`](controlled-passrole-validation-report-generator-design.md)
- [`docs/specs/release-hygiene-checkpoint.md`](release-hygiene-checkpoint.md)
- [`docs/specs/github-prerelease-publication-checkpoint.md`](github-prerelease-publication-checkpoint.md)

Runtime proof maturity material is archived/background. Current reviewer-facing
evidence is summarized through `README.md`, `docs/START_HERE.md`, this matrix,
`BENCHMARK_STATUS.md`, and the selected STS, PassRole, and Identity Deny
checkpoints above.

## Recommended Reviewer Focus

Check whether the supported, bounded, and unsupported areas are clear. Flag any
claim that sounds broader than the evidence summarized here.
