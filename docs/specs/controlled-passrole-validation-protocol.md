# Controlled PassRole Validation Protocol

## Purpose

This protocol defines how IAMScope should validate exactly one selected PassRole-to-service finding or path against bounded evidence. The goal is to ask whether a selected IAMScope prediction about `iam:PassRole` can be corroborated, refuted, or left unresolved under explicit controlled conditions without turning the result into a broad exploitability or production-readiness claim.

## Non-Goals

This protocol is not:

- An implementation.
- Live execution in this PR.
- A service launch or resource-creation procedure.
- Downstream AWS action proof.
- Production testing.
- Broad exploitability proof.
- Broad IAMScope correctness proof.
- CI gating.
- Composite scoring.
- A replacement for benchmark evidence or controlled STS evidence.

## Validation Question

When IAMScope predicts that a selected principal can pass a selected role to a selected service, can bounded evidence corroborate, refute, or leave unresolved that prediction?

The validation question is intentionally narrow. It concerns one selected PassRole-to-service prediction, not all PassRole findings, not arbitrary service execution, and not downstream authorization after a service receives the role.

## First Validation Scope

The first controlled PassRole validation must be limited to:

- One controlled AWS account or lab.
- One source principal.
- One target role.
- One service principal, such as `lambda.amazonaws.com` or `ec2.amazonaws.com`.
- One selected IAMScope PassRole finding or path.
- One validation report.
- No broad scan.
- No production resources.
- No service launch by default.
- No Terraform in the validation slice unless a later design explicitly approves controlled setup.

## Evidence Types

| Evidence Type | Evidence Value | Safety Risk | False-Positive / False-Negative Risk | Required Permissions | Artifact Risk | What It Proves |
| --- | --- | --- | --- | --- | --- | --- |
| A. IAM policy simulation | Useful for permission-side corroboration when simulation inputs are precise | Low to medium; read/simulation API only, but still live AWS if executed | Can miss trust/service behavior, context keys, boundaries, SCPs, session policies, or simulator limitations | Permission to call simulation APIs for the selected principal/policy context | Low if sanitized; simulator responses can still include sensitive ARNs/policy details | Permission-side `iam:PassRole` allowance or denial under modeled context, not downstream service execution |
| B. Dry-run or validation-only service API | Potentially stronger service-specific evidence if the API has a true non-destructive validation mode | Medium; service APIs vary, and dry-run semantics can still expose permissions or require setup | Service-specific dry-run behavior may validate caller permissions without proving PassRole, or may fail for unrelated missing parameters | Service-specific read/dry-run permissions plus any prerequisite validation permissions | Medium; service API errors can include environment details | At most service API acceptance/rejection under a dry-run path, not downstream action proof |
| C. Static trust/permission corroboration from sanitized AWS metadata | Strongest safe first step for schema/report design and offline review | Lowest; uses sanitized metadata only | Static evidence can miss runtime context keys, SCPs, permission boundaries, session policies, or service-specific constraints | No live permissions if evidence is already sanitized | Lowest when summaries are sanitized and raw artifacts are excluded | Static agreement that source permission and target trust shape are compatible with the selected prediction |
| D. Actual service create/launch call | Highest runtime evidence for service acceptance | Highest; creates/modifies resources and may trigger downstream behavior | Failures can come from unrelated service setup, quotas, regions, parameters, or cleanup issues | Mutating service permissions and cleanup permissions | High; can generate logs, resources, state, and side effects | Service accepted or rejected a resource creation path; may still not prove downstream authorization beyond creation |

## Recommended First Evidence Method

Recommend exactly one first method: static trust/permission corroboration from sanitized AWS metadata, optionally paired in a later approved slice with non-destructive IAM policy simulation if it is available and scoped to the selected principal, target role, and context.

Actual service launch/resource creation is deferred. The first PassRole validation should prove that IAMScope can represent, review, and classify one selected PassRole prediction with clear evidence boundaries before any mutating service call is considered.

## Required Conditions

A controlled PassRole validation candidate must satisfy these conditions before any live or simulated validation is considered:

- The source principal has `iam:PassRole` permission scoped to the selected target role, or the validation is explicitly testing a denied/refuted prediction.
- The target role trust policy allows the selected service principal.
- The service principal is explicit, for example `lambda.amazonaws.com` or `ec2.amazonaws.com`.
- Wildcard role/resource scope is avoided unless it is intentionally part of the selected finding and documented as such.
- No production resources are used.
- No downstream action execution is performed.
- Output paths are safe and separate from committed source files.
- No raw credentials, raw logs, Terraform state/cache/provider artifacts, or `/tmp` outputs are committed.
- Any generated report remains uncommitted by default unless separately sanitized and reviewed.

## Outcome Classifications

Allowed outcome classifications:

- `corroborated`
- `refuted`
- `inconclusive`
- `environment_mismatch`
- `evidence_gap`
- `probe_harness_issue`
- `tool_bug_candidate`
- `model_limitation`

Avoid outcome labels such as:

- `pass`
- `fail`
- `vulnerable`
- `exploited`
- `production_ready`

## Mismatch Taxonomy

A controlled PassRole validation report should classify mismatches using this taxonomy where applicable:

- Permission policy mismatch.
- Role trust mismatch.
- Service principal mismatch.
- Condition key not modeled.
- Permission boundary, SCP, or session policy interference.
- Environment drift.
- Stale artifact.
- Unsupported service behavior.
- Protocol design flaw.
- Tool/reasoner bug candidate.

## Artifact Safety

The protocol requires:

- No raw AWS logs committed.
- No credentials, tokens, or credential-shaped values committed.
- No `/tmp` outputs committed.
- No Terraform state/cache/provider artifacts committed.
- No generated reports committed by default.
- Sanitized summary only for any future committed checkpoint.
- Explicit artifact-safety status in the validation report.

## Future Report Schema Sketch

A future controlled PassRole validation report should include at least:

- `validation_id`
- `environment_label`
- `finding_id` / `path_id`, or a clearly labeled validation-layer ID when native IDs are unavailable
- `source_principal_arn`
- `target_role_arn`
- `service_principal`
- `predicted_behavior`
- `evidence_method`
- `observed_evidence`
- `outcome_classification`
- `caveats`
- `non_claims`
- `artifact_safety_status`

The schema should distinguish IAMScope-native identifiers from validation-layer identifiers and should not imply a native finding/path ID where one is unavailable.

## What This Protocol Would Prove

If followed for one selected candidate, this protocol would prove only that:

- One selected PassRole prediction was corroborated, refuted, or left inconclusive under explicit controlled conditions.
- The evidence method and artifact boundaries were preserved for that selected validation.
- The report classified the outcome without broad exploitability or production-readiness language.

## What Remains Unproven

This protocol would not prove:

- Production readiness.
- Broad IAMScope correctness.
- Broad exploitability.
- Downstream service execution.
- Downstream AWS authorization after a service receives the role.
- Arbitrary enterprise graph correctness.
- All findings verified.
- Real-world scalability.
- Generic PassRole coverage across services.
- Generic resource-policy Deny support.

## Recommended Next Slice

Recommend exactly one next slice: design minimal controlled PassRole validation report schema.

That next slice should remain docs/schema only. It should not implement validation logic, run live AWS, call `iam:PassRole`, launch services, create resources, add CI gates, introduce composite scoring, or broaden the evidence boundary.
