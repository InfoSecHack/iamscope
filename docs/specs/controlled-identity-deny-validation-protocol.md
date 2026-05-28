# Controlled Identity Deny Validation Protocol

## Purpose

This protocol defines how IAMScope should validate one selected explicit identity-Deny suppression case. The goal is to decide whether bounded evidence can corroborate, refute, or leave unresolved an IAMScope prediction that a structurally allowed path or action should be suppressed because an explicit identity policy `Deny` applies.

This is a docs/design protocol only. It does not implement validation logic, run live AWS, change IAMScope reasoning behavior, or claim generic Deny correctness.

## Non-Goals

This protocol is not:

- An implementation.
- Live AWS execution in this PR.
- Generic Deny correctness.
- Resource-policy Deny validation.
- SCP Deny validation.
- Production testing.
- Broad IAMScope correctness proof.
- Exploitability proof.
- Composite scoring.
- CI gating.
- A replacement for benchmark, STS, or PassRole evidence.

## Validation Question

When IAMScope sees a structurally allowed path or action but an explicit identity `Deny` applies, can bounded evidence corroborate that the path/action should be denied, suppressed, or classified infeasible?

The question is intentionally narrow. It covers one selected source principal, action, resource, and explicit identity-Deny statement. It does not cover generic Deny behavior, resource-policy Deny, SCP Deny, or arbitrary enterprise graph correctness.

## First Validation Scope

The first controlled Identity Deny validation must be limited to:

- One controlled source principal.
- One candidate action.
- One candidate resource.
- One explicit identity `Deny`.
- One allow basis, if present.
- One validation report.
- No broad scan.
- No production resources.
- No destructive action.
- No raw credentials, raw logs, or committed `/tmp` outputs.

## Evidence Methods

| Evidence Method | Evidence Value | Safety Risk | False-Positive / False-Negative Risk | Setup Cost | Artifact Risk | What It Proves And Does Not Prove |
| --- | --- | --- | --- | --- | --- | --- |
| A. Static policy evidence only | Strong first-pass evidence that a specific identity `Deny` syntactically covers the selected action/resource/context and overrides any allow basis | Lowest; uses committed or sanitized metadata only | Can miss runtime context, policy version drift, boundaries, SCPs, session policies, or service-specific behavior | Low if sanitized evidence already exists | Lowest when only sanitized summaries are committed | Proves static corroboration for one selected identity-Deny case; does not prove live AWS behavior |
| B. IAM policy simulation, if available and safe | Higher confidence for modeled IAM decision under explicit action, resource, and context | Low to medium; still a live AWS simulation API if executed | Simulator may not model every service behavior, condition key, boundary, SCP, session policy, or resource-policy interaction | Medium; requires exact inputs and simulation permissions | Low if outputs are summarized and sanitized | Proves simulator-modeled deny/allow result for one case; does not prove downstream service behavior |
| C. One harmless active AWS read/action, if separately approved | Potential runtime evidence that a selected harmless operation is denied as expected | Medium; any active API call may generate logs and expose environment drift | Failures can come from unrelated configuration, missing resources, throttling, service behavior, or policy context | Medium to high; requires a safe action and cleanup/abort plan | Medium; live errors/logs must remain out of repo | Proves one selected active operation result under controlled conditions; does not prove generic Deny correctness |
| D. No active check if safe action cannot be identified | Preserves safety when no harmless action exists | Lowest | Leaves runtime behavior unresolved | Low | Lowest | Proves only that the protocol declined unsafe validation; does not corroborate live behavior |

## Recommended First Evidence Method

Recommend exactly one first method: static allow/deny corroboration from sanitized policy evidence.

IAM policy simulation or a harmless active read/action may be considered only after a separate design slice defines exact inputs, permissions, artifact handling, abort conditions, and approval. This protocol does not authorize live AWS, STS, `iam:PassRole`, Lambda APIs, resource creation, or active validation.

## Required Conditions

Before a selected identity-Deny case can be validated, the candidate must document:

- Explicit source principal.
- Explicit candidate action.
- Explicit candidate resource.
- Documented allow basis, if relevant to the structurally allowed path/action.
- Explicit identity-policy `Deny` statement.
- Condition context captured when the `Deny` or allow basis uses conditions.
- Evidence source and whether it is committed, sanitized, or generated outside the repo.
- No production resources.
- No destructive actions.
- No raw credentials or raw logs.
- No Terraform state/cache/provider artifacts.
- No generated reports committed by default.

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

A controlled Identity Deny validation report should classify mismatches using this taxonomy where applicable:

- Deny does not actually match action.
- Deny does not actually match resource.
- Deny condition not satisfied.
- Allow basis missing.
- Permission boundary, SCP, or session policy interference.
- Unsupported condition key.
- Environment drift.
- Stale artifact.
- Protocol design flaw.
- IAMScope reasoner bug candidate.

## Artifact Safety

The protocol requires:

- No credentials, tokens, or credential-shaped values committed.
- No raw AWS logs committed.
- No `/tmp` outputs committed.
- No Terraform state/cache/provider artifacts committed.
- Sanitized summaries only.
- No generated reports committed by default.
- Explicit artifact-safety status in any future validation report.

## Future Report Schema Sketch

A future controlled Identity Deny validation report should include at least:

- `validation_id`
- `environment_label`
- `source_principal_arn`
- `candidate_action`
- `candidate_resource`
- `allow_basis`
- `deny_basis`
- `condition_context`
- `predicted_behavior`
- `evidence_method`
- `observed_or_static_evidence`
- `outcome_classification`
- `evidence_summary`
- `caveats`
- `non_claims`
- `artifact_safety_status`

The report should distinguish static evidence, simulation evidence, and active evidence. It should not imply live AWS execution when only static evidence was used.

## What This Protocol Would Prove

If followed for one selected candidate, this protocol would prove only that one selected explicit identity-Deny suppression prediction was corroborated, refuted, or left inconclusive under explicit controlled conditions.

It would also prove that the selected evidence method, caveats, non-claims, and artifact-safety boundaries were documented for that one case.

## What Remains Unproven

This protocol would not prove:

- Production readiness.
- Broad IAMScope correctness.
- Generic Deny correctness.
- Resource-policy Deny support.
- SCP Deny support.
- All findings verified.
- Real-world scalability.
- Exploitability.
- Downstream authorization.
- Arbitrary enterprise graph correctness.

## Recommended Next Slice

Recommend exactly one next slice: design controlled identity Deny validation report schema.

That next slice must remain docs/schema only. It should not run live AWS, perform active validation, create resources, implement validator or generator logic, add a benchmark framework, add CI gates, introduce composite scoring, or recommend multiple slices at once.
