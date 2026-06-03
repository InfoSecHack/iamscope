# Controlled Identity Deny Candidate Selection

## Purpose

Select one committed, sanitized evidence candidate for controlled identity Deny suppression validation. This slice is planning/inspection only: it does not run live AWS, call STS, call `iam:PassRole`, call Lambda APIs, create or modify resources, run Terraform, implement active validation, or change IAMScope reasoning behavior.

## Evidence Sources Searched

The search covered committed repository content only:

- Benchmark case manifests under `benchmarks/cases/`.
- Benchmark snapshots and run summaries under `benchmarks/snapshots/`.
- Mutation-pair reports under `benchmarks/pair-reports/`.
- Benchmark reporting/scoring metadata under `benchmarks/reporting/` and `benchmarks/scoring/`.
- Specification and checkpoint docs under `docs/specs/`.
- Synthetic/degradation manifests under `benchmarks/cases/`.
- Tests and sanitized fixtures under `tests/fixtures/`.

No raw AWS artifacts, `/tmp` outputs, live AWS calls, STS calls, `iam:PassRole` calls, Lambda APIs, or resource-modifying actions were used.

## Search Terms And Method

Search terms included:

- `identity Deny`
- `identity_deny`
- `explicit Deny`
- `Deny`
- `denied`
- `suppressed`
- `infeasible`
- `blocked`
- `permission boundary`
- `SCP`
- `iam:AddUserToGroup`

The search intentionally distinguished identity-policy Deny from SCP Deny, permission-boundary behavior, and resource-policy Deny. SCP and resource-policy Deny evidence was not selected for this slice.

## Candidates Considered

### Selected Candidate: Env03 Identity Deny Group Escalation

- Case: `env03_identity_deny_group_escalation`
- Family: `identity_deny`
- Evidence source:
  - `benchmarks/cases/env03_identity_deny_group_escalation.json`
  - `benchmarks/snapshots/phase0-20260509-env27/runs/env03-20260424T025701Z/run_manifest.json`
  - `benchmarks/snapshots/phase0-20260509-env27/runs/env03-20260424T025701Z/scorer_result.json`
  - `benchmarks/snapshots/phase0-20260509-env27/runs/env03-20260424T025701Z/report.md`
  - `docs/specs/env16-mutation-benchmark-harness.md`
  - `benchmarks/pair-reports/phase0-20260509-env27-mutation-pairs.md`
- Why selected: committed sanitized evidence identifies one source principal, one candidate action, one candidate resource, a structural Allow/path basis, and an explicit identity-policy Deny that suppresses the selected group-escalation result.

### Supporting Contrast: Env16 Identity Deny Removed

- Case: `env16_identity_deny_removed_validated_group_escalation`
- Evidence source:
  - `benchmarks/cases/env16_identity_deny_removed_validated_group_escalation.json`
  - `docs/specs/env16-mutation-benchmark-harness.md`
  - `benchmarks/pair-reports/phase0-20260509-env27-mutation-pairs.md`
- Use in this selection: supporting contrast only. Env16 removes the explicit identity Deny from the same group-escalation shape, so it supports the Env03 Deny-specific candidate but is not itself the selected Deny candidate.

### Not Selected: DEG03 Missing Blocker Evidence

- Case: `deg03_missing_blocker_evidence`
- Evidence source: `benchmarks/cases/deg03_missing_blocker_evidence.json`
- Reason not selected: synthetic degradation fixture focused on missing blocker attribution rather than a live benchmark candidate with the strongest current committed Env03/Env16 identity-Deny mutation evidence.

### Not Selected: SCP / Permission Boundary / Resource-Policy Deny Mentions

- Reason not selected: those are distinct boundaries. This slice is specifically for explicit identity-policy Deny suppression and does not reinterpret SCP, permission-boundary, or resource-policy Deny as identity Deny.

## Selected Candidate

- Validation-layer ID: `controlled-identity-deny-run-001-env03-add-user-to-group`
- Source principal: `arn:aws:iam::<redacted-aws-account-id>:user/iamscope-test/env03-cc1-alice`
- Candidate action: `iam:AddUserToGroup`
- Candidate resource: `arn:aws:iam::<redacted-aws-account-id>:group/iamscope-test/env03-cc1-admins`
- Pattern/finding family: `iam_group_membership_escalation`
- Expected behavior: `suppressed`
- AWS semantic expectation: the selected action is denied because explicit identity-policy Deny overrides the structural Allow.
- IAMScope evidence expectation: the structurally allowed group-escalation path is not emitted as validated; it is represented as blocked with identity-Deny blocker evidence in the committed benchmark evidence.

## Allow Basis Summary

The committed Env03/Env16 evidence states that Alice has an Allow for `iam:AddUserToGroup` on the target admins group:

- `docs/specs/env16-mutation-benchmark-harness.md` describes Env03 as giving Alice both Allow and explicit Deny for `iam:AddUserToGroup` on the admins group.
- `benchmarks/cases/env03_identity_deny_group_escalation.json` describes the blocked group-escalation path and the structural group-escalation target.
- `benchmarks/snapshots/phase0-20260509-env27/runs/env03-20260424T025701Z/run_manifest.json` records the exact source and target provider IDs for the Env03 run.

## Deny Basis Summary

The explicit identity-Deny basis is committed as sanitized benchmark evidence:

- `benchmarks/cases/env03_identity_deny_group_escalation.json` ground truth states that explicit identity-policy Deny on `iam:AddUserToGroup` overrides Allow for `env03-alice -> env03-admins`.
- The same case manifest requires identity-Deny blocker evidence and the Deny-specific required check.
- `benchmarks/snapshots/phase0-20260509-env27/runs/env03-20260424T025701Z/scorer_result.json` records the identity-Deny blocker assertion and identity-Deny check assertion as satisfied for the selected run.
- `benchmarks/snapshots/phase0-20260509-env27/runs/env03-20260424T025701Z/report.md` summarizes that the exact blocked group-escalation path is detected as blocked and that blocker attribution includes identity-Deny evidence.

## Condition Context

No committed source reviewed in this slice describes a condition requirement for the selected Env03 identity-Deny candidate. The initial static report should record condition context as absent/not applicable based on the sanitized evidence, with a caveat that no raw policy document is being committed or inspected in this slice.

## Native Finding Or Path ID Status

No native IAMScope `finding_id` or `path_id` is available from the committed sanitized run summaries inspected for this slice. The committed evidence identifies the case, run, source principal, target group, pattern, assertion IDs, and blocker/check expectations, but not a reusable native finding/path ID for the selected report.

Use this validation-layer ID strategy:

- `validation_layer_id`: `controlled-identity-deny-run-001-env03-add-user-to-group`
- `validation_id`: `controlled-identity-deny-run-001-static-suppressed`
- `source_document`: `docs/specs/controlled-identity-deny-candidate-selection.md`
- `source_bundle`: `benchmarks/snapshots/phase0-20260509-env27/runs/env03-20260424T025701Z`

## Readiness For Pre-Live / Static Report Plan

Readiness: yes.

Reasons:

- One source principal is explicit.
- One candidate action is explicit.
- One candidate resource is explicit.
- The identity Deny basis is explicit in committed sanitized benchmark evidence.
- The structural Allow/path basis is documented in committed benchmark and mutation-pair evidence.
- Expected behavior is bounded: `suppressed` / denied by explicit identity Deny.
- Evidence sources are committed and sanitized.
- No raw AWS artifacts are needed.
- No live AWS calls are needed for the next static report plan.

## Abort Conditions

Abort the next static report plan if:

- A native finding/path ID is required and the validation-layer ID strategy is not accepted.
- The report would need raw AWS artifacts or raw `/tmp` outputs.
- The report would require live AWS, STS, `iam:PassRole`, Lambda APIs, or resource modification.
- The candidate is reinterpreted as SCP Deny, resource-policy Deny, permission-boundary behavior, or generic Deny correctness.
- The report cannot preserve the one source/action/resource/identity-Deny scope.
- Required non-claims or artifact-safety fields cannot be represented.

## Evidence Boundary

This selection proves only that Env03 is a suitable committed sanitized candidate for a future controlled identity Deny static report. It does not create a new validation result, rerun the benchmark, inspect raw AWS artifacts, or perform active AWS validation.

The selected candidate is one narrow group-escalation identity-Deny suppression case. It does not prove broad identity-Deny behavior, generic Deny correctness, resource-policy Deny support, SCP Deny support, production readiness, broad IAMScope correctness, broad runtime exploitability, downstream authorization, or real-world scalability.

## Non-Claims

This candidate selection does not claim:

- Production readiness.
- Broad IAMScope correctness.
- Broad runtime exploitability.
- Generic Deny correctness.
- Resource-policy Deny support.
- SCP Deny support.
- Downstream authorization proof.
- All findings verified.
- Real-world scalability.
- Composite scoring.

## Recommended Next Slice

Recommend exactly one next slice: create controlled identity Deny Run #1 pre-live/static plan.

That next slice must remain pre-live/static planning only. It must not run live AWS, perform active validation, create or modify resources, add a new benchmark framework, add CI gates, introduce composite scoring, or recommend multiple slices at once.
