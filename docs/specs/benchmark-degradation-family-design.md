# Benchmark Degradation Family Design

## Purpose

The degradation benchmark family proves IAMScope does not create false confidence when required evidence is missing, malformed, partial, or artifact-insufficient. The threat model is a reviewer trusting a confident `validated` finding even though the supporting collection is incomplete. These cases should force the benchmark program to make missing evidence explicit instead of silently treating absence as proof.

The expected honest outcomes are one of:

- `inconclusive`, when IAMScope can emit a degraded finding with explicit unknowns.
- `artifact_insufficient`, when required benchmark artifacts are missing or invalid.
- `human_review_required`, when the evaluated run is structurally present but truth confidence is degraded.
- No target finding, when that is the current honest contract for the missing evidence shape.

What must not happen: IAMScope must not emit confident validated reachability when the required witness, blocker, binding, or artifact is absent.

## Why Frozen Artifacts First

This family should start as frozen-artifact benchmarks, not live AWS environments, because the goal is not to prove AWS can create a degraded state. The goal is to prove IAMScope and the benchmark gates react honestly when evidence is incomplete after collection.

Frozen fixtures are lower risk and more precise:

- They can remove one evidence element at a time from a known live-passing baseline.
- They avoid live AWS mutation, collection timing, Organizations permissions, and teardown risk.
- They can model malformed or missing artifacts that live AWS cannot reliably produce on demand.
- They avoid copying raw live archives while still using small evaluated artifacts or synthetic fixtures.

## Proposed Cases

### DEG01 Missing Trust Edge From Positive AssumeRole Path

- Source artifact basis: minimal Env06-like positive admin reachability fixture.
- Mutation applied: remove the `sts:AssumeRole_trust` edge for the admin target while preserving Alice's permission edge and the admin-equivalent target role.
- Expected outcome: no validated `admin_reachability` for the target path; acceptable outcomes are `inconclusive` or no target finding, depending on current reasoner behavior.
- What must not happen: a validated admin reachability finding for Alice -> admin.
- Likely scorer/gate behavior: assert validated target finding count is `0`; assert the trust edge count is `0`; mark `pair` or case as pass if the false-admin guard holds. If the benchmark expects an explicit degraded finding later, gate any absence as `semantic_mismatch`.

### DEG02 Missing Identity Permission Edge From Positive AssumeRole Path

- Source artifact basis: minimal Env06-like positive admin reachability fixture.
- Mutation applied: remove the `sts:AssumeRole_permission` edge while preserving trust and admin-equivalent target role.
- Expected outcome: no validated `admin_reachability` for the target path; acceptable outcomes are `inconclusive` or no target finding.
- What must not happen: a validated admin reachability finding for Alice -> admin.
- Likely scorer/gate behavior: assert validated target finding count is `0`; assert the permission edge count is `0`; pass only if artifacts are sufficient and no false validated finding appears.

### DEG03 Missing Complete Blocker Binding From Blocked Path

- Source artifact basis: Env13-like complete SCP-blocked path or Env05-like permission-boundary blocked path.
- Mutation applied: preserve permission/trust/admin path and preserve blocker constraint metadata, but remove the edge-to-constraint binding that makes the blocker complete for the target path.
- Expected outcome: no confident `validated` reachability and no confident `blocked` finding that pretends the unbound blocker applies. Preferred result is `inconclusive`; acceptable current contract may be no target finding if the reasoner cannot attach the blocker.
- What must not happen: validated admin reachability through the unbound blocker gap, or blocked reachability with fabricated blocker evidence.
- Likely scorer/gate behavior: assert `validated == 0`; assert required blocker-binding count is `0`; assert blocker evidence with string `constraint_id`/`edge_id` is absent unless the fixture intentionally contains a valid binding. Any false validated finding should map to `false_admin_claim`.

### DEG04 Missing Edge Constraints From Conditioned Path

- Source artifact basis: Env08 trust-condition path, Env14 permission-condition path, Env19 Lambda `PassedToService` path, or Env21 ECS `PassedToService` path.
- Mutation applied: keep the conditioned edge and raw condition evidence but remove `edge_constraints` or equivalent binding metadata that connects condition truth to the relevant path.
- Expected outcome: no validated target reachability. Preferred result is `inconclusive` or `precondition_only` when the reasoner can still identify a failed precondition from edge features.
- What must not happen: validated reachability through an unproven condition.
- Likely scorer/gate behavior: assert validated count is `0`; assert condition/binding artifact state is explicitly absent; mark human review required if the fixture indicates partial condition evidence.

### DEG05 Malformed Policy Parse / Parse Error Path

- Source artifact basis: small synthetic scenario containing a policy parse-status node, edge, or constraint shape already supported by parser tests.
- Mutation applied: represent a malformed trust, permission, SCP, or resource policy parse result without emitting a clean witness edge.
- Expected outcome: no validated target reachability; preferred result is `inconclusive` or an explicit parse-error/degraded evidence marker.
- What must not happen: silently treating malformed policy as Allow, Deny, or clean absence.
- Likely scorer/gate behavior: assert validated count is `0`; assert parse-error/degraded marker exists if current schema exposes one. If current schema lacks a marker, document as "no finding is the current honest contract" and make missing marker a future improvement, not a current failure.

### DEG06 Account Skipped / Partial Collection

- Source artifact basis: synthetic or redacted run manifest plus scenario metadata representing a skipped account or partial collection.
- Mutation applied: mark one account as skipped or incomplete while a cross-account or org-level reachability path would otherwise need that account's evidence.
- Expected outcome: artifact should be `human_review_required`, and the target path must not be validated.
- What must not happen: treating skipped account evidence as complete and validating the path.
- Likely scorer/gate behavior: if scenario validation fails or required artifact state is missing, emit `artifact_insufficient`; if artifacts are structurally valid but collection status is degraded, assert validated count is `0` and human review is required.

### DEG07 Missing Findings Or Scenario Artifact

- Source artifact basis: evaluated run directory fixture, not a scenario mutation.
- Mutation applied: omit `findings_json` or `scenario_json` from `run_manifest.artifacts`, or point it at a missing path.
- Expected outcome: `artifact_insufficient` and promotion blocked by the existing artifact gate.
- What must not happen: report generation or corpus summary silently treating the case as passed.
- Likely scorer/gate behavior: existing `collect_artifact_defects` should produce an `artifact_insufficient` defect; promotion gates should block.

## Recommended First Three Cases

1. DEG07 missing findings or scenario artifact.
2. DEG01 missing trust edge from an Env06-like positive path.
3. DEG02 missing identity permission edge from an Env06-like positive path.

These are the smallest first slice because they avoid new reasoner semantics. DEG07 directly validates the existing artifact gate. DEG01 and DEG02 validate the most important false-confidence guard: missing required AssumeRole evidence must not become validated admin reachability.

DEG03 should follow next because blocker-binding degradation is higher value but needs more care to avoid accidentally changing blocker semantics.

## Current Implementation Status

The implemented synthetic degradation benchmarks are status/pointer cases, not live AWS corpus cases. They complement the frozen live corpus and mutation-pair report by proving missing, malformed, or partial evidence is explicit in benchmark scoring and gates. They emit no composite score and do not claim broad IAMScope correctness or production readiness.

DEG07 is implemented as `benchmarks/cases/deg07_missing_required_artifacts.json` plus focused synthetic tests. Missing required artifact paths or missing required artifact keys now flow through the benchmark artifact gate as explicit `artifact_insufficient` defects instead of uncaught scorer exceptions or silent passes.

DEG01 is implemented as `benchmarks/cases/deg01_missing_trust_edge.json` plus generated synthetic tests. The fixture contains an Env06-like permission edge to an admin-equivalent role while omitting the matching `sts:AssumeRole_trust` edge. It proves the benchmark scorer/gate accepts the artifact-sufficient degraded fixture only when no validated `admin_reachability` finding is present, and blocks promotion if a false validated admin claim appears.

DEG02 is implemented as `benchmarks/cases/deg02_missing_permission_edge.json` plus generated synthetic tests. The fixture contains an Env06-like trust edge to an admin-equivalent role while omitting the matching `sts:AssumeRole_permission` edge. It proves the benchmark scorer/gate accepts the artifact-sufficient degraded fixture only when no validated `admin_reachability` finding is present, and blocks promotion if a false validated admin claim or unexpected permission edge appears.

DEG03 is implemented as `benchmarks/cases/deg03_missing_blocker_evidence.json` plus generated synthetic tests. The fixture uses an Env03-like `iam:AddUserToGroup` path to an admin-equivalent group, then strips identity-deny blocker/check evidence from the blocked finding. Missing blocker evidence is classified as `semantic_mismatch`, artifacts remain sufficient, and promotion is blocked. A false validated group-escalation claim is classified as `false_admin_claim`.

DEG04 is implemented as `benchmarks/cases/deg04_missing_edge_constraints.json` plus generated synthetic tests. The fixture uses an Env14-like AssumeRole path with permission and trust edges to an admin-equivalent role, then strips the permission-side `aws:MultiFactorAuthPresent` condition evidence from the permission edge. Missing condition evidence is classified as `semantic_mismatch`, artifacts remain sufficient, and promotion is blocked. A false validated admin claim is classified as `false_admin_claim`.

DEG05 is implemented as `benchmarks/cases/deg05_malformed_policy_parse.json` plus generated synthetic tests. The fixture uses an Env06-like AssumeRole shape with a clean trust edge to an admin-equivalent role and an explicit malformed caller-side policy parse marker, but no clean `sts:AssumeRole_permission` edge. Missing clean permission evidence is classified as `semantic_mismatch`, artifacts remain sufficient, and promotion is blocked. A false validated admin claim is classified as `false_admin_claim`, and a missing parse marker is also classified as `semantic_mismatch` so malformed evidence cannot disappear silently.

DEG06 is implemented as `benchmarks/cases/deg06_partial_account_collection.json` plus generated synthetic tests. The fixture uses a cross-account-looking AssumeRole shape with caller-side permission evidence and an explicit skipped target-account marker, but no target-account role or trust evidence. Missing target-account witnesses are classified as `semantic_mismatch`, artifacts remain sufficient because `scenario_json` and `findings_json` exist and scenario validation is marked passing, and promotion is blocked. False validated `admin_reachability` or `cross_account_trust` claims are classified as `false_admin_claim`, and a missing partial-collection marker is classified as `semantic_mismatch`.

## Minimal Implementation Strategy

Use synthetic fixtures first. Do not copy raw live AWS archives.

Recommended fixture shape:

- Create tiny evaluated run directories under a test fixture helper or generated `tmp_path`.
- Include only `run_manifest.json`, `scorer_result.json`, `gate_result.json`, and report output when testing reporting.
- For cases that need scorer execution, create tiny `scenario.json` and `findings.json` fixtures with only the source, target, edge, and finding fields required by the current scorer.
- Derive provider IDs and case narratives from Env06/Env13/Env19/Env21 where useful, but do not copy full frozen run artifacts or raw live archives.

If repo-local frozen degradation snapshots are later added, store only evaluated artifacts, mirroring `benchmarks/snapshots/*/runs/*/{run_manifest,scorer_result,gate_result,report.md}`. Do not include `scenario.json`, `findings.json`, `binding_metadata.json`, `run.log`, Terraform state, provider caches, or `collect/`.

## Required Scorer / Gate Additions

No scorer changes are required for DEG07, DEG01, or DEG02 if the initial cases assert existing `finding_count` and `scenario_edge_count` behavior.

Potential later additions:

- A `scenario_metadata_state` assertion if collection-status metadata becomes first-class in `scenario.json`.
- A `parse_status_present` assertion if parse errors are represented in a consistent schema field.
- A `human_review_required` gate assertion if degradation cases need to assert review state directly rather than infer it from defects.

These additions should be narrow predicates over existing artifacts. They must not become a general graph engine and must not emit a composite score.

## Artifact Hygiene Rules

- Do not run live AWS.
- Do not copy raw live benchmark archives.
- Do not commit Terraform state, `.terraform/`, provider binaries, `collect/`, `run.log`, `scenario.json`, `findings.json`, or `binding_metadata.json` unless a later explicitly approved fixture slice needs tiny synthetic copies.
- Prefer generated `tmp_path` fixtures in tests.
- If a repo-local frozen degradation snapshot is added, include evaluated summary artifacts only.

## Validation Strategy

First implementation pass should run:

- `bash -n` for any new wrapper script.
- Targeted pytest for degradation benchmark scorer/gate tests.
- `./scripts/check.sh`.
- `./scripts/test_fast.sh`.

If later work touches reasoner behavior or validation semantics, expand to the relevant reasoner tests and `./scripts/test_full.sh`.

## Exact Build Prompt For First Implementation Pass

Work from current `origin/main` in a fresh branch.

Mission: implement the first degradation benchmark reporting/gate slice using synthetic frozen-artifact fixtures only.

Scope:

- Add DEG07 missing-artifact gate tests proving missing `scenario_json` or `findings_json` produces `artifact_insufficient`, `promotion_blocked=true`, and `human_review_required=true`.
- Add DEG01 missing-trust-edge synthetic case proving an Env06-like positive path does not validate when the trust edge is absent.
- Add DEG02 missing-permission-edge synthetic case proving an Env06-like positive path does not validate when the permission edge is absent.
- Add docs or case manifests only as needed for these three cases.

Guardrails:

- Do not run live AWS.
- Do not change IAMScope reasoner logic.
- Do not create a composite score.
- Do not copy raw archives or run artifacts.
- Missing evidence must be explicit in scorer/gate/report output.

Validation:

- Targeted degradation tests.
- `./scripts/check.sh`.
- `./scripts/test_fast.sh`.
