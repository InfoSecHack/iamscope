# Resource Policy Deny Closure

## Decision

Option A: keep generic `resource-policy-deny` explicitly de-scoped for this
slice.

IAMScope currently collects resource policy documents and emits graph coverage
for supported resource-policy `Allow` statements. It does not parse, bind, or
emit generic `RESOURCE_POLICY_DENY` constraints end to end.

## Current Truth State

- Parser: `iamscope/parser/resource_policy.py` only returns rows for
  `Effect: Allow` statements. `Effect: Deny` statements are ignored by this
  parser and do not become deny rows.
- Binder: `iamscope/resolver/resource_policy_binder.py` converts parsed Allow
  rows into `_resource_policy` edges. Condition-bearing Allow statements also
  produce `RESOURCE_POLICY_CONDITION` constraints with
  `governance_confidence=needs_review`.
- Pipeline: `_run_resolution` collects resource policy documents, runs the
  Allow parser, and exports Allow-derived resource-policy edges plus condition
  constraints. It does not build `RESOURCE_POLICY_DENY` constraints.
- Scenario/output: `scenario.json` can represent resource-policy Allow edges
  and condition constraints. A deny-only resource policy should not silently
  appear as a supported deny constraint.
- Reasoners: no generic reasoner consumes `RESOURCE_POLICY_DENY` constraints.
  `SecretsBlastRadiusReasoner` has a separate KMS-key-policy evaluator that
  reads collected KMS key policy JSON from KMS node properties and handles
  relevant KMS `Deny` statements for its own decrypt check. That is
  reasoner-local KMS policy logic, not generic resource-policy-deny support.
- CLI/report exposure: no CLI or report path should claim generic
  resource-policy-deny closure.

## Non-Goals

- No generic resource-policy deny engine.
- No cross-service principal/action/resource matcher for S3, KMS, Secrets
  Manager, and Lambda resource policies.
- No weakening of validation and no suppression of findings.
- No benchmark, ARF, finding-key, or stale-principal changes.

## Acceptance Criteria

- Docs state that generic resource-policy Deny is not collect/pipeline/output
  supported end to end.
- Tests prove deny-only resource policies do not create Allow edges,
  `RESOURCE_POLICY_CONDITION` constraints, or `RESOURCE_POLICY_DENY`
  constraints.
- Existing KMS key-policy reasoner behavior remains documented as a narrow,
  reasoner-local exception rather than generic deny support.
