# Prod-Like Oracle I001 Mismatch Triage

## Purpose

Forensically triage the current v3/current-main comparator mismatch for
`oracle-i-001` without changing oracle expectations, comparator logic, Terraform
fixture code, reasoner behavior, or benchmark claims.

## Decision

Decision: `fixture_should_change_to_make_row_truly_inconclusive`.

`oracle-i-001` should remain expected `inconclusive` for now. The emitted
`blocked` finding is supported by complete-confidence permission boundary
evidence in the current Terraform fixture shape, but that boundary conflicts
with the row's intended uncertainty model.

This is not treated as an IAMScope false positive in this slice. It is also not
treated as a benchmark improvement by changing the oracle expectation to match
the current emitted verdict.

## Intended Oracle Model

The oracle row describes a wildcard target resource-scope uncertainty case:

- row: `oracle-i-001`;
- expected category: `inconclusive`;
- expected IAMScope behavior: emit inconclusive or preserve uncertainty;
- source: `iamscope-prodlike-v1-uncertainty-probe`;
- target: `iamscope-prodlike-v1-lambda-exec-scoped`;
- reason: target resource scope cannot be proven specific enough.

The Terraform oracle metadata for the same row labels the resource group as
`wildcard_resource_scope_unknown` and notes that it must remain inconclusive
unless resolved.

## Terraform Fixture Evidence

The live Terraform fixture currently attaches a permission boundary to the
shared `uncertainty_probe` source principal:

```hcl
source_permission_boundary_keys = {
  boundary_probe    = "passrole_lambda"
  uncertainty_probe = "session_context"
}
```

The same `uncertainty_probe` source has the `oracle-i-001` wildcard policy
shape:

```hcl
sid       = "OracleI001WildcardResourceScopeUnknown"
effect    = "Allow"
actions   = ["iam:PassRole", "lambda:CreateFunction"]
resources = ["*"]
```

The attached boundary policy allows only IAM read/list actions:

```hcl
actions = ["iam:GetRole", "iam:ListRolePolicies", "iam:GetPolicy", "iam:GetPolicyVersion"]
```

That boundary shape blocks `lambda:CreateFunction` and `iam:PassRole` with
complete confidence before the intended wildcard-resource uncertainty can remain
the decisive outcome for `oracle-i-001`.

## Emitted Finding Evidence

The v3/current-main finding for the selected source and target emitted:

- pattern: `passrole_lambda`;
- source: `iamscope-prodlike-v1-uncertainty-probe`;
- target: `iamscope-prodlike-v1-lambda-exec-scoped`;
- verdict: `blocked`;
- failed check: `no_boundary_blocks_lambda_create_function`;
- failed check: `no_boundary_blocks_passrole`;
- control kind: permission boundary;
- governance confidence: complete.

The same finding preserved the intended wildcard evidence as unknown source
preconditions:

- `source_has_lambda_create_function`: unknown because the matching edge has
  ambiguity from hyperedge, wildcard resource, or conditions;
- `source_has_passrole_to_target`: unknown because the matching edge has
  ambiguity from hyperedge, wildcard resource, or conditions.

The complete-confidence boundary blocker is therefore real evidence from the
fixture, not a comparator artifact.

## Why the Oracle Is Not Changed to Blocked

Changing `oracle-i-001` to expected `blocked` would make the current comparison
look cleaner, but it would erase the row's stated purpose: preserving wildcard
target resource-scope uncertainty.

The row is not a boundary-blocked PassRole case. The fixture already has a
separate boundary-blocked PassRole-to-Lambda row for that purpose. The current
mismatch is caused by reusing `uncertainty_probe` for multiple uncertainty
shapes while attaching a complete-confidence boundary that applies globally to
that source principal.

## Why This Is Not a Reasoner Bug

The reasoner observed a permission boundary on the source principal and emitted
`blocked` because complete-confidence boundary bindings applied to both
`lambda:CreateFunction` and `iam:PassRole` witness edges.

Given the current fixture, that is the conservative and explainable result. No
reasoner change is made or recommended in this slice.

## Required Fixture Correction

A later Terraform/oracle fixture slice should make `oracle-i-001` truly
inconclusive again without weakening the comparator:

- split `uncertainty_probe` into separate source principals for wildcard
  resource-scope uncertainty and session/boundary-context uncertainty; or
- remove the complete-confidence permission boundary from the
  wildcard-resource-scope source while preserving the intended wildcard
  `iam:PassRole` and `lambda:CreateFunction` resource shape; or
- model a genuinely unresolved boundary/session context if that is the intended
  uncertainty source, without producing complete-confidence boundary blockers
  for `oracle-i-001`.

After the fixture correction, rerun the controlled prod-like apply, collection,
comparison, destroy, cleanup, and artifact-hygiene workflow before changing
current evidence claims.

## Current Comparison Result

The current comparison result remains unchanged:

- `oracle-i-001`: expected `inconclusive`, emitted `blocked`;
- comparison category: `oracle_mismatch`;
- overall comparator summary remains the v3/current-main checkpoint summary.

## Non-Claims

- not broad IAMScope correctness
- not production readiness
- not full oracle success
- not production AWS
- not exploitability proof
- not downstream authorization proof
- not Lambda invocation behavior
- not generic Deny correctness
- not v2/v3 cross-version ID compatibility
- no composite benchmark score
- no pass/fail benchmark label
