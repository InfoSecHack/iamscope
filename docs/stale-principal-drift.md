# Stale Principal Unique-ID Drift

AWS IAM trust and resource policies can contain immutable principal unique IDs
after a referenced role or user is deleted. Common shapes are bare `AROA...`
role IDs and `AIDA...` user IDs in a policy `Principal` field. Those values are
not equivalent to the original ARN: recreating a role or user with the same name
does not make the old policy reference valid again.

IAMScope treats this as declared-policy truth evidence. A bare IAM principal
unique ID on a policy-derived edge is strong evidence that the policy reference
has drifted stale and should not be reported as cleanly reachable.

## Supported

IAMScope detects the narrow, reviewable pattern of bare IAM unique IDs:

- `AROA[A-Z0-9]+` role unique IDs
- `AIDA[A-Z0-9]+` user unique IDs
- policy-derived trust edges
- policy-derived resource-policy edges

For each match, IAMScope emits a `STALE_PRINCIPAL_DRIFT` constraint with
properties including `principal_id`, `principal_id_kind`,
`drift_state=stale_unique_id_suspected`, `evidence_level=complete`, and
statement metadata when available. The constraint is bound to the affected edge
with `likely_blocking=true` and `governance_confidence=complete`.

## Reasoner Impact

The current reasoner consumer is `assume_role_chain`. A complete stale-drift
binding on a chain trust hop blocks that chain finding instead of validating
through stale trust evidence.

Other reasoners may still see the exported scenario constraint, but they do not
currently consume it for verdict changes unless explicitly wired. Do not treat
this feature as generic identity hygiene reporting.

## Operator Inspection

Inspect evidence on a frozen scenario by edge:

```bash
iamscope stale-drift --scenario scenario.json --edge-id <edge_id>
```

If a findings file is available, inspect by stable semantic identity:

```bash
iamscope stale-drift --scenario scenario.json --findings findings.json --finding-key <finding_key>
```

## Not Supported

IAMScope does not infer stale drift from fuzzy name similarity, missing
same-account roles, CloudTrail events, IAM eventual consistency, or arbitrary
unknown principal strings. Other unresolved principal values are left alone
unless they match the bare IAM unique-ID shape.

This is static declared-policy evidence. Runtime probe overlays remain stronger
evidence when available.
