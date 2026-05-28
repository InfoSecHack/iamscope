# IAMScope Truth Contract

This document is the source of truth for the Phase 0-2 IAMScope truth contract.
It keeps graph structure separate from runtime evidence.

## Principle

Configuration is a hypothesis. Static IAM policy, trust policy, permissions
boundary, and SCP data describe declared structure, not runtime truth.

The IAM simulator is advisory. It can help explain a request, but it is not a
substitute for live validation and can miss ambient organization controls or
request-shape differences.

A live probe is the strongest evidence IAMScope can record, but it belongs in a
sidecar with timestamped evidence, not in `scenario.json` graph structure.

Inherited organization controls can confound a validation surface. If an OU or
root-level SCP broadly governs `sts:AssumeRole`, a runtime lab may not cleanly
validate the local policy mechanism being studied.

## States

- `declared_state`: what the graph declares for an edge, currently `allow` or
  `unknown` in the edge-truth view.
- `simulator_state`: advisory simulator result from a probe overlay.
- `validated_state`: runtime result from a probe overlay.
- `evidence_level`: strength of the current evidence.
- `confounded`: whether inherited org controls make the validation surface
  unsuitable for a clean runtime claim.

All state values are closed enums in `iamscope.constants`.

## Sidecar Rule

`scenario.json` schema and edge IDs are preserved. Runtime truth must not be
added to edge features, constraint properties, or metadata fields. New truth and
probe state is stored in sidecars keyed by stable `edge_id` and anchored to
`metadata.canonical_hash`.

The Phase 1 sidecar is `probe_overlay.json` with:

- `schema_version`
- `engagement_run_id`
- `scenario_canonical_hash`
- `generated_at_utc`
- `probes[]`

Each probe records its `edge_id`, `action_class`, `probe_kind`, `probe_state`,
optional simulator/runtime/cloudtrail states, confounder fields, and cited
control references.

## Confounded Detection

Phase 2 supports one action class: `sts:AssumeRole`.

An account or edge is confounded when inherited effective SCPs heuristically
include a Deny or NotAction Deny that broadly governs `sts:AssumeRole` for the
account or edge under study.

The evidence level for this first pass is `heuristic` unless a later validation
phase supplies stronger evidence.

## Operator Surface

`iamscope edge-truth` joins:

- `scenario.json`
- optional `binding_metadata.json`
- optional `probe_overlay.json`

It prints declared, simulated, validated, and confounded state for a single
source/target/action edge. It does not modify ARF-RT and does not change the
scenario schema.
