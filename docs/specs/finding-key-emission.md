# Finding Key Emission

## Goal

Emit a stable `finding_key` on every `findings.json` finding so replay and
semantic diffs can join the same finding across proof/evidence changes.

## Contract

`finding_key` is a lowercase SHA-256 hex digest over canonical JSON containing:

- `pattern_id`
- `scenario_hash`
- `source` node reference
- `target` node reference

It deliberately excludes `pattern_version`, `verdict`, `severity`, evidence,
reasoning trace, blockers, assumptions, and `finding_id`.

## Behavior

- `finding_id` remains the evidence-sensitive identity and may change when a
  probe overlay, trace, or evidence bundle changes.
- `finding_key` remains stable for the same pattern/source/target relation
  within the same scenario, even when verdict or evidence changes.
- `findings_diff` requires explicit `finding_key` fields and rejects findings
  documents that omit them instead of reconstructing legacy fallback keys.

## Non-Goals

- No change to reasoner verdict logic.
- No benchmark, ARF, stale-principal, or resource-policy-deny scope changes.
- No compatibility fallback for old `findings.json` files without
  `finding_key`.
