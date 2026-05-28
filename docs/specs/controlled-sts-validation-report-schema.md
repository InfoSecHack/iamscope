# Controlled STS Validation Report Schema Spec

## Purpose

Define the minimal schema for one controlled STS finding/path validation report.
The schema is a documentation target only; it does not implement parsing,
validation, live AWS execution, or benchmark behavior.

## Scope

- Add a schema design document for a single controlled STS validation result.
- Keep the report scoped to one controlled environment, one selected IAMScope
  finding/path, one STS probe/evidence check, one outcome classification, and
  one safe evidence summary.
- Preserve artifact hygiene and explicit non-claims from the controlled
  real-environment validation protocol.

## Acceptance Criteria

- The schema defines required top-level fields, finding references, predicted
  behavior, runtime probe fields, observed behavior, outcome classifications,
  artifact safety fields, caveats, non-claims, and a sanitized example.
- Future validation rules reject unsafe fields such as raw credentials,
  `composite_score`, and pass/fail fields.
- The recommended next slice is limited to a shape-only schema validator and
  does not run AWS.
