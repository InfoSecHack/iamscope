# Controlled STS Validation Report Validator Spec

## Purpose

Implement a minimal report-shape validator for one controlled STS validation
report JSON file.

## Scope

- Parse JSON only.
- Validate the controlled STS validation report shape and safety boundaries.
- Reject unsafe credential-shaped fields, composite scoring, pass/fail fields,
  unsupported classifications, unsafe artifact flags, and missing non-claims.
- Emit a safe validation summary to stdout.

## Non-Goals

- No live AWS.
- No STS AssumeRole calls.
- No controlled validation execution.
- No benchmark framework.
- No executor, dry-run validator, collector, reasoner, scorer,
  scenario-validation, threshold, comparator, reporting, or harness changes.
- No generated reports, raw artifacts, fixtures unrelated to validator tests, CI
  gates, pass/fail labels, or composite scoring.
