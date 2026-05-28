# Controlled STS Validation Report Generator Spec

## Purpose

Implement a minimal offline generator that converts already-sanitized STS proof
summary facts into one controlled STS validation report JSON file.

## Scope

- Support the committed sanitized `denied` and `assumed` proof summaries only.
- Write the generated report to a caller-provided path.
- Validate the generated report with the existing controlled STS validation
  report validator before returning success.
- Refuse repo-local output by default.

## Non-Goals

- No live AWS.
- No STS AssumeRole calls.
- No raw `/tmp` proof output reads.
- No raw AWS artifact, credential, or log ingestion.
- No controlled validation execution.
- No benchmark framework, executor, dry-run validator, collector, reasoner,
  scorer, scenario-validation, threshold, comparator, reporting, or harness
  changes.
- No committed generated reports, CI gates, pass/fail labels, or composite
  scoring.
