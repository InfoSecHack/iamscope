# Controlled STS Validation Report Bundle Generator Spec

## Purpose

Implement a minimal safe bundle generator for controlled STS validation reports
derived from already-sanitized committed STS proof summaries.

## Scope

- Require a caller-provided output directory.
- Refuse repo-local output by default.
- Generate denied and assumed controlled STS validation reports using the
  existing report generator.
- Validate both reports with the existing report validator.
- Emit a safe Markdown index, artifact safety manifest, and validator summary.

## Non-Goals

- No live AWS.
- No STS AssumeRole calls.
- No raw `/tmp` proof output ingestion.
- No raw AWS artifact, credential, or raw log ingestion.
- No controlled validation execution.
- No benchmark framework, executor, dry-run validator, collector, reasoner,
  scorer, scenario-validation, threshold, comparator, reporting, or harness
  changes.
- No committed generated bundle outputs by default, CI gates, pass/fail labels,
  or composite scoring.
