# Controlled Real-Environment Validation Protocol Spec

## Purpose

Define a docs-only protocol for validating one selected IAMScope finding or path
against one controlled AWS test environment while preserving evidence
boundaries, artifact hygiene, and non-claims.

## Scope

- Add a protocol document for controlled real-environment validation.
- Keep this separate from frozen live corpus benchmarks, synthetic scalability,
  threshold review, and runtime STS proof records.
- Do not implement validation logic, run live AWS, call STS, create resources,
  add fixtures, or change benchmark/runtime code.

## Acceptance Criteria

- The protocol defines bounded validation question, scope, allowed evidence,
  outcome classifications, mismatch taxonomy, artifact hygiene, and minimal
  report schema.
- It evaluates candidate first validation types and recommends one first type.
- It explicitly avoids production readiness, broad correctness, broad
  exploitability, all-findings-verified, CI-gate, and composite-score claims.
- Standard slice validation passes.
