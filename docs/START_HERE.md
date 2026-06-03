# START HERE: IAMScope Reviewer Guide

## What Is IAMScope?

IAMScope is a research-preview IAM reasoning tool and bounded evidence program for selected AWS IAM escalation patterns.

It is not a production-ready oracle. The current repository is best read as a documented evidence trail: selected benchmarks, selected runtime proofs, controlled validation checkpoints, and explicit non-claims.

## What Evidence Exists?

Current evidence is bounded but concrete:

- Frozen live AWS semantic benchmark layer for selected IAM cases.
- Mutation-pair sensitivity for selected semantic deltas.
- Synthetic scalability/degradation fixtures for controlled analysis.
- Reporting/comparison layer for benchmark summaries.
- Report-only threshold review; no CI gate or pass/fail benchmark label.
- Standalone STS denied and assumed runtime proofs.
- Controlled STS selected-path denied/access_denied corroboration.
- Static PassRole report/schema validation.
- Active PassRole-to-Lambda service-mediated corroboration for one test-only case.
- Static controlled Identity Deny suppression evidence for one selected explicit
  identity-Deny case. This is static/report validation only: no live AWS was
  run, no active Deny runtime behavior was observed, and no generic Deny
  correctness is claimed.
- Artifact hygiene checks for tracked raw artifacts, Terraform state/cache/provider artifacts, gitlinks/submodules, and carriage-return filenames.

## What Does Active PassRole Corroborate?

The active PassRole-to-Lambda result is narrow:

- One test-only source principal.
- One test-only target role.
- One Lambda `CreateFunction` operation.
- `CreateFunction` succeeded.
- `GetFunctionConfiguration` succeeded.
- `DeleteFunction` succeeded.
- Post-delete `GetFunction` confirmed the function was missing.
- The function was not invoked.
- No triggers, function URL, event source mappings, aliases, versions, or downstream actions were used.
- Cleanup was verified.

This corroborates one service-mediated controlled PassRole-to-Lambda case under explicit conditions. It does not prove exploitability, downstream authorization, production readiness, or broad PassRole correctness.

## What Is Safe To Run?

For a fresh public clone, use the local-only Quick Start in
[`README.md`](../README.md). It creates a virtual environment, installs the
development extras, and runs the safe local checks. If you have already cloned
and installed the project, the local checks are:

```sh
source .venv/bin/activate
./scripts/check.sh
./scripts/test_fast.sh
```

The default reviewer path makes no AWS calls, no STS probes, no `iam:PassRole`
calls, no Lambda API calls, no service launch, and no AWS resource mutations.

Safe generated outputs, where documented, should go to `/tmp` or a caller-provided path outside the repository and should not be committed by default.

Do not run live AWS commands by default.

## How Can I Run IAMScope Safely?

Use three tiers:

### Fresh Clone Local Setup

For a fresh public clone, use the README Quick Start. It is local-only:

```sh
git clone https://github.com/InfoSecHack/iamscope.git
cd iamscope
python3 -m venv .venv
source .venv/bin/activate
python -m pip install --upgrade pip
python -m pip install -e ".[dev]"
./scripts/check.sh
./scripts/test_fast.sh
```

These commands make no AWS calls, no STS probes, no `iam:PassRole` calls, no
Lambda API calls, no service launch, and no AWS resource mutations.

### Safe Local CLI Exploration

These commands inspect local CLI help only and do not call AWS:

```sh
iamscope --help
iamscope validate --help
iamscope report --help
iamscope diff --help
iamscope why --help
```

Examples that operate on scenario, report, or diff files require existing local
fixture or sanitized scenario files. They should not perform live collection.

### Local Demo

Local demo: [Path Overcounting and Shared Uncertainty](case-studies/path-overcounting-shared-uncertainty.md) shows how IAMScope separates naive path-shaped rows from validated, blocked, precondition-only, and inconclusive fixture verdicts without making live AWS or replay-equivalence claims.

Case study: [PassRole-to-Lambda Controlled Live Validation](case-studies/passrole-lambda-controlled-live-validation.md) summarizes the two-sided controlled live validation pair: one selected allowed `CreateFunction` match and one missing-PassRole `access_denied` no-selected-finding match.

### Live AWS Collection

Live `iamscope collect` is not the default path. It is advanced/authorized only.
Use the README section "Advanced: live AWS collection requires explicit
authorization" only with explicit authorization, a scoped profile/account, and a
reviewed plan.

## What Requires Separate Approval?

These require a separate protocol and explicit approval:

- Live AWS access.
- STS probes.
- `iam:PassRole`.
- Lambda `CreateFunction`, `GetFunction`, `GetFunctionConfiguration`, or `DeleteFunction`.
- Service launch or invocation.
- AWS resource creation or modification.
- Raw artifact handling or raw AWS log handling.
- Credential/profile creation or teardown.

## What Is Not Claimed?

IAMScope does not claim:

- Production readiness.
- Broad IAMScope correctness.
- Arbitrary enterprise graph correctness.
- Broad runtime exploitability.
- Downstream authorization proof.
- Generic Deny correctness.
- Generic resource-policy Deny support.
- SCP Deny support unless explicitly scoped.
- Active Identity Deny runtime validation.
- Finding-level reachability unless explicitly scoped.
- All findings verified.
- Real-world scalability.
- Composite benchmark score.
- Pass/fail benchmark label or CI threshold gate validity.

## Reviewer Reading Order

Read in this order:

1. [`README.md`](../README.md) — project framing, safe quickstart, and non-claims.
2. [`docs/specs/supported-unsupported-evidence-matrix.md`](specs/supported-unsupported-evidence-matrix.md) — current supported, bounded, and unsupported evidence areas.
3. [`BENCHMARK_STATUS.md`](../BENCHMARK_STATUS.md) — benchmark status and bounded evidence notes.
4. [`docs/specs/controlled-passrole-active-run-001-result-and-teardown-checkpoint.md`](specs/controlled-passrole-active-run-001-result-and-teardown-checkpoint.md) — active PassRole-to-Lambda result and teardown.
5. [`docs/specs/controlled-identity-deny-run-001-static-validation-checkpoint.md`](specs/controlled-identity-deny-run-001-static-validation-checkpoint.md) — static Identity Deny report-validation boundary.
6. [`docs/specs/controlled-sts-run-002-live-result-checkpoint.md`](specs/controlled-sts-run-002-live-result-checkpoint.md) — selected controlled STS denied/access_denied result.

### Optional Background

- [`docs/releases/research-checkpoint-release-notes.md`](releases/research-checkpoint-release-notes.md) — research/evidence checkpoint release notes.
- [`docs/specs/release-hygiene-checkpoint.md`](specs/release-hygiene-checkpoint.md) — release-facing hygiene status.
- [`docs/specs/github-prerelease-publication-checkpoint.md`](specs/github-prerelease-publication-checkpoint.md) — published prerelease checkpoint.
- [`docs/archive/BENCHMARK_RUNTIME_STS_PROOF_MATURITY_CHECKPOINT.md`](archive/BENCHMARK_RUNTIME_STS_PROOF_MATURITY_CHECKPOINT.md) — archived runtime-proof maturity background material, not first-read reviewer guidance.

## Artifact Safety

Reviewer and release-facing boundaries:

- No raw AWS artifacts should be committed.
- No credentials, access keys, tokens, or credential-shaped values should be committed.
- No `/tmp` outputs should be committed.
- No Terraform state/cache/provider artifacts should be committed.
- Generated reports, bundles, ZIP files, and summaries are not committed by default.
- Artifact hygiene checks are part of `./scripts/check.sh`.

## Reviewer Boundary

Use this guide for orientation only. Do not use it to authorize live AWS, new
validation, production testing, broad validation, CI gates, composite scoring,
or multiple follow-on work.
