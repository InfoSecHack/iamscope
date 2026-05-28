# Private Reviewer Request Note

## Purpose

Provide a reusable note for inviting selected trusted reviewers to review IAMScope before public release.

This is a docs/writing slice only. It does not make the repository public, run live AWS, call `iam:PassRole`, call STS, call Lambda APIs, change implementation, generate reports, commit `/tmp` outputs, add pass/fail labels, add composite scoring, or broaden IAMScope claims.

## Short Reviewer Invitation

Subject: Private review request: IAMScope research-preview evidence checkpoint

Hi <reviewer>,

I’m preparing IAMScope for a possible public research-preview release and would value a private technical review first.

IAMScope is an AWS IAM reasoning tool and bounded evidence program for selected escalation patterns. It is not production ready and does not claim broad IAM correctness, broad exploitability, or generic Deny correctness. The current evidence includes frozen benchmark cases, mutation-pair checks, standalone and controlled STS evidence, static PassRole report validation, one active service-mediated PassRole-to-Lambda `CreateFunction` result with no invocation and verified cleanup, and one controlled Identity Deny static validation where the report passed schema/safety validation.

The Identity Deny evidence is deliberately narrow: no live AWS was run for that slice, no active Deny behavior was observed, and no generic Deny correctness is claimed.

Could you take a look at the reviewer docs and tell me whether the claims, evidence boundaries, and limitations are clear enough for a public research preview after private feedback?

Suggested first pass:

1. `README.md`
2. `docs/START_HERE.md`
3. `docs/specs/supported-unsupported-evidence-matrix.md`
4. `docs/specs/controlled-identity-deny-run-001-static-validation-checkpoint.md`
5. `docs/specs/controlled-passrole-active-run-001-result-and-teardown-checkpoint.md`
6. `docs/specs/controlled-sts-run-002-live-result-checkpoint.md`
7. `docs/releases/research-checkpoint-release-notes.md`

The default local check path is:

```sh
source .venv/bin/activate
./scripts/check.sh
./scripts/test_fast.sh
```

Please do not run live AWS, `iam:PassRole`, STS probes, Lambda APIs, or resource-changing actions as part of this review unless separately discussed.

The main question: would you consider this ready to share publicly as a research preview after private feedback, and if not, what would block that?

Thanks.

## What Reviewers Should Look At

Ask reviewers to inspect:

- `README.md`.
- `docs/START_HERE.md`.
- `docs/specs/supported-unsupported-evidence-matrix.md`.
- `docs/specs/controlled-identity-deny-run-001-static-validation-checkpoint.md`.
- `docs/specs/controlled-passrole-active-run-001-result-and-teardown-checkpoint.md`.
- `docs/specs/controlled-sts-run-002-live-result-checkpoint.md`.
- `docs/releases/research-checkpoint-release-notes.md`.
- Artifact hygiene and test status, especially `./scripts/check.sh`, `scripts/check_benchmark_artifact_hygiene.sh`, and `./scripts/test_fast.sh`.

## Evidence Delta For Reviewers

The reviewer note now includes the Identity Deny evidence delta:

- Controlled identity Deny Run #1 static validation exists.
- The selected Env03 identity-Deny candidate was represented as a controlled identity Deny validation report.
- The report passed schema/safety validation.
- No live AWS was run for that evidence slice.
- No active Deny runtime behavior was observed.
- No generic Deny correctness is claimed.

Active PassRole-to-Lambda should remain framed narrowly:

- One controlled service-mediated PassRole-to-Lambda `CreateFunction` result.
- No Lambda invocation.
- Cleanup verified.
- No exploitability or downstream authorization claim.

## Questions For Reviewers

Suggested questions:

- Are the claims too strong for the evidence shown?
- Is the evidence matrix clear?
- Is Identity Deny evidence framed narrowly enough?
- Is it clear that Identity Deny evidence is static/report validation, not active runtime Deny validation?
- Are unsupported Deny areas visible enough, including generic Deny correctness, resource-policy Deny, SCP Deny, and active Deny runtime validation?
- Are active PassRole and STS evidence framed correctly?
- Is active PassRole-to-Lambda framed correctly as one controlled service-mediated result with no invocation and verified cleanup?
- Are limitations obvious?
- Is the quickstart safe and clearly local by default?
- Would you consider this ready for public research preview after private feedback?
- What would block public release?
- What would make this more trustworthy?
- Are artifact safety boundaries clear?
- Are there confusing or stale reviewer paths?

## Explicit Framing

Use this framing consistently:

- IAMScope is a research preview.
- IAMScope is not production ready.
- IAMScope does not claim broad exploitability.
- IAMScope does not claim broad IAM correctness.
- IAMScope does not claim generic Deny correctness.
- IAMScope currently presents selected controlled evidence only.
- Identity Deny evidence is static/report validation only, not active runtime Deny validation.
- Active PassRole-to-Lambda evidence is one service-mediated `CreateFunction` result with no invocation and verified cleanup.
- STS evidence is selected and bounded, not all-findings verification.
- No composite benchmark score or pass/fail grade is claimed.

## Suggested Reviewer Types

Good private reviewers include:

- AWS/IAM security engineer.
- Cloud red teamer.
- Detection or blue team engineer familiar with IAM.
- Research-minded security engineer.

## Recommended Next Slice

Recommend exactly one next slice: send private reviewer request to selected reviewers and collect feedback.

That next slice should be communication/coordination only. It must not recommend public release immediately, more live validation before reviewer feedback, production testing, CI gates, composite scoring, or multiple slices at once.
