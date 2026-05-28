# Public Visibility Change Readiness Checklist

## Purpose

Provide the final operational readiness checklist before changing IAMScope repository visibility.

This is a docs/checklist slice only. It does not make the repository public, create or modify GitHub release settings, create or move tags, run live AWS, call `iam:PassRole`, call STS, call Lambda APIs, create or modify AWS resources, generate reports, commit `/tmp` outputs, change implementation, add pass/fail labels, add composite scoring, or broaden IAMScope claims.

## Preconditions

Before any visibility change, confirm:

- [ ] Public release readiness verdict reviewed: `ready_for_public_research_preview`.
- [ ] `README.md` reviewed.
- [ ] `docs/START_HERE.md` reviewed.
- [ ] `docs/specs/supported-unsupported-evidence-matrix.md` reviewed.
- [ ] Release notes reviewed.
- [ ] GitHub prerelease reviewed.
- [ ] `./scripts/check.sh` passed.
- [ ] `./scripts/test_fast.sh` passed.
- [ ] `git status` is clean.
- [ ] No raw AWS artifacts are staged, committed, or attached.
- [ ] No credentials, access keys, tokens, or credential-shaped values are staged, committed, or attached.
- [ ] No `/tmp` outputs are staged, committed, or attached.
- [ ] No generated bundles, decks, ZIP files, or reports are attached by default.
- [ ] No Terraform state/cache/provider artifacts are staged, committed, or attached.
- [ ] No production-readiness, broad-correctness, exploitability, real-world scalability, pass/fail, or composite-score claims are introduced.

## Evidence Claims Visible

Public-facing materials should visibly state:

- IAMScope is a research preview.
- IAMScope is a bounded evidence program.
- Evidence covers selected AWS IAM escalation patterns.
- Controlled STS and PassRole evidence exists.
- Active PassRole-to-Lambda was one controlled service-mediated Lambda `CreateFunction` result.
- Active PassRole-to-Lambda used no invocation and verified cleanup.
- IAMScope does not claim production readiness.
- IAMScope does not claim broad correctness.
- IAMScope does not claim exploitability.
- IAMScope does not claim all findings are verified.
- IAMScope does not claim a composite benchmark score.

## GitHub Visibility-Change Steps

Operational steps to perform only after explicit approval:

- [ ] Navigate to the GitHub repository settings.
- [ ] Locate the repository visibility setting.
- [ ] Change visibility from private to public.
- [ ] Confirm GitHub warning dialogs deliberately.
- [ ] Verify the public repository URL loads.
- [ ] Verify `README.md` renders correctly on the public page.
- [ ] Verify `docs/START_HERE.md` is reachable from the README.
- [ ] Verify `docs/specs/supported-unsupported-evidence-matrix.md` is reachable from the README or START_HERE path.
- [ ] Verify the existing release page renders.
- [ ] Verify no artifacts are attached unexpectedly.

This checklist documents the steps only; it does not perform the visibility change.

## Immediate Post-Public Checks

After visibility changes, check:

- [ ] Public repository page opens in a browser.
- [ ] README links render and resolve.
- [ ] START_HERE link resolves.
- [ ] Evidence matrix link resolves.
- [ ] Release page opens and still presents research/evidence checkpoint framing.
- [ ] Issues settings are as intended.
- [ ] Discussions settings are as intended.
- [ ] GitHub secret scanning alerts, if available, show no new blockers.
- [ ] No raw artifacts, credentials, `/tmp` outputs, generated bundles, decks, Terraform state/cache/provider artifacts, or raw logs are exposed unexpectedly.

## Rollback / Pause Plan

If something looks wrong:

- [ ] Immediately switch the repository back to private if needed.
- [ ] Remove, disable, or draft the release if needed.
- [ ] Do not delete evidence docs blindly.
- [ ] Document the issue before patching.
- [ ] Create a focused follow-up branch for the specific issue.
- [ ] Re-run `./scripts/check.sh`, `./scripts/test_fast.sh`, and `git diff --check` after any repo patch.

## Communication Guidance

If announcing publicly, use bounded language:

- Say: research preview.
- Say: evidence checkpoint.
- Say: bounded evidence program for selected AWS IAM escalation patterns.
- Say: not production ready.
- Say: active PassRole-to-Lambda was one controlled service-mediated `CreateFunction` result with no invocation and verified cleanup.
- Avoid: exploitability proven.
- Avoid: enterprise validated.
- Avoid: production ready.
- Avoid: broadly correct.
- Avoid: all findings verified.
- Avoid: real-world scalable.
- Avoid: composite score or pass/fail grade.

## Recommended Next Slice

Recommend exactly one next slice: make IAMScope repository public as research preview.

That next slice should be manual/operational, not code. It must not recommend more validation before visibility change unless a blocker is found, production testing, live AWS, CI gates, composite scoring, or multiple slices at once.