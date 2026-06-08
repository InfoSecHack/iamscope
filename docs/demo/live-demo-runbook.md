# Live Demo Runbook

This runbook supports two demo modes: a no-AWS walkthrough and an explicitly authorized AWS walkthrough. The default and safest path is the no-AWS demo.

## Safety Boundary

- Do not run live AWS by default.
- Do not run Terraform by default.
- Do not show raw account IDs or raw IAM/STS ARNs on screen unless explicitly authorized.
- Do not commit raw `scenario.json`, `findings.json`, labels, logs, or generated review artifacts.
- Do not present any result as production readiness, exploitability proof, full IAM safety, a composite score, or a pass/fail benchmark label.

## Redaction Preflight Before Screen Sharing

Before showing repo docs or generated demo output, run safe local checks like:

```bash
grep -R --line-number -E '[0-9]{12}' docs/demo docs/case-studies docs/reference || true
grep -R --line-number -E 'arn:aws:' docs/demo docs/case-studies docs/reference || true
```

Review any hits before screen sharing. Pattern-only command examples are not raw artifacts, but raw 12-digit account IDs, raw IAM/STS ARNs, local role names, raw policy docs, and local real-pilot outputs should stay off-screen unless separately authorized and sanitized.

Do not screen-share raw `scenario.json`, `binding_metadata.json`, `findings.json`, or local real-pilot artifacts unless they have been separately sanitized.

Prefer showing:

- [`sanitized-finding-card.md`](sanitized-finding-card.md)
- [`demo-narrative-one-pager.md`](demo-narrative-one-pager.md)
- [`iamscope-vs-pacu-pmapper.md`](iamscope-vs-pacu-pmapper.md)
- [`../reference/capability-honesty-matrix.md`](../reference/capability-honesty-matrix.md)
- [`../case-studies/real-pilot-dev-001-human-review-summary.md`](../case-studies/real-pilot-dev-001-human-review-summary.md)

## Mode A — No-AWS Demo

Use this mode for recorded demos, public walkthroughs, and first-pass reviewer conversations.

Steps:

1. Open [`sanitized-finding-card.md`](sanitized-finding-card.md).
2. Open [`demo-narrative-one-pager.md`](demo-narrative-one-pager.md).
3. Open [`iamscope-vs-pacu-pmapper.md`](iamscope-vs-pacu-pmapper.md).
4. Open [`../reference/capability-honesty-matrix.md`](../reference/capability-honesty-matrix.md).
5. Open [`../case-studies/real-pilot-dev-001-human-review-summary.md`](../case-studies/real-pilot-dev-001-human-review-summary.md).
6. If a sanitized review table is present locally, show only sanitized columns and avoid raw account IDs or raw IAM/STS ARNs.

Facts to state:

- 18 findings.
- 18 validated.
- 15 `cross_account_trust`.
- 3 `admin_reachability`.
- 14 `valid_path`.
- 3 `expected_benign`.
- 1 `needs_more_evidence`.
- 5 `owner_confirmed`.
- complete `collection_context`.
- sanitized output hygiene clean.

Explain that this is evidence-grade review material, not live exploitation and not a safety certificate.

## Mode B — Authorized AWS Demo

Use this mode only in a sandbox, non-production account, or explicitly authorized environment controlled by the reviewer.

Preconditions:

- written or clearly recorded authorization;
- scoped AWS profile;
- expected account checked before collection;
- no production admin access requested;
- output path outside the repository, preferably under `/tmp`;
- redaction plan agreed before screen sharing or publication.

Suggested flow:

1. Confirm the profile and expected account out of band with the environment owner.
2. Run collection or replay only if authorized.
3. Produce sanitized reviewer output under `/tmp` or another non-repo path.
4. Run hygiene grep against generated demo output before showing or sharing it.
5. Show findings, required checks, blockers, `collection_context`, labels, and owner-confirmation status.
6. Keep raw account IDs, raw IAM/STS ARNs, raw findings, and logs off-screen unless explicitly authorized.
7. Do not commit generated artifacts.

Stop conditions:

- profile/account does not match the expected environment;
- collection emits unexpected raw artifacts into the repo tree;
- raw account IDs or raw IAM/STS ARNs would be exposed without authorization;
- reviewer asks to stop;
- any command would mutate resources without explicit approval;
- any result is being framed as exploitability proof, production readiness, or a pass/fail benchmark label.

## Hygiene Checks For Demo Outputs

Before sharing sanitized output, run equivalent local checks against the output directory:

- no raw 12-digit account IDs unless explicitly authorized;
- no raw IAM/STS ARNs unless explicitly authorized;
- no Terraform state, plan, lock file, or output JSON;
- no raw AWS logs;
- no generated artifacts committed to git.

## Demo Close

End with:

> “IAMScope is not an exploitation framework. It is an evidence-grade IAM finding workflow. No findings does not mean safe, and validated does not mean exploited.”
