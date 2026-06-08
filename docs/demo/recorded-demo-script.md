# Recorded Demo Script

Target length: 7-10 minutes.

## 0:00-1:00 — Concrete Finding First

Open [`sanitized-finding-card.md`](sanitized-finding-card.md).

Say:

> “IAMScope helps cloud security teams turn messy AWS IAM relationships into evidence-backed attack-path findings a reviewer can actually act on.”

Show the card fields first:

- Source: `ExternalOrBroadPrincipalAlias`.
- Target: `ProdDeployRoleAlias`.
- Pattern: `cross_account_trust`.
- Verdict: `validated`.
- Reviewer label: `valid_path`.
- Owner confirmed: `true`.
- Collection context: `complete`.

Say:

> “This is a sanitized presentation artifact, not raw findings.json. Validated does not mean exploited, but it does mean IAMScope has enough modeled evidence to send this trust relationship to an owner for review.”

## 1:00-2:00 — Positioning: Pacu vs PMapper vs IAMScope

Show [`iamscope-vs-pacu-pmapper.md`](iamscope-vs-pacu-pmapper.md).

Talk track:

- Pacu is useful as an offensive AWS exploitation and attack-module framework.
- PMapper is useful for IAM graph/query work, local authorization simulation, and privilege-escalation path mapping.
- IAMScope is narrower: it turns collection or replay into findings with verdicts, required checks, blockers, `collection_context`, capability honesty, human labels, and owner-confirmation trail.

Do not disparage Pacu or PMapper. They solve different jobs.

## 2:00-2:45 — Capability-Honesty Matrix

Open [`../reference/capability-honesty-matrix.md`](../reference/capability-honesty-matrix.md).

Call out:

- modeled areas;
- unsupported or static-only areas;
- places where IAMScope refuses to turn missing evidence into a stronger claim;
- why no composite score and no pass/fail benchmark label are used.

Say:

> “The matrix is part of the product. It tells reviewers what not to believe.”

## 2:45-4:15 — Real-Pilot Case Study And Final Calibrated Replay

Open [`../case-studies/real-pilot-dev-001-human-review-summary.md`](../case-studies/real-pilot-dev-001-human-review-summary.md).

Show the final calibrated replay:

- 18 findings.
- 18 validated.
- 15 `cross_account_trust`.
- 3 `admin_reachability`.
- 18 labeled.
- 14 `valid_path`.
- 3 `expected_benign`.
- 1 `needs_more_evidence`.
- 5 `owner_confirmed`.
- complete `collection_context`.

Say:

> “This is bounded real-pilot evidence. It is not production readiness, exploitability proof, or full IAM safety.”

## 4:15-5:45 — Cross-Account Trust Finding

Return to [`sanitized-finding-card.md`](sanitized-finding-card.md) or walk through one `cross_account_trust` row from sanitized local review material if it is present locally. If the raw or sanitized table is not available, use the committed sanitized card and case-study summary instead.

Explain:

- the finding is a trust-structure review row;
- wildcard-principal trust findings were repeatedly classified as `valid_path`;
- expected-benign rows are still useful because they represent real structures owners may need to confirm;
- owner-confirmed rows strengthen reviewability but do not create a full owner-confirmed truth set.

Avoid showing raw account IDs or raw IAM/STS ARNs unless the demo owner explicitly authorizes it.

## 5:45-7:15 — Admin Reachability Finding

Walk through one `admin_reachability` row from the sanitized local review material if present.

Explain the calibrated evidence chain:

- source role has `sts:AssumeRole` to `ProdDBAdminRole`;
- the target trust is conditioned account-root trust narrowed by `aws:PrincipalArn`;
- the admin witness is AWS-managed `AdministratorAccess`;
- `clean_witness_check` is pass;
- `source_has_assume_role`, `reaches_at_least_one_admin`, and `walk_terminated_within_depth_limit` are pass.

Say:

> “Validated does not mean exploited. It means IAMScope’s modeled checks for this finding passed under the current bounded evidence.”

## 7:15-8:15 — Collection Context And Non-Claims

Show that `collection_context` is complete:

- `graph_collection_complete`: true.
- `has_collection_failures`: false.
- `has_policy_parse_failures`: false.

Then read the non-claims:

- no production readiness.
- no exploitability proof.
- no full IAM safety.
- no full AWS authorization semantics.
- no complete IAM privilege-escalation coverage.
- no composite score.
- no pass/fail benchmark label.

## 8:15-9:15 — Owner-Confirmation Layer

Explain why owner-confirmation matters:

- labels are human review, not an automatic truth oracle;
- five priority trust findings were owner-confirmed;
- owner confirmation is bounded to those findings only;
- this creates a review trail without claiming broad IAMScope correctness.

## 9:15-10:00 — Close

Close with:

> “IAMScope does not prove the account is safe. It gives a reviewer evidence they can act on.”

Then repeat:

> “No findings does not mean safe. Validated does not mean exploited. The demo evidence is bounded.”
