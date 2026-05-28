# Benchmark Controlled Real-Environment Validation Protocol

## 1. Purpose

This protocol defines how IAMScope can validate selected findings or paths
against a controlled AWS test environment without claiming production readiness,
broad IAMScope correctness, arbitrary enterprise graph correctness, real-world
scalability, or verification of all findings.

The goal is bounded corroboration. A controlled real-environment validation can
ask whether one selected IAMScope prediction is supported, contradicted, or left
unresolved by one carefully scoped runtime evidence check under explicit test
conditions.

This evidence track is separate from:

- Frozen live AWS semantic benchmark cases.
- Mutation-pair sensitivity checks.
- Synthetic scalability and degradation fixtures.
- Offline reporting and comparator evidence.
- Report-only threshold review.
- Runtime STS proof records.

## 2. Non-Goals

This protocol is not:

- Implementation.
- Live AWS execution in this PR.
- Production testing.
- Broad enterprise validation.
- Verification that all findings are correct.
- Exploitability proof for arbitrary paths.
- CI gating.
- Composite scoring.

It also does not add Terraform, fixtures, benchmark framework behavior,
collector logic, reasoner logic, scorer logic, scenario-validation logic,
threshold logic, comparator logic, reporting logic, or harness logic.

## 3. Validation Question

Core validation question:

When IAMScope predicts a selected path or finding in a controlled AWS
environment, does bounded runtime evidence corroborate, refute, or leave
unresolved that prediction?

The answer must stay tied to the selected finding, selected environment,
selected input bundle, selected probe or evidence check, and explicit test
conditions. It must not be generalized into broad correctness, production
readiness, or exploitability.

## 4. Scope Of First Validation

The first controlled real-environment validation should be limited to:

- One controlled AWS account or lab environment.
- One selected IAMScope finding or path.
- One runtime probe or evidence check.
- One frozen input bundle.
- One validation report.
- No broad scan.
- No production resources.

The first validation should not expand the benchmark corpus, create a broad
runtime validation framework, or accumulate environments for breadth.

## 5. Evidence Sources

Allowed evidence sources:

- Frozen sanitized collection bundle.
- IAMScope finding or path output.
- Selected runtime probe output.
- Safe AWS metadata summaries.
- Manually reviewed trust and permission context.

Forbidden evidence sources unless separately frozen, sanitized, and approved:

- Raw credentials.
- Raw AWS debug logs.
- Terraform state.
- Uncontrolled collect directories.
- Raw `scenario.json`, `findings.json`, `binding_metadata.json`, or `run.log`.
- Screenshots with secrets.
- Broad enumeration output.

Evidence must be summarized in a way that lets reviewers understand the
validation without exposing sensitive runtime material.

## 6. Validation Outcome Classifications

Allowed outcome classifications:

- `corroborated`: bounded runtime evidence supports the selected IAMScope
  prediction under the stated conditions.
- `refuted`: bounded runtime evidence contradicts the selected IAMScope
  prediction under the stated conditions.
- `inconclusive`: runtime evidence was collected, but it does not clearly
  support or contradict the prediction.
- `environment_mismatch`: the runtime environment does not match the frozen
  input bundle or documented assumptions.
- `probe_harness_issue`: the probe or evidence check failed in a way that
  prevents interpreting the prediction.
- `evidence_gap`: required evidence is missing or insufficient for a bounded
  conclusion.
- `tool_bug_candidate`: the result suggests an IAMScope implementation or
  reasoning defect that needs investigation.
- `model_limitation`: the result is outside the supported IAMScope model or
  documented evidence boundary.

Avoid these labels:

- `pass`
- `fail`
- `vulnerable`
- `exploited`
- `production_ready`

## 7. Mismatch Taxonomy

When prediction and observation do not align, classify the mismatch before
assigning broad blame. Candidate mismatch causes include:

- Tool or reasoner bug.
- Collector or import issue.
- Stale artifact.
- Runtime probe issue.
- AWS eventual consistency.
- Environment drift.
- Unmodeled policy condition.
- Unsupported resource-policy Deny behavior.
- Benchmark or protocol design flaw.

The report should distinguish confirmed causes from hypotheses. A mismatch may
produce a `tool_bug_candidate` or `model_limitation`, but only after ruling out
environment, artifact, and probe issues as far as the evidence allows.

## 8. Artifact Hygiene

Artifact rules:

- Write outputs to `/tmp` or a caller-provided safe path by default.
- Commit no raw artifacts.
- Commit no credentials, tokens, or secrets.
- Commit no Terraform artifacts.
- Commit no raw AWS logs.
- Use safe redacted summaries only.
- Require separate review before committing any validation summary.

Generated runtime evidence must not be copied into the repository by default.
Any committed summary must preserve the evidence boundary, non-claims, and
artifact-safety status.

## 9. Minimal Report Schema

A future validation report should include:

```json
{
  "validation_id": "controlled-real-env-001",
  "environment_label": "test-lab-placeholder",
  "input_bundle_reference": "frozen-sanitized-bundle-reference",
  "finding_id": "finding-or-path-id-placeholder",
  "path_id": "optional-path-id-placeholder",
  "predicted_behavior": "selected IAMScope prediction",
  "runtime_probe_type": "sts_assume_role | passrole_no_downstream | identity_deny | stale_principal_drift",
  "observed_behavior": "bounded observed behavior summary",
  "outcome_classification": "corroborated | refuted | inconclusive | environment_mismatch | probe_harness_issue | evidence_gap | tool_bug_candidate | model_limitation",
  "evidence_summary": {
    "sanitized_inputs": "safe summary only",
    "runtime_observation": "safe summary only",
    "manual_context_review": "safe summary only"
  },
  "caveats": [
    "one selected finding/path only",
    "one controlled environment only"
  ],
  "non_claims": [
    "no production readiness",
    "no broad IAMScope correctness",
    "no broad runtime exploitability"
  ],
  "artifact_safety_status": {
    "raw_credentials_committed": false,
    "raw_aws_logs_committed": false,
    "terraform_artifacts_committed": false,
    "raw_collect_outputs_committed": false,
    "safe_summary_review_required": true
  }
}
```

The schema is a design target only. It does not implement validation logic.

## 10. First Candidate Validation Types

### A. STS AssumeRole Finding/Path Corroboration

Evidence value: High for a selected trust/permission path because the runtime
check maps directly to a bounded `sts:AssumeRole` prediction.

Safety: Strong if the probe remains limited to one AssumeRole attempt, uses a
test account, emits no credentials, and performs no downstream AWS actions.

Setup cost: Low to medium if an existing controlled lab/test account and
test-only principals are available.

Artifact risk: Manageable if outputs remain sanitized and no raw debug logs or
credentials are committed.

Overclaim risk: Medium unless wording stays narrow. The result must not imply
downstream authorization or broad exploitability.

Expected determinism: Generally good for explicitly configured IAM trust and
permission relationships, subject to environment drift and AWS eventual
consistency.

Design required first: Yes, especially for report schema, selected finding/path
identity, input bundle reference, and abort conditions.

What it would still not prove: Production readiness, broad correctness,
downstream authorization, resource-policy Deny support, or all finding
correctness.

### B. PassRole-To-Service Edge Corroboration With No Downstream Action

Evidence value: Useful for a selected PassRole edge if the evidence check can
confirm the relationship without invoking a downstream service action.

Safety: More complex than STS because PassRole meaning often depends on a
service action. The protocol must avoid resource creation and downstream
execution.

Setup cost: Medium because selected service context and role usage assumptions
must be explicit.

Artifact risk: Medium due to potential service metadata or configuration
summaries.

Overclaim risk: High if reviewers read the edge as successful service
execution. The protocol must state that no downstream action was performed.

Expected determinism: Medium, depending on how the no-downstream evidence check
is designed.

Design required first: Yes, with a tighter safety model than STS.

What it would still not prove: Service execution, impact, persistence, or broad
authorization.

### C. Identity Deny Suppression Validation

Evidence value: Useful for selected Deny precedence behavior and suppression of
otherwise plausible paths.

Safety: Potentially strong if the evidence check is metadata-only or uses a
non-destructive probe.

Setup cost: Medium because policy context must be frozen and reviewed.

Artifact risk: Medium because policy summaries can contain sensitive account
structure.

Overclaim risk: Medium. One Deny scenario does not establish generic Deny
support across policies and resources.

Expected determinism: Good when the selected Deny condition is explicit and the
environment does not drift.

Design required first: Yes, particularly around condition keys, policy scope,
and mismatch taxonomy.

What it would still not prove: Generic resource-policy Deny support or
finding-level reachability.

### D. Stale Principal Drift Validation

Evidence value: Useful for detecting mismatch between frozen artifacts and
current environment identity state.

Safety: Strong if metadata summaries are sanitized and no mutation occurs.

Setup cost: Low to medium depending on available sanitized identity metadata.

Artifact risk: Medium because raw identity metadata can be sensitive.

Overclaim risk: Medium. Drift validation says something about artifact
freshness, not broad reasoning correctness.

Expected determinism: Medium because drift is time-sensitive by definition.

Design required first: Yes, especially to separate stale artifact, environment
drift, and tool behavior.

What it would still not prove: Runtime exploitability, production readiness, or
semantic correctness of all findings.

## 11. Recommendation

Recommended first validation type:

`STS AssumeRole finding/path corroboration using an already controlled lab/test account`

Rationale:

- It aligns with IAMScope's existing runtime STS safety model and proof
  maturity.
- It can be limited to one selected finding or path.
- It can remain non-destructive.
- It can avoid downstream AWS actions.
- It has a direct observed behavior: the selected AssumeRole attempt is
  corroborated, refuted, or unresolved under explicit conditions.
- It has lower setup and artifact risk than PassRole-to-service validation.

This recommendation is not a recommendation to run live AWS in this PR. The
next step should define a minimal controlled STS finding validation report
schema before any implementation or live validation.

## 12. Required Preconditions Before Implementation

Before any implementation or live validation slice:

- Selected environment is test-only.
- Selected finding or path is explicit.
- Input bundle is frozen and sanitized.
- Runtime probe is non-destructive.
- Operator approval is recorded.
- Output path is safe and caller-provided or under `/tmp`.
- Teardown is not needed or is documented.
- No downstream actions are configured or performed.
- No raw AWS debug logging is requested.
- No credentials, tokens, or secrets are written to output.
- Validation report non-claims are explicit.

## 13. What This Protocol Would Prove

If implemented and executed later, this protocol would prove only:

- One selected IAMScope prediction was corroborated, refuted, or left
  inconclusive in one controlled environment under explicit conditions.
- A validation report can preserve evidence boundaries and artifact safety.

It would not prove broader behavior outside that selected environment,
prediction, input bundle, and evidence check.

## 14. What Remains Unproven

This protocol does not prove:

- Production readiness.
- Broad correctness.
- Arbitrary enterprise graph correctness.
- Real-world scalability.
- All findings verified.
- Broad exploitability.
- Downstream authorization.
- Generic resource-policy Deny support unless the selected validation is
  explicitly designed for that behavior.
- Multi-account runtime stability.
- Multi-day runtime stability.

## 15. Recommended Next Slice

Recommended next slice:

`design minimal controlled STS finding validation report schema`

That next slice should remain docs/schema only. It should not implement
validation logic, run live AWS, call STS, create resources, add Terraform, add
fixtures, generate benchmark outputs, add CI gates, introduce pass/fail labels,
or create a composite score.
