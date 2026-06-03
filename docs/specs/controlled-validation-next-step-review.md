# Controlled Validation Next-Step Review

## Purpose

This review assesses whether IAMScope should perform more controlled live STS validation after Controlled STS Run #2.

This is docs/review only. It does not run live AWS, call STS AssumeRole, run `live_probe`, create pre-live plans, create or modify AWS resources, inspect raw AWS artifacts, copy raw artifacts, commit `/tmp` outputs, change executor logic, change validator logic, change report generator logic, change collector/reasoner/scorer/scenario-validation logic, change benchmark logic, add pass/fail labels, add composite scoring, claim production readiness, claim broad IAMScope correctness, or claim broad runtime exploitability.

## Current Controlled Validation Summary

- Controlled STS Run #1: `environment_mismatch`; no live execution.
- Controlled STS Run #2: selected live-profile-matched `iamscope-admin` denied candidate; live result `denied/access_denied`; `outcome_classification=corroborated`.
- Run #2 source: `arn:aws:iam::<redacted-aws-account-id>:user/iamscope-admin`.
- Run #2 target: `arn:aws:iam::<redacted-aws-account-id>:role/arf-rt-DevRole`.
- Run #2 credentials obtained: `false`.
- Run #2 downstream AWS actions: none.
- Earlier standalone STS executor proofs include one denied case and one assumed case, but those are bounded runtime-probe evidence and are not controlled finding/path validation for a current selected IAMScope path.
- No broad production-readiness, broad exploitability, or broad IAMScope correctness claim exists from these results.

## What Run #2 Adds

Run #2 adds one bounded, controlled validation datapoint:

- A selected live-profile-matched denied STS prediction was corroborated by live AWS.
- `access_denied` was safely classified without emitting credentials.
- No downstream AWS actions were performed.
- No raw `/tmp` outputs were committed.
- The validation workflow caught the Run #1 profile/source mismatch and proceeded only after selecting a matched candidate for Run #2.

This is useful evidence for the controlled validation workflow itself: it demonstrates that mismatch handling can stop an unsafe or irrelevant live run, and that a matched denied candidate can be planned, simulated, executed in a bounded way, and summarized without broadening claims.

## What Remains Unproven

The current controlled validation track still does not prove:

- Positive controlled finding/path validation.
- A `credentials_obtained=true` path for controlled finding/path validation.
- Downstream authorization.
- Production readiness.
- Broad IAMScope correctness.
- Arbitrary enterprise graph correctness.
- Resource-policy Deny support.
- Finding-level reachability.
- Real-world scalability.
- Multi-account runtime stability.
- Multi-day runtime stability.

## Candidate Next Options

### Option A: Stop controlled validation after Run #2

- Evidence value: high enough for the current phase; the track now has a Run #1 mismatch checkpoint, a Run #2 matched denied corroboration, and older standalone denied/assumed executor proofs.
- Safety risk: lowest; avoids new live STS calls and avoids overfitting the project around runtime probes.
- Setup cost: low; requires only a final maturity checkpoint.
- Risk of overclaiming: lowest if the checkpoint keeps boundaries explicit.
- Needs another pre-live path-selection step: no.
- Still does not prove: positive controlled finding/path validation, downstream authorization, production readiness, broad correctness, or scalability.

### Option B: Design one matched positive controlled STS validation run

- Evidence value: potentially useful because it would add a controlled `credentials_obtained=true` finding/path validation result.
- Safety risk: higher than stopping; a positive run obtains credentials and therefore requires stricter artifact review and cleanup discipline.
- Setup cost: medium to high; the current live profile mapping does not identify an already-available matched positive path from committed sanitized evidence.
- Risk of overclaiming: moderate; a positive result is easy to overread as exploitability or downstream authorization unless aggressively bounded.
- Needs another pre-live path-selection step: yes, unless a current-profile-matched positive candidate is first identified from committed sanitized evidence.
- Still does not prove: downstream authorization, production readiness, broad correctness, arbitrary enterprise graph correctness, resource-policy Deny support, or scalability.

### Option C: Select another denied path

- Evidence value: low; Run #2 already exercises a matched denied controlled path.
- Safety risk: low to moderate depending on the path, but still requires more live STS work.
- Setup cost: medium; another path-selection and pre-live plan would be required.
- Risk of overclaiming: low if bounded, but the incremental evidence is redundant.
- Needs another pre-live path-selection step: yes.
- Still does not prove: positive controlled validation, credentials-obtained handling for controlled finding/path validation, downstream authorization, production readiness, broad correctness, or scalability.

### Option D: Return to non-live benchmark/reporting work

- Evidence value: useful for improving reviewability and presentation of existing evidence without adding live-call risk.
- Safety risk: low.
- Setup cost: low to medium depending on scope.
- Risk of overclaiming: low if reporting stays boundary-first.
- Needs another pre-live path-selection step: no.
- Still does not prove: new runtime behavior or positive controlled finding/path validation.

## Recommendation

Recommend exactly one next slice: stop controlled validation after Run #2 and create a final controlled validation maturity checkpoint.

Rationale:

- Run #2 supplies the matched denied controlled validation result that Run #1 could not provide.
- Existing standalone executor evidence already includes one denied and one assumed STS proof, so the immediate gap is presentation and boundary discipline, not another live probe by default.
- No already-available matched positive controlled finding/path candidate from committed sanitized evidence and current live profiles is identified in the merged review trail.
- The next risk is overclaiming or expanding live validation beyond the evidence boundary.

Do not recommend immediate live execution, another live probe, broad validation, production testing, downstream AWS actions, a new benchmark framework, CI gates, composite scoring, or multiple next slices.

## Non-Claims

This review does not claim:

- Production readiness.
- Broad exploitability.
- Downstream authorization proof.
- Broad IAMScope correctness.
- Arbitrary enterprise graph correctness.
- A composite score.
- A pass/fail benchmark label.
- That controlled validation can never resume.
- That positive controlled finding/path validation is unnecessary forever.

It recommends stopping the current controlled validation expansion now and recording the maturity state truthfully.
