# Benchmark Runtime STS Positive Proof Gap Review

## Purpose

This review evaluates whether IAMScope is ready to prepare a positive/assumed single-case STS proof after the denied proof and the positive proof protocol.

This is docs/review only. It does not run live AWS, call STS AssumeRole, create or modify IAM users, roles, or policies, change trust policies, add Terraform, add live AWS environments, implement runtime behavior, change the STS executor, change the dry-run validator, add raw artifacts, commit `/tmp` outputs, add CI gates, add pass/fail benchmark labels, add composite scoring, claim production readiness, claim broad IAMScope correctness, or claim broad runtime exploitability.

## Current Finding

The positive proof is blocked because no local AWS profile currently maps to the trusted source principal for the target role.

Target role:

- `arn:aws:iam::<redacted-aws-account-id>:role/arf-rt-DevRole`

Target trust policy allows:

- `arn:aws:iam::<redacted-aws-account-id>:user/arf-rt-attacker`

Current gap:

- No local AWS profile currently resolves to `arn:aws:iam::<redacted-aws-account-id>:user/arf-rt-attacker`.
- Therefore a positive/assumed proof against `arn:aws:iam::<redacted-aws-account-id>:role/arf-rt-DevRole` is not ready.

## Evidence Observed

Available local profiles were observed to resolve as follows:

- `iamscope-test` -> `arn:aws:iam::<redacted-aws-account-id>:user/iamscope-verify`
- `iamscope-admin` -> `arn:aws:iam::<redacted-aws-account-id>:user/iamscope-admin`
- `serim-dev-admin` -> `arn:aws:sts::<redacted-aws-account-id>:assumed-role/OrganizationAccountAccessRole/...`
- `serim-prod-admin` -> `arn:aws:sts::<redacted-aws-account-id>:assumed-role/OrganizationAccountAccessRole/...`
- `serim2-devengineer` -> `arn:aws:sts::<redacted-aws-account-id>:assumed-role/serim2-DevEngineerRole/...`
- `serim2-jump` -> `arn:aws:sts::<redacted-aws-account-id>:assumed-role/serim2-JumpRole/...`
- `serim2-terraform` -> `arn:aws:sts::<redacted-aws-account-id>:assumed-role/serim2-TerraformRole/...`
- `serim-management-admin` errored.

This review records the observed mapping only. It does not rerun AWS discovery and does not require AWS credentials.

## Trust-Policy Mismatch

The target role trusts `arn:aws:iam::<redacted-aws-account-id>:user/arf-rt-attacker`.

The available same-account profiles resolve to:

- `arn:aws:iam::<redacted-aws-account-id>:user/iamscope-verify`
- `arn:aws:iam::<redacted-aws-account-id>:user/iamscope-admin`

Using either currently available same-account profile would not satisfy the trusted-principal condition for a positive proof against `arn:aws:iam::<redacted-aws-account-id>:role/arf-rt-DevRole`.

The denied proof already demonstrated this boundary for `arn:aws:iam::<redacted-aws-account-id>:user/iamscope-admin`: the result was `denied` with `safe_error_category=access_denied`.

## Decision

Decision: the positive/assumed STS proof is not ready.

Do not force the positive proof by changing IAM users, roles, permissions, or trust policies ad hoc.

Do not run `live_probe` for the positive proof with a mismatched source principal.

Do not treat a profile that resolves to a different principal as evidence for `arn:aws:iam::<redacted-aws-account-id>:user/arf-rt-attacker`.

## Safe Options

### A. Stop Runtime Proofing After The Denied Proof

Evidence value: preserves the current denied proof as the only live runtime checkpoint and avoids further live AWS risk.

Safety risk: lowest.

Engineering cost: low.

Overclaim risk: low, if the denied proof remains described as one exact test condition.

What it still would not prove: positive AssumeRole behavior, credentials-obtained sanitization on success, downstream authorization, production readiness, broad runtime exploitability, broad IAMScope correctness, resource-policy Deny support, or finding-level reachability.

### B. Create A Separate Design For A Test-Only Positive Setup Plan

Evidence value: highest if the project wants a positive proof, because it would define the missing test-only setup without ad hoc IAM changes.

Safety risk: moderate. Any setup involving IAM principals, trust, or permissions requires careful design before implementation.

Engineering cost: moderate.

Overclaim risk: moderate, because a positive proof is easy to overstate as exploitability unless the setup and evidence boundary are explicit.

Design required first: yes. The setup plan must be design-only before any user, role, trust policy, or permission changes occur.

What it still would not prove: downstream authorization, production readiness, broad runtime exploitability, broad IAMScope correctness, resource-policy Deny support, finding-level reachability, enterprise coverage, persistence, or impact.

### C. Configure A Local Profile For The Existing Trusted Principal Outside IAMScope

Evidence value: potentially useful if `arn:aws:iam::<redacted-aws-account-id>:user/arf-rt-attacker` already exists and is intended for this test.

Safety risk: moderate. Local credential/profile setup can still create accidental production or persistence risk if not reviewed.

Engineering cost: low to moderate, depending on whether the principal already exists and has safe test-only credentials.

Overclaim risk: moderate. The result would still be one exact principal/role proof only.

Design required first: yes, unless the profile already exists and the user explicitly confirms it is test-only and intended for this proof.

What it still would not prove: downstream authorization, production readiness, broad runtime exploitability, broad IAMScope correctness, resource-policy Deny support, finding-level reachability, enterprise coverage, persistence, or impact.

## Recommendation

Recommended next slice: design a test-only positive STS setup plan.

That next slice should be design-only. It must not create users, modify trust policies, attach permissions, run Terraform, run live AWS, call STS, commit raw artifacts, add CI gates, add pass/fail benchmark labels, add composite scoring, claim production readiness, claim broad IAMScope correctness, or claim broad runtime exploitability.

Rationale:

- The positive proof protocol requires an intentional trusted source principal and explicit `sts:AssumeRole` permission.
- The currently available profiles do not resolve to the trusted source principal for `arf-rt-DevRole`.
- Changing IAM or trust policy ad hoc would undermine the safety model.
- A separate setup design can decide whether to use an existing test-only `arf-rt-attacker` principal, create a new test-only positive pair, or stop runtime proofing without rushing into live changes.

## Non-Claims

This review does not claim:

- A positive proof was run.
- Broad runtime exploitability.
- Production readiness.
- Downstream authorization proof.
- Broad IAMScope correctness.
- Resource-policy Deny support.
- Finding-level resource-policy reachability.

The current runtime evidence remains the documented denied single-case proof only.
