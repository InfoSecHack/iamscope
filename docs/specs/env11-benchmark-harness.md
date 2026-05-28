# Env11 Benchmark Harness

## Goal

- Add a broad-looking trust negative control.
- Prove IAMScope does not shortcut through broad same-account trust when an unsatisfied trust condition is present.

## Trust Shape

- Principal: same-account root ARN, `arn:aws:iam::<account>:root`
- Condition: `Bool` on `aws:MultiFactorAuthPresent=true`
- Source: `env11-alice`
- Target: `env11-broad-conditioned-admin` with `AdministratorAccess`

This condition shape is already surfaced by IAMScope as `TRUST_CONDITION`.

## Harness Contract

- The wrapper uses the same temp-copy pattern as Env08.
- Required benchmark pass conditions:
  - scenario validation PASS
  - `sts:AssumeRole_permission` edge exists for `alice -> target`
  - `sts:AssumeRole_trust` edge exists to the target
  - `TRUST_CONDITION` evidence for `aws:MultiFactorAuthPresent` exists
  - the target trust edge is bound to that `TRUST_CONDITION`
  - `admin_reachability.validated == 0`

## Out Of Scope

- No runtime STS proof.
- No reasoner changes.
- No broader trust-condition framework.
