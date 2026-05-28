# Env 8: Trust-Condition Blocked Admin Benchmark

## Overview

This environment is a small single-account IAM benchmark for conditioned trust.
It creates a user and an admin-equivalent role with:

```text
env08-alice --[sts:AssumeRole permission]--> env08-conditioned-admin
env08-conditioned-admin trust policy: allows Alice, but only when aws:MultiFactorAuthPresent == true
```

`env08-conditioned-admin` has `AdministratorAccess`, but the trust condition requires MFA.
The benchmark user is not provisioned with an MFA-backed session in this setup, so the trustworthy benchmark outcome is: no confident validated admin reachability claim.

## AWS Resources Created

- IAM user: `env08-alice`
- Inline IAM user policy: `env08-alice-assume-conditioned-admin`
- IAM role: `env08-conditioned-admin`
- Managed role policy attachment: `AdministratorAccess`

No paid AWS services are created.

## Repo-Grounded Expectation

Current IAMScope definitely exports the trust condition structurally in `scenario.json` as `TRUST_CONDITION` evidence.
Whether `admin_reachability` is suppressed or downgraded by that evidence is what this benchmark is intended to test live.
