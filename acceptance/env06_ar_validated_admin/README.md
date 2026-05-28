# Env 6: Positive admin_reachability Acceptance

## Overview

This environment is the smallest positive AWS benchmark for `admin_reachability`.
It creates one user and one admin role with a truthful direct assume-role path:

```text
env06-alice --[sts:AssumeRole allow + matching trust]--> env06-admin
```

`env06-admin` has `AdministratorAccess`, so IAMScope should emit a validated
`admin_reachability` finding for `alice -> admin` with no blockers on that
validated target path.

## AWS Resources Created

- IAM user: `env06-alice`
- Inline IAM user policy: `env06-alice-assume-admin`
- IAM role: `env06-admin`
- IAM role policy attachment: AWS managed `AdministratorAccess`

No paid AWS services are created.

## How to Run

Run from the project root:

```bash
bash acceptance/env06_ar_validated_admin/run.sh
```
