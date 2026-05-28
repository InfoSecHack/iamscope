# Env 5: AR-1 Regression — Permission Boundary Blocks Chain Hop 2

## Overview

This environment regression-tests the **AR-1 fix** introduced in Session 6c Phase 2.
The bug: before the fix, `admin_reachability` would emit `VALIDATED` for a principal
whose only path to an admin role passed through a hop blocked by a permission boundary.
Simultaneously, `assume_role_chain` correctly emitted `BLOCKED` for the same path —
producing contradictory verdicts with no signal to the operator.

The fix adds a cross-reasoner consistency post-processor (`cross_reasoner_consistency.py`)
that detects the overlap and demotes `admin_reachability` from `VALIDATED` to `INCONCLUSIVE`
with a `cross_reasoner_blocked` blocker. This environment deploys the minimal IAM resources
that reproduce the scenario and verifies iamscope emits the correct pair of verdicts.

## Topology

```
env05-alice  --[sts:AssumeRole]--> env05-devops  --[sts:AssumeRole]--> env05-admin
                                        |
                               permission boundary
                               (allows s3:ListBucket only;
                                sts:AssumeRole is absent →
                                implicit deny on hop 2)
```

`env05-admin` has `AdministratorAccess` — the admin-equivalent endpoint both reasoners
detect. The chain is structurally valid (trust edges and permission edges exist), but
the boundary on `env05-devops` makes the second hop unreachable at runtime.

## Prerequisites

- **Terraform >= 1.5** in PATH
- **jq** in PATH
- **iamscope venv** at `../../.venv` (the script activates it automatically)
- **AWS profiles** configured in `~/.aws/config`:
  - `iamscope-admin` — AdministratorAccess, used for `terraform apply/destroy`
  - `iamscope-test` — ReadOnlyAccess, used for `iamscope collect`

## How to Run

```bash
bash acceptance/env05_ar1_blocked_chain/run.sh
```

Run from the project root. The script handles `cd` internally. No manual `terraform init`
needed after the first run (`.terraform/` is checked in via `.terraform.lock.hcl`).

## What PASS Means

All three structural assertions passed against `findings.json`:

1. **Assertion 1** — `assume_role_chain` emitted exactly one `blocked` finding for
   `alice → admin`. The per-hop boundary check in `assume_role_chain` detected that
   `sts:AssumeRole` is absent from the boundary's Allow set and set `likely_blocking=True`.
2. **Assertion 2** — `admin_reachability` emitted exactly one `inconclusive` finding for
   `alice → admin`. The Phase 2 post-processor demoted the pre-fix `validated` verdict.
3. **Assertion 3** — That `admin_reachability` finding has a `cross_reasoner_blocked`
   blocker with `constraint_id=null`. This is the specific signal that the post-processor
   (not a primary reasoner) produced the demotion.

The AR-1 fix is working correctly.

## What FAIL Means

| Assertion | Symptom | Likely cause |
|-----------|---------|--------------|
| 1 — `assume_role_chain` not BLOCKED | Count ≠ 1 | Boundary detection broke in the resolver or `assume_role_chain`'s per-hop check; or the chain itself isn't being detected (trust/permission edges missing) |
| 2 — `admin_reachability` not INCONCLUSIVE | Count ≠ 1 | Post-processor not being called from `cli.py`; or overlap detection logic regressed; or `admin_reachability` BFS itself changed |
| 3 — No `cross_reasoner_blocked` blocker | Count < 1 | Post-processor logic changed (blocker kind renamed, `constraint_id` no longer null, or the demotion produces a different blocker shape) |

If assertions 1 passes but 2 fails, the AR-1 bug has regressed.
If assertion 1 fails, debug the boundary/chain detection before interpreting assertion 2.

## Cost

**$0.** All resources are IAM (users, roles, policies) which are free. No Secrets Manager,
KMS, EC2, or other paid resources are created. `terraform destroy` runs unconditionally
on script exit via trap, so resources never linger.

## Runtime

Approximately **3–5 minutes** end to end:
- `terraform apply`: ~30s
- IAM eventual consistency sleep: 30s
- `iamscope collect` (single account, standalone): ~60–90s
- Assertions + `terraform destroy`: ~30s

## Why Permission Boundary, Not SCP

SCPs require an AWS Organizations OU hierarchy and a management account. A permission
boundary achieves the same blocked-hop pattern with no Organizations dependency: both
mechanisms produce `likely_blocking=True` bindings on the affected permission edge, and
`assume_role_chain` consumes them identically. The sandbox account used here is a
standalone account with no Organizations membership, making a boundary the correct and
simpler choice for this test.
