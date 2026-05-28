# Env09 ? Env05 mutation with boundary removed

Env09 is the first mutation-pair benchmark for Env05.

## Relationship to Env05
- **Base case:** `acceptance/env05_ar1_blocked_chain`
- **Mutation:** remove only the permission boundary from the intermediate `env09-devops` role
- **Preserved shape:** `alice -> devops -> admin`

## Ground Truth
- `env09-alice` can assume `env09-devops`
- `env09-devops` can assume `env09-admin`
- `env09-admin` has `AdministratorAccess`
- There is no permission boundary blocking the second hop

## Expected IAMScope Behavior
- `scenario.json` validates successfully
- `admin_reachability.validated >= 1` for `alice -> admin`
- `admin_reachability.blocked == 0` for `alice -> admin`
- `admin_reachability.inconclusive == 0` for `alice -> admin`
- `assume_role_chain` may also validate for `alice -> admin`; the benchmark records that count but does not require it

## What This Does Not Prove
- It does not prove broader mutation-pair scoring yet
- It does not prove every two-hop chain behaves identically
- It does not by itself explain *why* Env05 differs; the intended delta is the boundary removal
