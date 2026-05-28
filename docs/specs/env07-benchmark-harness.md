# Env07 Benchmark Harness Contract

## Scope
- Add a narrow single-account IAM benchmark for a reachable non-admin AssumeRole path.
- Keep the benchmark truthful to current IAMScope surfaces.
- Do not change reasoner logic.

## Ground truth
- `env07-alice` can directly assume `env07-reader`.
- `env07-reader` has only non-admin permissions (`s3:ListAllMyBuckets`).
- `env07-reader` does not have `AdministratorAccess` and is not admin-equivalent.

## Truthful benchmark contract
- Current repo behavior does **not** provide a validated non-admin reachability finding for this case.
- `assume_role_chain` is intentionally admin-endpoint-oriented today, so this benchmark does **not** require `assume_role_chain.validated`.
- The benchmark instead proves:
  - `scenario.json` contains both `sts:AssumeRole_permission` and `sts:AssumeRole_trust` edges for `alice -> reader`
  - `admin_reachability` emits zero validated findings for `alice -> reader`
  - `admin_reachability` emits zero blocked findings for `alice -> reader`
  - `admin_reachability` emits zero inconclusive findings for `alice -> reader`
  - `iamscope validate` passes for `scenario.json`

## Harness behavior
- Use the existing temp-copy benchmark pattern.
- Archive `run.log`, `expected_findings.json`, and collect outputs.
- Let extra non-target findings exist unless they contradict the target-path semantics above.
- Do not add a Phase 0 case manifest until the scorer can truthfully express structural path assertions without inventing a new finding surface.