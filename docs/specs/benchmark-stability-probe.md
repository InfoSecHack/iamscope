# Benchmark Stability Probe

## Scope
`scripts/run_stability_probe.sh` repeats one existing low-risk live benchmark and records whether target semantics stay stable across runs.

Supported first cases:
- `env03`: identity-policy Deny blocked group escalation. This is the first blocked-path stability target.
- `env05`: permission-boundary blocked assume-role/admin chain. This is the permission-boundary blocked-path stability target.
- `env06`: positive admin reachability.
- `env07`: non-admin AssumeRole structure without false admin claim.
- `env18`: validated Lambda PassRole path. This is the first PassRole positive stability target.
- `env19`: Lambda PassRole `iam:PassedToService` scoped-away path. This is the matching Lambda PassRole negative stability target.
- `env20`: validated ECS PassRole path. This is the first ECS PassRole positive stability target.
- `env21`: ECS PassRole `iam:PassedToService` scoped-away path. This is the matching ECS PassRole negative stability target.

The probe intentionally excludes SCP/Organizations cases such as Env12 and Env13 because Organizations propagation adds AWS-side nondeterminism.

## Command
```bash
cd <local-iam-scope-repo>
source .venv/bin/activate
bash scripts/run_stability_probe.sh \
  --case env03 \
  --runs 3 \
  --out-dir /tmp/iamscope-stability-env03
```

For Env05 permission-boundary blocked-chain stability:
```bash
bash scripts/run_stability_probe.sh \
  --case env05 \
  --runs 3 \
  --out-dir /tmp/iamscope-stability-env05
```

For Env18 Lambda PassRole stability:
```bash
bash scripts/run_stability_probe.sh \
  --case env18 \
  --runs 3 \
  --out-dir /tmp/iamscope-stability-env18
```

For Env19 Lambda PassRole PassedToService scoped-away stability:
```bash
bash scripts/run_stability_probe.sh \
  --case env19 \
  --runs 3 \
  --out-dir /tmp/iamscope-stability-env19
```

For Env20 ECS PassRole stability:
```bash
bash scripts/run_stability_probe.sh \
  --case env20 \
  --runs 3 \
  --out-dir /tmp/iamscope-stability-env20
```

For Env21 ECS PassRole PassedToService scoped-away stability:
```bash
bash scripts/run_stability_probe.sh \
  --case env21 \
  --runs 3 \
  --out-dir /tmp/iamscope-stability-env21
```

## Outputs
Under `--out-dir`:
- `archives/`: one normal benchmark archive per run.
- `evaluations/`: one Phase 0 evaluation directory per run when artifacts are available.
- `stability_summary.json`: machine-readable summary.
- `stability_report.md`: human-readable summary.
- `stability_runs.jsonl`: per-run raw records.

## Categories
The probe reports separate categories and does not compute a composite score:

- `tool_semantic_stability`: target semantic assertions passed or failed after artifacts were produced and evaluation ran.
- `collection_runtime_failure`: expected artifacts or scenario validation were missing/failing.
- `aws_terraform_setup_failure`: setup/auth/provider/throttling-style failure was visible in the run log.

## Evidence Boundary
Passing repeated runs support stability for the selected case only. They do not prove broad IAMScope stability, production readiness, or stability for SCP/Organizations benchmarks.

Do not run live AWS unless explicitly requested.
