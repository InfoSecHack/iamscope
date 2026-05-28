# Env25 Mutation Benchmark Harness

Env25 is the scoped-away S3 resource-policy Allow mutation pair for Env24.

## Purpose

Env24 proves that a bucket-policy Allow for the exact `env24-reader` principal is emitted as scenario-edge-level evidence. Env25 keeps the same single-account S3 bucket-policy Allow shape, but scopes the Allow to `env25-decoy` rather than `env25-reader`. The benchmark proves IAMScope does not emit a reader-to-bucket resource-policy edge when the resource policy names a different principal.

## Fixture

- `env25-reader` IAM user exists.
- `env25-decoy` IAM user exists.
- An empty Terraform-managed S3 bucket exists.
- The bucket policy has one Allow statement granting exact `env25-decoy` ARN `s3:GetObject` on `bucket/*`.
- There is no identity-policy `s3:GetObject` grant for `env25-reader`.
- There is no bucket-policy Allow for `env25-reader`.
- There is no resource-policy Deny statement.
- No S3 objects are required.

## Expected Scenario Evidence

- Scenario validation passes.
- `env25-reader` IAMUser node count is at least one.
- `env25-decoy` IAMUser node count is at least one.
- S3Bucket node count is at least one.
- `s3:GetObject_resource_policy` edge from `env25-decoy` to the bucket exists with `permission_source=resource_policy`, `layer=resource_policy`, and `has_conditions=false`.
- `s3:GetObject_resource_policy` edge from `env25-reader` to the bucket is absent.
- `s3:GetObject_permission` identity edge from `env25-reader` to the bucket is absent.
- Env25-scoped `RESOURCE_POLICY_CONDITION` constraints are absent.
- `RESOURCE_POLICY_DENY` constraints are absent.

## Evidence Boundary

Env25 is scenario-edge-level only. It does not assert a finding-level resource-policy reachability verdict, runtime S3 object readability, S3 takeover, or generic resource-policy Deny support.

## Live Command

```bash
bash scripts/run_env25_s3_resource_policy_allow_scoped_away_benchmark.sh
```

The runner copies the acceptance fixture to a temporary directory, injects the current project root into `PYTHONPATH`, runs collection and validation from the current worktree, and destroys Terraform-managed resources on exit.
