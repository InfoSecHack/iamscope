# Env24 Benchmark Harness

Env24 is the first resource-policy Allow benchmark implementation. It follows
`docs/specs/env24-resource-policy-allow-benchmark-design.md` and remains
scenario-edge-level evidence only.

## Fixture

- Single-account AWS fixture.
- IAM user `env24-reader` under `/iamscope-test/`.
- Empty S3 bucket `env24-rp-allow-<account-id>-<suffix>`.
- Bucket policy grants exact `env24-reader` ARN `s3:GetObject` on `bucket/*`.
- No identity policy grants `s3:GetObject` to `env24-reader`.
- No resource-policy `Deny` statement is created.

## Expected Machine-Scored Evidence

The case manifest asserts:

- `IAMUser` node exists for `env24-reader`.
- `S3Bucket` node exists for the Env24 bucket.
- `s3:GetObject_resource_policy` edge exists from `env24-reader` to the bucket.
- The resource-policy edge has `permission_source=resource_policy`,
  `layer=resource_policy`, and `has_conditions=false`.
- No matching `s3:GetObject_permission` identity-policy edge exists for the
  same source and target.
- No `RESOURCE_POLICY_CONDITION` constraint exists for the unconditioned edge.
- No generic `RESOURCE_POLICY_DENY` constraint exists.

No finding-level assertion is required or implied.

## Live Command

Do not run live AWS unless explicitly requested.

```bash
cd <local-iam-scope-repo>
source .venv/bin/activate
bash scripts/run_env24_s3_resource_policy_allow_benchmark.sh
```

## Boundary

This harness does not test generic resource-policy Deny and does not claim
generic Deny support. It also does not prove runtime S3 object readability,
Secrets Manager/KMS/Lambda resource-policy Allow behavior, or production
readiness.
