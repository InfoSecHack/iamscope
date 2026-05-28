# Env24 - S3 Resource-Policy Allow Edge Benchmark

Env24 is the first resource-policy Allow benchmark. It is a single-account,
scenario-edge-level fixture for S3 bucket-policy Allow evidence.

## Fixture Shape

- `env24-reader` is an IAM user under `/iamscope-test/`.
- An empty S3 bucket named `env24-rp-allow-<account-id>-<suffix>` is created.
- The bucket policy allows the exact `env24-reader` ARN to call
  `s3:GetObject` on `bucket/*`.
- `env24-reader` has no identity policy granting `s3:GetObject`.
- No S3 objects are required.
- No resource-policy `Deny` statement is created.

## Expected Result

- Scenario validation passes.
- The `IAMUser` node for `env24-reader` exists.
- The `S3Bucket` node for the Env24 bucket exists.
- A `s3:GetObject_resource_policy` edge exists from `env24-reader` to the
  bucket.
- The edge has resource-policy provenance in its features.
- No matching `s3:GetObject_permission` edge exists for the same source and
  target.
- No `RESOURCE_POLICY_CONDITION` or generic `RESOURCE_POLICY_DENY` constraint is
  emitted for this unconditioned Allow.
- No finding-level resource-policy Allow claim is required.

## Live Run

Do not run live AWS unless explicitly requested.

```bash
cd <local-iam-scope-repo>
source .venv/bin/activate
bash scripts/run_env24_s3_resource_policy_allow_benchmark.sh
```

## Boundary

This benchmark proves only one controlled S3 resource-policy Allow edge in
`scenario.json`. It does not prove runtime S3 object readability, S3
`PutBucketPolicy` takeover findings, Secrets Manager/KMS/Lambda resource-policy
Allow behavior, generic resource-policy Deny support, or production readiness.
