# Env25: S3 Resource-Policy Allow Scoped Away

Env25 is the negative mutation pair for Env24. Env24 grants the exact benchmark reader principal `s3:GetObject` through an S3 bucket-policy Allow and expects a resource-policy scenario edge for that reader. Env25 keeps the same S3 bucket-policy shape but grants the Allow to `env25-decoy`, not `env25-reader`.

Expected behavior:

- `env25-reader` IAM user node exists.
- `env25-decoy` IAM user node exists.
- S3 bucket node exists.
- `s3:GetObject_resource_policy` edge exists from `env25-decoy` to the benchmark bucket.
- Matching `s3:GetObject_resource_policy` edge from `env25-reader` to the benchmark bucket is absent.
- Matching `s3:GetObject_permission` identity edge from `env25-reader` to the benchmark bucket is absent.
- Env25 does not create resource-policy Deny statements or claim generic resource-policy Deny support.
- Env25 is scenario-edge-level only; no finding-level resource-policy reachability claim is required.

Run from the repository root only when a live AWS benchmark run is intended:

```bash
bash scripts/run_env25_s3_resource_policy_allow_scoped_away_benchmark.sh
```

The runner applies the fixture, collects IAMScope evidence, validates the scenario, checks the Env25 semantic contract, and destroys the Terraform-managed resources on exit.
