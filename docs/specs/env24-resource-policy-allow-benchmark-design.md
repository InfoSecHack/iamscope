# Env24 Resource-Policy Allow Benchmark Design

## Purpose And Scope

Env24 starts the resource-policy Allow benchmark family. The purpose is to
prove, with a small live AWS fixture, that IAMScope can collect, parse, bind,
and export a resource-policy `Allow` statement as scenario evidence without
overstating generic resource-policy `Deny` support.

This is a design-only slice. It does not build Terraform, run live AWS, change
IAMScope logic, add benchmark artifacts, or add a generic resource-policy Deny
engine.

## Current Support Summary

Current resource-policy support is graph-oriented:

- `iamscope/parser/resource_policy.py` parses `Effect: Allow` statements only.
- `iamscope/resolver/resource_policy_binder.py` emits ordinary graph edges with
  the `_resource_policy` layer suffix, for example
  `s3:GetObject_resource_policy`.
- Condition-bearing Allow statements emit `RESOURCE_POLICY_CONDITION`
  constraints with `governance_confidence=needs_review`.
- Deny-only resource policies intentionally emit no Allow rows, no
  `_resource_policy` edges, and no generic `RESOURCE_POLICY_DENY` constraints.
- Existing S3 and Secrets reasoners consume IAM permission-layer edges such as
  `s3:PutBucketPolicy_permission` and
  `secretsmanager:GetSecretValue_permission`; they do not currently consume
  `_resource_policy` Allow edges as finding-level proof.

Because of that boundary, the first implementation should be a
scenario-edge-level benchmark, not a finding-level benchmark. A later slice can
add a finding-level resource-policy Allow reasoner only after the truth contract
for that finding is designed explicitly.

## Chosen Service

Choose S3 bucket policy Allow for Env24/Env25.

S3 is the safest first service because:

- The collector already records S3 bucket nodes and bucket policies.
- The parser and binder already have focused tests for S3 bucket-policy Allow.
- A bucket policy can grant read-only `s3:GetObject` on `bucket/*` without
  creating objects or invoking data-plane reads.
- The fixture can be IAM/resource-policy-only and single-account.
- The benchmark can avoid KMS decrypt semantics, Secrets Manager secret values,
  Lambda invocation surfaces, and any destructive resource-policy mutation.

Do not use KMS as the first Allow benchmark. KMS key policy Allow is already
partly interpreted inside `SecretsBlastRadiusReasoner` for its reasoner-local
decrypt precondition, and mixing that with the first generic Allow-family case
would blur the boundary.

Do not use Secrets Manager as the first Allow benchmark. A resource policy on a
secret is relevant to secret access, but current `SecretsBlastRadiusReasoner`
does not consume `secretsmanager:GetSecretValue_resource_policy` edges as
finding-level proof, and live secrets add avoidable cleanup and sensitivity
concerns.

## Env24 Fixture Shape

Env24 should be a single-account IAM/S3 fixture:

- IAM user: `env24-reader`
- S3 bucket: `env24-resource-policy-allow-<unique-suffix>`
- Bucket policy statement:
  - `Effect`: `Allow`
  - `Principal`: exact ARN of `env24-reader`
  - `Action`: `s3:GetObject`
  - `Resource`: `arn:aws:s3:::env24-resource-policy-allow-<unique-suffix>/*`
  - No `Condition`
  - No `Deny`
- No S3 objects are required.
- No production identities are used.

The target bucket should be empty. The benchmark tests IAMScope evidence about
the bucket policy; it does not need to read or write object data.

## Principal And Resource Policy Shape

The positive Env24 policy should be exact and unconditioned:

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "AllowEnv24ReaderGetObject",
      "Effect": "Allow",
      "Principal": {
        "AWS": "arn:aws:iam::<account-id>:user/iamscope-test/env24-reader"
      },
      "Action": "s3:GetObject",
      "Resource": "arn:aws:s3:::env24-resource-policy-allow-<suffix>/*"
    }
  ]
}
```

The fixture should not attach an identity policy granting `s3:GetObject` to
`env24-reader`. The resource-policy edge should be the only intended witness
for the benchmark assertion.

## Expected Collected Nodes And Edges

Expected nodes:

- `IAMUser` node for `env24-reader`
- `S3Bucket` node for the Env24 bucket

Expected edges:

- Exactly one relevant `s3:GetObject_resource_policy` edge from
  `env24-reader` to the Env24 bucket.
- Edge features should include:
  - `permission_source = "resource_policy"`
  - `layer = "resource_policy"`
  - `principal_type = "AWS"`
  - `resource_pattern = "arn:aws:s3:::.../*"`
  - `target_arn` set to the bucket ARN
  - at least one `RESOURCE_POLICY` allow control reference
  - `has_conditions = false`

Expected constraints:

- No `RESOURCE_POLICY_CONDITION` constraint for the Env24 edge.
- No `RESOURCE_POLICY_DENY` constraint.

## Expected Findings And Reasoner Output

Env24 should not require a finding-level assertion in the first implementation.
Current reasoners do not turn `s3:GetObject_resource_policy` into a validated
finding, and the benchmark must not fake that support.

Acceptable first implementation result:

- Scenario validation passes.
- Scenario contains the exact `s3:GetObject_resource_policy` edge.
- No unsupported Deny constraint appears.
- Findings may contain no Env24-specific finding.

Unacceptable result:

- A missing resource-policy edge.
- A conditioned edge treated as clean.
- A generic `RESOURCE_POLICY_DENY` constraint.
- Any documentation or report claim that Env24 proves generic
  resource-policy Deny support.

## Semantic Assertions

Env24 case manifest should use scenario structural assertions:

- `scenario_edge_count`:
  - `edge_type = "s3:GetObject_resource_policy"`
  - source provider ID from context: `env24-reader` ARN
  - target provider ID from context: Env24 bucket ARN
  - `feature_has_conditions = false`
  - `op = "gte"`
  - `expected_value = 1`
- `scenario_edge_count`:
  - same source/target
  - `edge_type = "s3:GetObject_permission"`
  - `op = "eq"`
  - `expected_value = 0`
  - Purpose: prove the fixture did not accidentally create an identity-policy
    permission witness for the target path.
- `scenario_constraint_count`, if supported by the manifest/scorer:
  - `constraint_type = "RESOURCE_POLICY_DENY"`
  - `op = "eq"`
  - `expected_value = 0`
  - If the scorer cannot express this yet, use the smallest structural
    assertion extension consistent with existing benchmark assertion patterns.

Do not add a finding-count assertion for a validated finding unless a later
implementation also adds a dedicated finding-level resource-policy Allow
reasoner.

## Proposed Env24/Env25 Pair

Env24: S3 bucket policy Allow present.

- `env24-reader` exists.
- Bucket policy allows exact `env24-reader` ARN to perform `s3:GetObject` on
  `bucket/*`.
- Expected truth: resource-policy Allow edge exists in `scenario.json`.
- Expected benchmark level: scenario-edge-level pass.

Env25: same shape, but Allow scoped away.

- `env25-reader` exists.
- Optional decoy user `env25-decoy` exists.
- Bucket policy allows `env25-decoy`, not `env25-reader`, to perform
  `s3:GetObject` on `bucket/*`.
- Expected truth for `env25-reader`: no matching
  `s3:GetObject_resource_policy` edge.
- Expected optional structural evidence: decoy resource-policy edge exists.
- Expected benchmark level: scenario-edge-level non-validated mutation.

Prefer the scoped-away mutation over removing the policy entirely because it
proves IAMScope observed the bucket policy and preserved the principal
distinction. If scoped-away evidence is too awkward in the initial scorer,
Env25 may start as Allow removed, but that is weaker and should be documented
as such.

## Materializer And Case Manifest Needs

Env24/Env25 should follow the existing benchmark pattern:

- Add acceptance environments only in the build slice:
  - `acceptance/env24_s3_resource_policy_allow/`
  - `acceptance/env25_env24_resource_policy_allow_scoped_away/`
- Add runner scripts only in the build slice:
  - `scripts/run_env24_s3_resource_policy_allow_benchmark.sh`
  - `scripts/run_env25_s3_resource_policy_allow_scoped_away_benchmark.sh`
- Add case manifests:
  - `benchmarks/cases/env24_s3_resource_policy_allow_edge.json`
  - `benchmarks/cases/env25_s3_resource_policy_allow_scoped_away_nonvalidated.json`
- Add materializer support only if small and consistent with existing Env14+
  patterns.

The first build should add tests for any new structural assertion shape before
running live AWS.

## Live AWS Risk And Cost Notes

Risk is low if the fixture stays IAM/S3 metadata-only:

- S3 bucket storage cost is near zero because no objects are required.
- No Lambda, ECS, Secrets Manager, or KMS data-plane operations are required.
- No read/write object probes should run.
- Bucket names are globally unique, so the Terraform fixture must include a
  deterministic or random suffix.
- Use a dedicated non-production account/profile.

The bucket policy grants read access to an empty benchmark bucket only. It must
not reference production buckets, production principals, or broad account-root
principals.

## Cleanup Risks

Cleanup should destroy:

- `env24-reader` / `env25-reader`
- optional `env25-decoy`
- Env24/Env25 bucket policies
- Env24/Env25 empty buckets

Because S3 buckets must be empty before deletion, the runner should either avoid
creating objects entirely or include an explicit empty-bucket cleanup step.
Terraform destroy should be guarded by a trap, matching the existing benchmark
runner style.

## What This Proves

If Env24 passes, it proves only:

- IAMScope collected an S3 bucket policy from the benchmark bucket.
- IAMScope parsed the unconditioned `Allow` statement.
- IAMScope bound the exact principal-to-bucket Allow as a
  `s3:GetObject_resource_policy` scenario edge.
- IAMScope did not require a generic Deny path to represent Allow evidence.

If Env25 passes, it proves only:

- IAMScope does not create a matching resource-policy Allow edge for the real
  benchmark principal when the bucket policy trusts a decoy principal instead.

## What This Does Not Prove

This family does not prove:

- Runtime S3 object readability.
- S3 object-level collection.
- S3 `PutBucketPolicy` takeover findings via resource-policy Allow edges.
- Secrets Manager resource-policy Allow findings.
- KMS key-policy Allow findings.
- Lambda resource-policy Allow findings.
- Cross-account runtime exploitability.
- Broad resource-policy condition handling.
- Broad resource-policy Allow correctness across all principal forms.
- Production readiness.

## Explicit Deny Boundary

Env24/Env25 do not test generic resource-policy Deny.

They do not claim Deny support. Deny-only resource policies remain explicitly
de-scoped from collect/pipeline/output end-to-end support. The only documented
Deny exception remains the narrow reasoner-local KMS key-policy handling inside
`SecretsBlastRadiusReasoner`; that is not generic `RESOURCE_POLICY_DENY`
support and is not part of this benchmark family.

## Exact Next Build Prompt

```text
Work from current origin/main in a fresh branch.

Mission:
Build Env24: S3 resource-policy Allow scenario-edge benchmark.

Goal:
Create the first resource-policy Allow benchmark without adding generic
resource-policy Deny support.

Design doc:
- docs/specs/env24-resource-policy-allow-benchmark-design.md

Do not change IAMScope reasoner logic unless the benchmark exposes a real
parser/binder/scenario bug.
Do not implement generic RESOURCE_POLICY_DENY.
Do not run live AWS unless explicitly asked.
Do not copy raw artifacts.

Expected fixture:
- single non-production account
- IAM user env24-reader
- empty S3 bucket env24-resource-policy-allow-<suffix>
- bucket policy allows exact env24-reader ARN to perform s3:GetObject on
  bucket/*
- no identity policy grants s3:GetObject to env24-reader
- no resource-policy Deny statement
- no S3 objects required

Expected behavior:
- scenario validation PASS
- scenario has s3:GetObject_resource_policy edge from env24-reader to the bucket
- edge features show permission_source=resource_policy, layer=resource_policy,
  has_conditions=false, and RESOURCE_POLICY allow attribution
- scenario has no matching s3:GetObject_permission edge for the same source and
  target
- no RESOURCE_POLICY_DENY constraint is emitted
- no finding-level resource-policy Allow claim is required

Required files:
- acceptance/env24_s3_resource_policy_allow/{main.tf,run.sh,README.md,expected_findings.json}
- scripts/run_env24_s3_resource_policy_allow_benchmark.sh
- docs/specs/env24-benchmark-harness.md
- benchmarks/cases/env24_s3_resource_policy_allow_edge.json
- materializer support only if small and consistent
- focused tests if new structural assertion support is needed

Validation:
- bash -n new scripts
- terraform fmt -check if Terraform is added
- targeted benchmark tests if manifests/scorer/materializer change
- ./scripts/check.sh
- ./scripts/test_fast.sh
- no live AWS unless explicitly asked

Final summary:
- whether Env24 is scenario-edge-level or finding-level
- exact resource-policy Allow edge asserted
- Deny boundary preserved
- changed files
- validation results
- exact live command
```
