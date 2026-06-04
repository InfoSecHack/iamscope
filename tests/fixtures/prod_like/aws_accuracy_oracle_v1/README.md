# Prod-Like AWS Accuracy Oracle v1

Fixture id: `prod_like_aws_accuracy_oracle_v1`

This is a local-only known-ground-truth oracle fixture for IAMScope's future prod-like AWS accuracy benchmark. It freezes 24 oracle rows for later Phase 5 comparison. It does not run IAMScope, does not run AWS, and does not prove IAMScope accuracy yet.

## Files

- `oracle_rows.json`: 24 frozen oracle rows and category breakdown.
- `scenario.json`: static descriptive local oracle support file, not replay-ready IAMScope output.
- `binding_metadata.json`: static descriptive binding notes, not an IAMScope replay sidecar.
- `expected_findings.json`: supported IAMScope-facing expected rows for future comparison; unsupported rows are separate static-only rows.
- `expected_comparison.json`: Phase 5 comparison skeleton with `not_run_yet` emitted categories.

## Row Breakdown

- `validated`: 6
- `blocked`: 5
- `precondition_only`: 4
- `inconclusive`: 5
- `unsupported`: 4

Unsupported rows are unsupported/static-only. They are not counted as false positives, false negatives, extra findings, or missing findings.

## Local-Only Boundary

- no live AWS
- no Terraform
- no AWS credentials
- no production accounts
- no raw AWS result JSON
- no real account IDs
- static fixture support only
- generated/replayed by IAMScope: false
- reasoners run: []

## Non-Claims

- not broad IAMScope correctness
- not production readiness
- not real production AWS
- not exploitability proof
- not downstream authorization proof
- not Lambda invocation behavior
- not generic Deny correctness
- not resource-policy Deny support except unsupported/static-only row labeling
- not SCP Deny support beyond selected benchmark behavior
- no composite benchmark score
- no pass/fail benchmark label
