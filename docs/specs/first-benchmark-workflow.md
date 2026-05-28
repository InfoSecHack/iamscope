# First Benchmark Workflow

Supported first testing workflow in this repo:

1. Run the Env 5 AR-1 blocked-chain acceptance path through `scripts/run_env05_first_benchmark.sh`.
2. Let the wrapper execute the existing real-AWS Env 5 runner in a disposable temp copy so repo-local Terraform artifacts are not mutated.
3. Treat success as a narrow claim: IAMScope truthfully distinguishes a blocked chain from a merely declared path, and preserves an inconclusive demotion where a naive reachability pass would overclaim.

This workflow is intentionally narrow:
- real AWS
- single account
- `--standalone`
- IAM-only resources
- no Organizations dependency
- no probe-overlay requirement
- no ARF dependency

It is the first supported benchmark workflow because it is the smallest existing live path that exercises IAMScope's strongest current value: truthful reachability judgment.

Not part of this first workflow:
- SeRIM multi-account labs
- ARF wrapper validation
- resource-policy-deny
- broad repo hygiene cleanup
