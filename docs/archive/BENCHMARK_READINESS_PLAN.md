# Benchmark Readiness Plan

## Flagship Path To Benchmark
- **Env 5 AR-1 blocked-chain acceptance path** via `scripts/run_env05_first_benchmark.sh`
- Real workflow: minimal IAM-only deploy -> `iamscope collect --standalone` -> emit scenario + findings -> compare observed findings against expected blocked/inconclusive outcomes

## Test Goals
1. Prove IAMScope can collect and emit truthful findings for a structurally valid but runtime-blocked chain.
2. Preserve the distinction between:
   - declared graph structure
   - blocked path (`assume_role_chain`)
   - inconclusive path (`admin_reachability` demoted by cross-reasoner evidence)
3. Save enough artifacts to inspect or diff the run later.

## Success / Failure Criteria

### Success
- `acceptance/env05_ar1_blocked_chain/run.sh` exits `0`
- Assertions hold:
  - exactly one `assume_role_chain` finding for `alice -> admin` with `verdict=blocked`
  - exactly one `admin_reachability` finding for `alice -> admin` with `verdict=inconclusive`
  - the `admin_reachability` finding includes a `cross_reasoner_blocked` blocker with `constraint_id=null`
- `iamscope validate <scenario.json>` passes on the collected scenario artifact

### Failure
- Terraform deploy or destroy fails
- `iamscope collect` fails or does not emit `findings.json`
- Any Env 5 jq assertion fails
- Scenario validation fails on emitted `scenario.json`

## How To Read Outcome States In This First Pass
- **blocked**: IAMScope has concrete blocker evidence that the path is not runtime-effective
- **confounded**: external ambiguity prevents a truthful claim (not expected in Env 5)
- **inconclusive**: IAMScope refuses to overclaim validated reachability; in Env 5 this is the truthful demotion of `admin_reachability`

## First Environments / Fixtures
- **Use first:** `acceptance/env05_ar1_blocked_chain`
- **Use second, if needed:** `acceptance/env03_cc1_identity_deny`
- **Do not start with:** `acceptance/serim-lab`, `acceptance/serim-lab-v2`, or ARF wrapper workflows

## Exact First Benchmark Pass Command Sequence

```bash
cd <local-iam-scope-repo>
source .venv/bin/activate
bash scripts/run_env05_first_benchmark.sh
```

Optional explicit artifact location:

```bash
cd <local-iam-scope-repo>
source .venv/bin/activate
IAMSCOPE_BENCHMARK_OUT=/tmp/iamscope-benchmark-env05-manual \
  bash scripts/run_env05_first_benchmark.sh
```

## Artifacts To Save From Each Run
- `run.log`
- `expected_findings.json`
- `collect/scenario.json`
- `collect/binding_metadata.json`
- `collect/findings.json`
- `scenario_validate.txt` (if scenario emission succeeded)

All are saved under the wrapper's artifact directory in `/tmp` by default.
## Normalize A Live Archive Into A Phase 0 Run Manifest

```bash
cd <local-iam-scope-repo>
source .venv/bin/activate
bash scripts/ingest_benchmark_archive.sh \
  --case-id env03_identity_deny_group_escalation \
  --archive-dir /tmp/iamscope-benchmark-env03-<RUN_ID> \
  --out benchmarks/runs/env03-<RUN_ID>.json
```

- Required archive files:
  - `run.log`
  - `scenario_validate.txt`
  - `collect/scenario.json`
  - `collect/findings.json`
- Optional archive files:
  - `collect/binding_metadata.json`
  - `expected_findings.json`
## Evaluate A Completed Archive End-To-End

```bash
cd <local-iam-scope-repo>
source .venv/bin/activate
bash scripts/evaluate_benchmark_archive.sh \
  --case-id env05_permission_boundary_blocked_chain \
  --archive-dir /tmp/iamscope-benchmark-env05-20260424T203548Z \
  --out-dir benchmarks/runs/env05-20260424T203548Z
```

Outputs under `--out-dir`:
- `run_manifest.json`
- `scorer_result.json`
- `gate_result.json`
- `report.md`

## Compare Expected vs Observed
- Primary comparison: the Env 5 runner's built-in jq assertions against `findings.json`
- Ground truth reference: `acceptance/env05_ar1_blocked_chain/expected_findings.json`
- Structural guardrail: `iamscope validate` output for collected `scenario.json`
- Optional deeper follow-up: inspect `findings.json` manually or use `iamscope why` on the emitted finding IDs

## What Not To Conclude Yet
- Do **not** conclude broader multi-account cross-account testing is ready
- Do **not** conclude probe-overlay or ARF workflows are part of the first benchmark path
- Do **not** conclude resource-policy-deny is test-ready
- Do **not** conclude the whole repo is production-clean just because Env 5 passes

## Summarize A Completed Evaluation Corpus

```bash
cd <local-iam-scope-repo>
source .venv/bin/activate
bash scripts/summarize_benchmark_corpus.sh \
  --runs-dir benchmarks/runs \
  --out-dir benchmarks/corpus-runs/phase0-latest
```

Outputs under `--out-dir`:
- `corpus_summary.json`
- `promotion_decision.json`
- `corpus_report.md`
## Materialize A Phase 0 Corpus From Explicit Archives

```bash
cd <local-iam-scope-repo>
source .venv/bin/activate
bash scripts/materialize_phase0_corpus.sh \
  --env03-archive /tmp/iamscope-benchmark-env03-20260424T025701Z \
  --env05-archive /tmp/iamscope-benchmark-env05-20260424T203548Z \
  --env06-archive /tmp/iamscope-benchmark-env06-20260424T044157Z \
  --env07-archive /tmp/iamscope-benchmark-env07-20260424T222444Z \
  --env08-archive /tmp/iamscope-benchmark-env08-20260425T002835Z \
  --env09-archive /tmp/iamscope-benchmark-env09-20260425T012013Z \
  --env10-archive /tmp/iamscope-benchmark-env10-<RUN_ID> \
  --env11-archive /tmp/iamscope-benchmark-env11-<RUN_ID> \
  --env12-archive /tmp/iamscope-benchmark-env12-<RUN_ID> \
  --env13-archive /tmp/iamscope-benchmark-env13-<RUN_ID> \
  --env14-archive /tmp/iamscope-benchmark-env14-<RUN_ID> \
  --env15-archive /tmp/iamscope-benchmark-env15-<RUN_ID> \
  --env16-archive /tmp/iamscope-benchmark-env16-<RUN_ID> \
  --out-root benchmarks/runs \
  --corpus-out benchmarks/corpus-runs/phase0-latest
```

Outputs:
- evaluated run directories under `benchmarks/runs/`
- `benchmarks/corpus-runs/phase0-latest/corpus_summary.json`
- `benchmarks/corpus-runs/phase0-latest/promotion_decision.json`
- `benchmarks/corpus-runs/phase0-latest/corpus_report.md`
## Freeze A Repo-Local Phase 0 Snapshot

```bash
cd <local-iam-scope-repo>
source .venv/bin/activate
bash scripts/freeze_phase0_benchmark_snapshot.sh \
  --runs-dir /tmp/iamscope-phase0-runs \
  --corpus-dir /tmp/iamscope-phase0-corpus-latest \
  --snapshot-id phase0-20260424 \
  --out-root benchmarks/snapshots
```

Outputs:
- `benchmarks/snapshots/<snapshot-id>/README.md`
- `benchmarks/snapshots/<snapshot-id>/runs/...`
- `benchmarks/snapshots/<snapshot-id>/corpus/corpus_summary.json`
- `benchmarks/snapshots/<snapshot-id>/corpus/promotion_decision.json`
- `benchmarks/snapshots/<snapshot-id>/corpus/corpus_report.md`
## Update The Frozen Snapshot Index

```bash
cd <local-iam-scope-repo>
source .venv/bin/activate
bash scripts/update_benchmark_snapshot_index.sh \
  --snapshots-dir benchmarks/snapshots \
  --out benchmarks/snapshots/INDEX.md
```
