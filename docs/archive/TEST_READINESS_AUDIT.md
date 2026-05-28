# Test Readiness Audit

## 1. Executive Judgment

### Ready to test now
- **Primary controlled AWS path:** `acceptance/env05_ar1_blocked_chain/run.sh` through the new wrapper `scripts/run_env05_first_benchmark.sh`.
- This path is the strongest immediate operator test because it is:
  - real AWS, not fixture-only
  - single-account and `--standalone`, so it avoids Organizations noise
  - low cost (IAM-only)
  - focused on IAMScope's strongest current value: truthful reachability judgment when a structurally present path is blocked at runtime by governance
  - already backed by a concrete expected outcome file and jq assertions

### Not ready as a first controlled test path
- `acceptance/serim-lab` and `acceptance/serim-lab-v2`: implemented and documented, but heavier and more environment-dependent (multiple accounts, OU placement, profiles, truth probes, Terraform vars). Better as later-stage validation, not the first benchmark pass.
- ARF wrapper path: already proven separately, but not the right first readiness path for controlled AWS testing here.
- resource-policy-deny: explicitly de-scoped, not a testing-ready flagship surface.

### Noisy but non-blocking
- Broad dirty branch state and many unrelated modified files.
- Checked-in Terraform state in acceptance envs is messy, but the new wrapper avoids polluting the repo for the flagship Env 5 pass.
- Repo-wide hygiene is imperfect, but the core small acceptance path is still usable.

## 2. Flagship Path Recommendation

### Chosen primary path
- **Env 5 AR-1 blocked-chain acceptance path**
- Workflow: deploy minimal IAM-only lab -> `iamscope collect --standalone` -> emit `scenario.json` / `binding_metadata.json` / `findings.json` -> assert blocked and inconclusive outcomes -> archive artifacts

### Why this is the best current first path
- Exercises real IAMScope collection and findings emission against live AWS.
- Tests truthful differentiation between structural reachability and runtime-effective blockage.
- Uses the smallest existing live AWS environment in the repo that already has explicit expected outcomes.
- Avoids Organizations/SCP inheritance confounders that make broader labs less credible as a first pass.
- Does not depend on probe overlays, replay, ARF, or multi-account lab choreography.

## 3. Readiness Matrix

| Surface | Status | Confidence | Notes |
|---|---|---|---|
| `collect` (standalone single-account) | implemented, wired | likely good | Real acceptance envs call it; flagship path depends on it. Not manually re-run in this session because it would touch live AWS. |
| scenario emission | implemented, wired | likely good | Used by collect and validated by `validate.py`; flagship wrapper saves it. |
| findings emission | implemented, wired | likely good | Acceptance envs assert against `findings.json`; `finding_key` contract already fixed earlier. |
| `validate` CLI / structural scenario validation | implemented, wired | likely good | Local targeted tests pass. Useful as a post-collect guardrail, not primary truth proof. |
| `replay-findings` | implemented, wired | likely good | Local targeted tests pass. Best treated as secondary offline analysis, not first live test path. |
| `probe-overlay` | implemented, wired | likely good | Local targeted tests pass. Valuable later, but not needed for first controlled AWS path. |
| `diff-findings` / `demo-pack` | implemented, wired | likely good | Local targeted tests pass. Useful for analysis and handoff after first live runs. |
| `verify` | implemented, wired | unverified | Code exists and tests exist, but not the right first benchmark path; also narrower pattern support. |
| `acceptance/env03_cc1_identity_deny` | implemented, wired | likely good | Small real-AWS env, but less central than Env 5 to current flagship value of truthful path blockage. |
| `acceptance/env05_ar1_blocked_chain` | implemented, wired | likely good | Best first live path. Existing script had one hidden first-run blocker (`terraform init`) now fixed. |
| `acceptance/serim-benchmark` | implemented | likely good | Deterministic local benchmark exists, but it measures planner behavior, not first controlled AWS truth testing. Secondary, not flagship. |
| `acceptance/serim-lab*` | implemented, claimed | unverified | Richer labs exist but are heavier and more confounded. Not first-pass ready for credible controlled testing. |
| resource-policy-deny | de-scoped | definitely broken for end-to-end testing | Not a candidate testing surface now. |

## 4. Blockers

### Blocking test execution now
- **Hidden first-run Terraform dependency in Env 5 runner**: `acceptance/env05_ar1_blocked_chain/run.sh` did not run `terraform init`. Fixed in this pass.
- **Repo-polluting local Terraform artifacts**: running Env 5 in-place would modify local state/workdir files. Mitigated in this pass by `scripts/run_env05_first_benchmark.sh`, which uses a disposable temp copy.

### Blocking benchmark credibility
- No repeated-run scorecard or aggregation for the live AWS Env 5 path yet.
- No clean multi-environment comparison layer yet; first pass should stay narrow and claim only that Env 5 behaves as expected.
- Larger multi-account SeRIM labs remain unproven as a clean first validation surface.

### Non-blocking repo hygiene
- Broad dirty branch churn.
- Older docs with hardcoded historical paths under acceptance/serim-*.
- Checked-in Terraform state files in acceptance env folders.

## 5. Exact Minimal Fix Plan To Start Testing Now
- Fix Env 5 runner to self-initialize Terraform.
- Add one disposable benchmark wrapper that runs Env 5 without dirtying the repo and archives outputs.
- Add one concise operator workflow spec and one benchmark plan so the first supported path is explicit.
- Do **not** broaden beyond Env 5 for this pass.
