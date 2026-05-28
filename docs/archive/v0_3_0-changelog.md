# IAMScope v0.3.0 — simulator verification capability

**Date:** 2026-04-14
**Commit range:** `aeb4e02` (v0.2.39) → `v0.3.0`
**Test count:** 1204 (v0.2.39) → 1236 (+32 net)

## Summary

v0.3.0 adds **IAM simulator verification** as a correctness gate for
iamscope findings. The `iamscope verify` subcommand — inherited from
v0.2.35 as an untested v1 prototype supporting only
`secrets_blast_radius` — has been characterized with pinning tests,
extended to 5 patterns, restructured with typed dataclasses, validated
against real AWS, and shipped with 32 new tests. This is Session 5's
work on top of v0.2.39's completed tactical build plan.

**Ship gate: Option B (real-AWS acceptance required).** v0.3.0 was
validated against a test AWS account with known-good and
known-bad IAM configurations before shipping. Unit and integration tests with stubbed boto3 clients were necessary
but not sufficient — real AWS is the only path that exercises the
actual simulator endpoint. Step 7 integration tests pivoted from moto
to `unittest.mock.patch` because moto 5.1.22 does not implement
`iam:SimulatePrincipalPolicy`.

## Capabilities added

### Simulator verification via `iamscope verify`

The `iamscope verify` subcommand calls `iam:SimulatePrincipalPolicy`
for each eligible finding and compares AWS's authorization decision
against iamscope's verdict. Findings where AWS agrees are
`simulator_validated`; disagreements are `simulator_disagreement`
(cases warranting investigation — either iamscope false positives or
simulator blind spots such as resource-based policies, KMS key
policies, or conditions the simulator evaluates conservatively); findings that couldn't be
evaluated are `simulator_inconclusive` with a documented reason.

### 5-pattern support

| Pattern | Simulator action | v1 | v0.3.0 |
|---------|------------------|----|----|
| `secrets_blast_radius` | `secretsmanager:GetSecretValue` | Supported | Supported |
| `cross_account_trust` | `sts:AssumeRole` | Skipped | **Supported** |
| `passrole_lambda` | `iam:PassRole` | Skipped | **Supported** |
| `passrole_ecs` | `iam:PassRole` | Skipped | **Supported** |
| `s3_bucket_takeover` | `s3:PutBucketPolicy` | Skipped | **Supported** |

### Multi-hop patterns: explicit inconclusive

`admin_reachability`, `assume_role_chain`, and
`iam_group_membership_escalation` findings return
`simulator_inconclusive` with reason *"multi-hop finding requires
per-hop simulator chaining — deferred to future session"*. Previously
silently skipped; now explicitly documented in the output.

### Source-type gating for `cross_account_trust`

`iam:SimulatePrincipalPolicy` requires a specific IAM user or role
ARN as `PolicySourceArn`. For `cross_account_trust` findings whose
source is `AccountPrincipalSet` (account root ARN) or `OIDCProvider`,
the simulator cannot be called — these return `simulator_inconclusive`
with a documented reason naming the source type.

### Structured output schema

Per-finding verification results are grouped under
`findings_verification.<finding_id>` with three sibling keys:

- **`simulator_verdict`** (8 fields): `result`, `simulated_action`,
  `simulated_resource`, `simulated_principal`, `context_keys_applied`,
  `raw_api_response_digest`, `reason`, `timestamp`
- **`target_state`** (4 fields): `checked`, `state`, `reason`,
  `timestamp`
- **`conditions_signal`** (3 fields): `conditions_present`,
  `detected_via`, `note`
- **`final_verdict`**: aggregated string (`agreed` / `disagreed` /
  `inconclusive`)

Simulator and target-state are semantically different signals — the
simulator evaluates authorization policy, the liveness check evaluates
runtime resource state. They live as sibling keys so future
`RuntimeVerificationVerdict` from the roadmap can slot in cleanly.

### `--check-target-state` flag

Preserved from v1. In v0.3.0, the liveness check is scoped to
`secrets_blast_radius` findings only (queries SecretsManager
`DescribeSecret`). For other patterns, `target_state` reports
`{checked: false, state: "not_applicable"}`. Generalized liveness
checking is deferred (see Known limitations).

### Raw API response digest

Every `simulator_verdict` includes `raw_api_response_digest`: the
SHA-256 hex of the full `simulate_principal_policy` response body
(serialized with `json.dumps(sort_keys=True, default=str)`). For
`simulator_inconclusive` verdicts where no API call was made, the
digest is `""`. Purpose: auditability — a reviewer can re-run the
simulator call and compare digests to confirm iamscope reported what
AWS actually said.

### Canonical hash stability

`simulator_verdict`, `target_state`, `conditions_signal`, and
`final_verdict` are added to finding dicts AFTER the `findings.json`
canonical hash is computed. The `iamscope verify` command operates
on already-emitted JSON — it reads the file, adds annotations, and
writes the annotated version. The original `canonical_hash` is
preserved unchanged. Verified by a regression test in Step 7 (Test 1:
compute hash before verify, recompute after, assert equal).

## Quality improvements

- **32 new tests** across 3 new test files:
  - `tests/test_verify_v1_characterization.py` — 12 pinning tests
    documenting every v1 code path before v2 changes landed
  - `tests/test_verify_v2_pattern_extension.py` — 17 tests covering
    per-pattern happy/disagreement paths, source-type gating,
    multi-hop inconclusive, conditions signal, and liveness scoping
  - `tests/test_verify_v2_moto_integration.py` — 3 end-to-end tests
    proving the full pipeline works (multi-finding interaction,
    canonical hash stability, source-type control flow)
- **Real-AWS acceptance testing** completed against a dedicated test
  account (see Acceptance test results below)
- **1 inherited v1 defect surfaced and fixed** (Step 7.5):
  `_check_secret_target_state` constructed a malformed endpoint URL
  (`secretsmanager..amazonaws.com`) for IAM role ARNs whose region
  segment is empty. Scoped the liveness check to
  `secrets_blast_radius` findings only.
- **Design decisions documented** in `docs/session-5-design.md`:
  v1 behaviors preserved/changed, pinning test breakage predictions,
  deferred capabilities

## Breaking changes vs v0.2.39

- **`iamscope verify` output format changed.** v1's flat
  `results: [...]` array replaced by v2's structured
  `findings_verification: {<finding_id>: {simulator_verdict,
  target_state, conditions_signal, final_verdict}}`. v1 had zero
  test coverage and no known users, so this is not a practical
  compatibility break — but noted explicitly for auditability.
- **Exit code semantics preserved:** 0 = all agreed or nothing to
  verify, 1 = one or more disagreements, 2 = file/session error.

## Known limitations in v0.3.0

- **`--check-target-state` scoped to `secrets_blast_radius`.**
  Liveness check only queries SecretsManager's `DescribeSecret`.
  Other patterns receive `target_state.state = "not_applicable"`.
  Generalized liveness checking (`iam:GetRole`, `s3:HeadBucket`,
  etc.) is deferred to a future session.
- **Conditional findings simulated unconditionally.**
  `conditions_signal.conditions_present = true` is an operator
  breadcrumb, not a simulator gate. Context-key mapping to
  `--context-entries` is deferred.
- **Multi-hop patterns are explicit inconclusive.** Per-hop
  simulator chaining is deferred.
- **Non-IAM source types cannot be simulated.** `AccountPrincipalSet`
  and `OIDCProvider` sources return `simulator_inconclusive` because
  `SimulatePrincipalPolicy` requires a specific IAM user or role ARN.
- **moto does not implement `SimulatePrincipalPolicy`.** Step 7
  integration tests use `unittest.mock.patch` on `boto3.Session`
  rather than moto. Real AWS is the only test path for the
  simulator's actual behavior.

## Acceptance test results

**Account:** iamscope-test (test AWS account)
**Profile:** `iamscope-test`
**Resources:** 1 IAM user with inline policies, 1 Secrets Manager
secret, 1 IAM role with Lambda trust policy (provisioned via
Terraform in `acceptance/step8/`)

3 findings tested:

| Finding | Pattern | Expected | Actual | Target state |
|---------|---------|----------|--------|-------------|
| `1111...` | `secrets_blast_radius` | `simulator_validated` | `simulator_validated` | `live` |
| `2222...` | `passrole_lambda` | `simulator_validated` | `simulator_validated` | `not_applicable` |
| `3333...` | `cross_account_trust` | `simulator_disagreement` | `simulator_disagreement` | `not_applicable` |

- **Exit code:** 1 (one disagreement, as expected)
- **Agreements:** 2 (secrets + passrole, as expected)
- **Disagreements:** 1 (cross_account_trust, as expected — target
  role's trust policy does not trust the source principal)
- **`raw_api_response_digest`:** populated with non-empty SHA-256
  hex for all 3 findings (confirms AWS returned a response and
  iamscope hashed it)
- **Step 7.5 fix verified:** Finding 2 (`passrole_lambda`, IAM role
  target with empty region segment) correctly returned
  `target_state.state = "not_applicable"` instead of crashing with
  the v1 endpoint URL bug

## Session 5 commit chain

| Hash | Description |
|------|-------------|
| `19aee6f` | Step 1: characterize v1 with 12 pinning tests |
| `dd9ec54` | Step 2: design decisions document |
| `e23cb86` | Step 3: SimulatorVerdict/TargetStateCheck dataclasses + v2 output |
| `83d3665` | Step 4: 5-pattern support + multi-hop + source-type gating |
| `3dbc20a` | Step 7: end-to-end integration tests + hash stability |
| `2fd8012` | Step 7.5: scope --check-target-state to secrets_blast_radius |
| `7d3843d` | Step 8: real-AWS acceptance artifacts |

## Post-v0.3.0 roadmap (preview)

See `~/projects/post-v0.2.39-roadmap.md` (active planning document).
Key items for next sessions:

- **Generalized resource liveness checking** — `iam:GetRole`,
  `s3:HeadBucket`, cross-account liveness via assume-role attempt
- **Context-key mapping** — translate `raw_conditions` to simulator
  `ContextEntries` for conditional findings
- **Multi-hop per-hop chaining** — call simulator for each hop in
  `admin_reachability` and `assume_role_chain` findings
- **Inline `--verify-simulator` on scan** — decouple verification
  from the separate `iamscope verify` subcommand into an optional
  inline step during `iamscope scan`
- **Systematic explicit-deny audit** — extend SCP/boundary analysis
- **IAM simulator comparison harness** — calibrate iamscope's
  confidence against the simulator across large policy sets
