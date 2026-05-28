# Session 5 design decisions — `iamscope verify` v1 → v2 evolution

## Context

`iamscope/verify.py` has been in the codebase since the v0.2.35
baseline. It implements a v1 IAM simulator verification capability:
`iamscope verify --findings <path> --profile <name>` calls
`iam:SimulatePrincipalPolicy` for each validated
`secrets_blast_radius` finding and compares the simulator's decision
against iamscope's verdict.

v1 had zero test coverage until Session 5 Step 1 added 12
characterization tests pinning every code path. v2 extends v1 with
broader pattern support, structured output, and conservative
handling of edge cases (conditions, multi-hop findings).

v2 ships as v0.3.0. **v0.3.0 does not ship until real-AWS
acceptance testing confirms correct behavior** — moto-only
completion is necessary but not sufficient.

---

## Section 1 — v1 behaviors preserved in v2

### Exit codes

| Code | Meaning | Preserved? |
|------|---------|------------|
| 0 | All verified findings agreed (or nothing to verify) | Yes |
| 1 | One or more disagreements | Yes |
| 2 | File/argument/session error | Yes |

### CLI arguments

| Argument | v1 | v2 | Notes |
|----------|----|----|-------|
| `--findings` | Required, path to findings.json | **Kept** | Backward compatible. No `--input` alias — one name for one thing. The argument name is already clear and matches the file it references. |
| `--profile` | Required, AWS profile name | Kept | |
| `--output` | Optional, path to write report | Kept | Output format changes (see Section 2) |
| `--check-target-state` | Flag, enables liveness check | **Kept and extended** | v2 preserves the liveness check as an independent verification signal alongside `simulator_verdict`. A finding can be `simulator_validated` but `target_state=missing` — both signals are now visible in the output. |

### Module location and entry point

- `iamscope/verify.py` stays as the module location. No move to
  `iamscope/verification/` package — the module is self-contained
  and doesn't need sub-modules yet.
- `cmd_verify(args)` stays as the entry point called by
  `cli.py:266-268`.

### Per-finding error handling

v1's pattern of catching `ClientError`/`BotoCoreError` per finding
and continuing the loop (rather than aborting the entire run) is
preserved. A single finding's API failure doesn't prevent other
findings from being verified.

---

## Section 2 — v1 behaviors changed in v2

### Pattern support expansion

| Pattern | v1 | v2 | Simulator action |
|---------|----|----|------------------|
| `secrets_blast_radius` | Supported | Supported | `secretsmanager:GetSecretValue` |
| `cross_account_trust` | Skipped | **Supported** | `sts:AssumeRole` |
| `passrole_lambda` | Skipped | **Supported** | `iam:PassRole` |
| `passrole_ecs` | Skipped | **Supported** | `iam:PassRole` |
| `s3_bucket_takeover` | Skipped | **Supported** | `s3:PutBucketPolicy` |
| `admin_reachability` | Skipped | **Inconclusive** | N/A — multi-hop |
| `assume_role_chain` | Skipped | **Inconclusive** | N/A — multi-hop |
| `iam_group_membership_escalation` | Skipped | **Inconclusive** | N/A — multi-hop |

Multi-hop patterns return `simulator_inconclusive` with reason
`"multi-hop finding requires per-hop simulator chaining — deferred
to future session"`. This is strictly better than v1's silent skip:
operators see explicit coverage gaps rather than wondering whether
a finding was checked.

### Output format — structured `simulator_verdict`

v1 writes a separate report dict with flat fields (`agreement`,
`simulator_decision`, `target_state`). v2 replaces this with a
structured `simulator_verdict` object on each finding in the
annotated findings.json:

```json
{
  "simulator_verdict": {
    "result": "simulator_validated",
    "simulated_action": "secretsmanager:GetSecretValue",
    "simulated_resource": "arn:aws:secretsmanager:...",
    "simulated_principal": "arn:aws:iam::111:user/Alice",
    "context_keys_applied": [],
    "raw_api_response_digest": "sha256hex...",
    "reason": "simulator EvalDecision=allowed agrees with validated verdict",
    "timestamp": "2026-04-13T14:30:00Z"
  }
}
```

The `result` field has three possible values:
- `simulator_validated` — AWS agrees the action is allowed
- `simulator_disagreement` — AWS says denied (explicit or implicit)
- `simulator_inconclusive` — couldn't evaluate (conditions,
  multi-hop, API error, unsupported pattern)

Findings emitted without simulator verification have
`"simulator_verdict": null` (explicit null, not absent — makes the
field's presence predictable for downstream parsers).

### Condition handling — conservative for v0.3.0

Any finding whose evidence includes edges with non-empty
`raw_conditions` returns `simulator_inconclusive` with reason
`"conditional finding requires manual verification — simulator-based
validation of conditional edges requires context-key mapping design
deferred to future session"`.

This is conservative on purpose: the IAM simulator can evaluate
conditions if given the right context keys, but mapping iamscope's
`raw_conditions` dict to simulator `ContextEntries` requires a
per-condition-key translation layer that doesn't exist yet.
Producing `simulator_validated` for a conditioned finding without
passing the condition keys would be misleading — the simulator would
evaluate the action as if no conditions exist, which is only correct
if the conditions are satisfied. Better to say "I can't tell" than
to say "yes" without checking the conditions.

### Coverage visibility

v1 silently skips findings that don't match the pattern+verdict
filter. v2 emits explicit `simulator_inconclusive` entries for
findings that are in scope but can't be evaluated (multi-hop,
conditional, API error). Non-validated findings (verdict !=
"validated") are still not simulated — there's no "iamscope says
yes" to verify against — but v2 may optionally emit a
`simulator_verdict: null` for them if the `--annotate-all` flag
is added in a future session.

---

## Section 3 — v1 behaviors evaluated and kept as-is

### `_check_secret_target_state()` defensive error handling

The function handles five cases: `live`, `pending_deletion`,
`missing` (ResourceNotFoundException), `access_denied`, and generic
`error`. Each returns a tuple `(status, reason)` without raising.
This is well-written and the characterization test for
`test_missing_target_demotes_agreement` pins the demotion path.
Kept as-is.

### File-level error handling

Both `FileNotFoundError` (findings path doesn't exist) and
`json.JSONDecodeError` return exit code 2 with a logged error.
Clean and predictable. Kept as-is.

### Per-finding error continuation

A `ClientError` on `simulate_principal_policy` for one finding
appends an `agreement: "error"` result and continues to the next
finding. The overall exit code is still determined by the
disagreement count, not by errors. This is the right behavior for a
verification tool: partial results are better than no results.

---

## Section 4 — New v2 capabilities not present in v1

### `SimulatorVerdict` dataclass

Defined in `iamscope/verify.py` (co-located with the module that
produces it). Fields:

| Field | Type | Description |
|-------|------|-------------|
| `result` | `str` | `simulator_validated` / `simulator_disagreement` / `simulator_inconclusive` |
| `simulated_action` | `str` | Action passed to simulator (e.g. `secretsmanager:GetSecretValue`) |
| `simulated_resource` | `str` | Resource ARN passed to simulator |
| `simulated_principal` | `str` | Principal ARN passed to simulator |
| `context_keys_applied` | `list[str]` | Context key names (always `[]` in v0.3.0) |
| `raw_api_response_digest` | `str` | SHA-256 hex of the raw API response body |
| `reason` | `str` | Human-readable explanation |
| `timestamp` | `str` | ISO 8601 UTC timestamp of the simulator call |

### Raw API response digest

`hashlib.sha256(json.dumps(response, sort_keys=True).encode()).hexdigest()`
computed over the full `simulate_principal_policy` response dict.
Stored in `raw_api_response_digest`. Purpose: auditability — a
future reviewer can re-run the simulator call and compare digests
to confirm iamscope reported what AWS actually said. For
`simulator_inconclusive` verdicts where no API call was made, the
digest is an empty string `""`.

### Pattern-specific action derivation

v1 hardcodes `_ACTION_FOR_PATTERN = {"secrets_blast_radius":
"secretsmanager:GetSecretValue"}`. v2 extends this map:

```python
_ACTION_FOR_PATTERN = {
    "secrets_blast_radius": "secretsmanager:GetSecretValue",
    "cross_account_trust": "sts:AssumeRole",
    "passrole_lambda": "iam:PassRole",
    "passrole_ecs": "iam:PassRole",
    "s3_bucket_takeover": "s3:PutBucketPolicy",
}
```

### Canonical hash exclusion

`simulator_verdict` is added to finding dicts AFTER the
`findings.json` canonical hash is computed. The `iamscope verify`
command reads an already-emitted `findings.json`, adds
`simulator_verdict` to each finding dict at the JSON layer, and
writes the annotated version. The canonical hash is preserved from
the original — no recomputation needed because
`simulator_verdict` was never in the hash payload.

This is structurally safe: `_finding_to_dict()` in
`findings_json.py` produces dicts with a fixed set of keys that
does not include `simulator_verdict`. The verify command operates
on the serialized JSON, not on `Finding` dataclass instances.

A regression test (Step 4) will assert: emit findings.json, run
verify to annotate, recompute canonical hash from the annotated
version's finding dicts (excluding `simulator_verdict`), assert
equal to the original canonical hash.

---

## Section 5 — Pinning test breakage anticipated by Step 3+

Each of the 12 characterization tests in
`tests/test_verify_v1_characterization.py` and its expected
disposition when v2 changes land:

| Test | Class | Breaks in Step | Reason |
|------|-------|----------------|--------|
| `test_agreement_returns_exit_0` | HappyPath | **No** | Exit code semantics preserved |
| `test_agreement_writes_output_report` | HappyPath | **Step 3** | Output report shape changes to structured `findings_verification` |
| `test_explicit_deny_returns_exit_1` | Disagreement | **No** | Exit code semantics preserved |
| `test_implicit_deny_returns_exit_1` | Disagreement | **No** | Exit code semantics preserved |
| `test_client_error_returns_exit_0_when_only_finding` | ApiError | **Step 3** | Output report shape changes; v2 maps API errors to `simulator_inconclusive` (exit code 0 preserved) |
| `test_cross_account_trust_skipped` | UnsupportedPattern | **Step 4** | cross_account_trust moves from "unsupported" to "supported" — boto3.Session WILL be called |
| `test_inconclusive_verdict_skipped` | UnsupportedPattern | **No** | Non-validated verdicts are still not simulated in v2 |
| `test_empty_findings_list` | UnsupportedPattern | **No** | Empty input handling unchanged |
| `test_live_target_preserves_agreement` | TargetStateCheck | **Step 3** | Output report shape changes to `findings_verification` with separate `target_state` sibling |
| `test_missing_target_demotes_agreement` | TargetStateCheck | **Step 3** | Output report shape changes; simulator_verdict stays `simulator_validated`, target_state demotes `final_verdict` to `"disagreed"` |
| `test_missing_file_returns_exit_2` | FileErrors | **No** | File error handling preserved |
| `test_invalid_json_returns_exit_2` | FileErrors | **No** | JSON error handling preserved |

**Summary (corrected in Step 3):** 8 of 12 tests pass v2 unchanged.
4 tests break deliberately — all 4 read the `--output` report shape
which changed from v1's flat `results: [...]` to v2's
`findings_verification: {fid: {simulator_verdict, target_state,
final_verdict}}`. The original prediction missed 3 of the 4 because
it checked the primary behavioral claim per test (exit code, error
handling, demotion logic) without verifying whether each test also
asserted on the output report shape. Lesson: when changing an output
format, grep every test for the old format's field names, not just
the test whose name contains "output".
- `test_agreement_writes_output_report` — output format changes
  (Step 3). Will be updated to assert the new structured
  `simulator_verdict` shape.
- `test_cross_account_trust_skipped` — `cross_account_trust`
  becomes supported (Step 4). Will be updated to assert simulator
  is called and returns `simulator_validated` or
  `simulator_inconclusive` depending on conditions.

Both breakages are intentional behavior changes, not regressions.
Each will be updated in the same commit that introduces the
breaking change, with the commit message documenting the deliberate
test update.

---

## Section 6 — Not in v2 (deferred to future sessions)

### Inline `--verify-simulator` flag on `iamscope scan`

v0.3.0 keeps verification decoupled from scanning. The operator
runs `iamscope scan` to produce findings.json, then runs
`iamscope verify` as a separate step. Inline integration (verify
during scan) deferred to Session 6+ — it couples scan latency to
verification latency and complicates error handling.

### Context-key mapping for conditional findings

The IAM simulator can evaluate conditions if given
`ContextEntries`. Mapping iamscope's `raw_conditions` dict to
simulator context keys requires a per-condition-key translation
layer. Deferred to Session 6+.

### Multi-hop per-hop simulator chaining

`admin_reachability` and `assume_role_chain` findings describe
multi-hop paths. Verifying them requires calling the simulator for
each hop and composing the results. Deferred — the composition
logic has trust-boundary subtleties (each hop's principal is the
previous hop's target, and the simulator doesn't model assumed-role
session context).

### Cross-account simulator calls

The IAM simulator evaluates policies from the perspective of the
`PolicySourceArn`'s account. Cross-account simulation requires
either (a) credentials in both accounts or (b) AWS Organizations
integration with `iam:SimulatePrincipalPolicy` delegated access.
v0.3.0 assumes the verify profile has permissions in the account
where the principal lives. Cross-account deferred.

### Automatic re-verification on findings.json regeneration

When a new scan produces a new findings.json, previously verified
findings lose their `simulator_verdict` annotations. Automatic
re-verification (detect stale annotations, re-run verification)
deferred.
