# IAMScope

**Research-preview AWS IAM reasoning tool with bounded evidence and explicit non-claims.**

Start here: [`docs/START_HERE.md`](docs/START_HERE.md) gives reviewers the shortest safe orientation path: evidence boundaries, local validation commands, approval gates, and the recommended reading order.

IAMScope collects AWS IAM facts, builds a deterministic fact graph, runs pattern reasoners against it, and emits byte-locked findings in one of four verdicts: **`validated`**, **`blocked`**, **`inconclusive`**, or **`precondition_only`**. Every finding carries the exact evidence that supports the verdict: statement digests, edge IDs, constraint IDs, and a step-by-step reasoning trace. If the tool cannot prove a privilege escalation chain is supported by the collected evidence, it says so. It does not default to "probably exploitable" and it does not emit a composite score.

## Research and evidence status

IAMScope should currently be read as a research-preview, bounded evidence program for selected cloud IAM escalation patterns, not as a production-ready oracle. The repository demonstrates a truth-first analysis model across selected controlled cases and preserves the evidence boundaries around those cases.

For the current support boundary, read [docs/specs/supported-unsupported-evidence-matrix.md](docs/specs/supported-unsupported-evidence-matrix.md).

What the current evidence package demonstrates:

- Frozen live AWS semantic benchmark cases, summarized in [BENCHMARK_STATUS.md](BENCHMARK_STATUS.md), with the latest snapshot at [benchmarks/snapshots/phase0-20260509-env27](benchmarks/snapshots/phase0-20260509-env27).
- Mutation-pair sensitivity, including policy/control changes where one bounded change alters the expected reachability result, summarized in [benchmarks/pair-reports/phase0-20260509-env27-mutation-pairs.md](benchmarks/pair-reports/phase0-20260509-env27-mutation-pairs.md).
- Synthetic scalability and degradation fixtures that exercise large or degraded artifact shapes without claiming real-world scale proof.
- Reporting/comparison and report-only threshold review layers for inspecting frozen and synthetic evidence without turning results into a composite score or pass/fail label.
- Runtime STS denied and assumed standalone proofs, documented in [docs/archive/BENCHMARK_RUNTIME_STS_PROOF_MATURITY_CHECKPOINT.md](docs/archive/BENCHMARK_RUNTIME_STS_PROOF_MATURITY_CHECKPOINT.md).
- Controlled STS validation: Run #1 stopped before live execution as `environment_mismatch`; Run #2 corroborated one selected denied/access_denied STS prediction.
- Active PassRole-to-Lambda controlled validation: one test-only source principal, one test-only target role, and one Lambda `CreateFunction` operation were corroborated under explicit controlled conditions; the function was not invoked, was deleted, and cleanup was verified. This does not prove exploitability or downstream authorization.
- Static controlled Identity Deny suppression evidence: one selected explicit identity-Deny candidate was represented as a controlled report and passed schema/safety validation. This is static/report validation only; no active runtime Deny behavior was observed, and no generic Deny correctness is claimed.
- Artifact hygiene and safety boundaries: no raw AWS artifacts, credentials, `/tmp` outputs, Terraform state/cache/provider artifacts, or generated bundles/reports are committed by default.

What IAMScope does **not** claim:

- No production readiness.
- No broad IAMScope correctness.
- No arbitrary enterprise graph correctness.
- No broad runtime exploitability.
- No downstream AWS authorization proof.
- No generic Deny correctness.
- No generic resource-policy Deny support.
- No SCP Deny support unless explicitly scoped.
- No active Identity Deny runtime validation.
- No finding-level reachability unless explicitly scoped.
- No real-world scalability.
- No all-findings-verified claim.
- No composite benchmark score.

Current maturity status:

- Benchmark evidence is complete for the current scope.
- Runtime STS proof is complete for the current scope.
- Controlled validation is complete for the current scope, including one active service-mediated PassRole-to-Lambda result and one static controlled Identity Deny suppression result.
- The recommended next work is private reviewer feedback and release/research packaging cleanup, not more live probes by default.

Reviewer reading path:

1. [docs/START_HERE.md](docs/START_HERE.md): public reviewer orientation, safe local commands, and approval boundaries.
2. [docs/specs/supported-unsupported-evidence-matrix.md](docs/specs/supported-unsupported-evidence-matrix.md): supported, bounded, and unsupported evidence areas.
3. [docs/releases/research-checkpoint-release-notes.md](docs/releases/research-checkpoint-release-notes.md): research/evidence checkpoint release notes.
4. [docs/specs/final-controlled-validation-maturity-checkpoint.md](docs/specs/final-controlled-validation-maturity-checkpoint.md): final controlled validation maturity checkpoint.
5. [docs/specs/controlled-passrole-active-run-001-result-and-teardown-checkpoint.md](docs/specs/controlled-passrole-active-run-001-result-and-teardown-checkpoint.md): active PassRole-to-Lambda result and teardown boundary.
6. [docs/specs/controlled-identity-deny-run-001-static-validation-checkpoint.md](docs/specs/controlled-identity-deny-run-001-static-validation-checkpoint.md): static Identity Deny report-validation boundary.
7. [docs/specs/controlled-sts-run-002-live-result-checkpoint.md](docs/specs/controlled-sts-run-002-live-result-checkpoint.md): selected controlled STS denied/access_denied result.
8. [docs/specs/release-hygiene-checkpoint.md](docs/specs/release-hygiene-checkpoint.md): release-facing artifact hygiene status.
9. Artifact hygiene: [scripts/check_benchmark_artifact_hygiene.sh](scripts/check_benchmark_artifact_hygiene.sh), which is also run by `./scripts/check.sh`.

## Quick Start (local only)

The default getting-started path works from a fresh clone and is local-only. It makes no AWS calls, no STS probes, no `iam:PassRole` calls, no Lambda API calls, no service launch, and no AWS resource mutations.

```bash
git clone https://github.com/InfoSecHack/iamscope.git
cd iamscope
python3 -m venv .venv
source .venv/bin/activate
python -m pip install --upgrade pip
python -m pip install -e ".[dev]"
./scripts/check.sh
./scripts/test_fast.sh
```

Safe reproduction covers tests, docs, and frozen/sanitized summaries. Live AWS collection, STS probes, `iam:PassRole`, Lambda APIs, service launch, and AWS resource mutation are not part of the default README quickstart; they require a separate protocol, explicit scope, and operator approval.

### Safe local evidence utilities

The helper commands below inspect documented local utilities only. Generated reports or bundles should write under `/tmp` or another caller-provided scratch path and are not committed by default.

```bash
./scripts/generate_controlled_sts_validation_bundle.sh --help
```

`benchmarks/samples/*.log` files are committed sanitized benchmark summaries, not raw AWS debug logs; they contain no credentials or raw `/tmp` outputs.

## Why IAMScope is different

Most IAM analyzers produce output that looks like this:

> `Alice can assume AdministratorRole (high confidence)`

That's a claim. You, the reviewer, have no way to verify it without re-running the analysis yourself. Was there an SCP blocking it? A permission boundary? A session policy the analyzer couldn't see? A wildcard PassRole grant that the analyzer silently expanded to a specific role? You don't know. The tool is asking you to trust it.

IAMScope produces output that looks like this:

> `Alice → LambdaExec via Lambda PassRole chain: inconclusive / high`
> `  required_checks[1]: source_has_passrole_to_target = UNKNOWN`
> `    reason: "matching iam:PassRole edge is a warn-suppressed wildcard → hyperedge dst; cannot prove specific-resource coverage"`
> `  evidence: 3 statement digests, 3 edge refs, 10-step reasoning trace`
> `  scenario_hash: d26ef2d033c0040f...`

That's a verifiable claim. Every piece of supporting evidence has an identifier you can look up in `scenario.json`. The reasoning trace tells you exactly which check failed to pass and why. If the tool refuses to say `validated`, it tells you which specific piece of evidence it couldn't confirm. It does not say "we're 73% sure." It says "check 2 returned UNKNOWN because the witness edge was a hyperedge, here is the edge ID, go look at it."

IAMScope's design goal is evidence-bound output. Every `validated` finding means IAMScope has sufficient modeled evidence under its current rules for the scoped scenario: the permission edge is non-wildcard, the trust policy admits the service principal, the boundary intersection allows the action, no SCP blocks it with complete confidence, and any conditions (like `iam:PassedToService`) evaluate favorably. If any of that is unknowable from collection-time data, the verdict drops to `inconclusive` and the tool tells you why.

This matters because in pentest engagements, false positives destroy client trust. IAMScope is designed so a client reviewer can drill into any `validated` finding and confirm it for themselves, or drill into any `inconclusive` finding and understand exactly what IAMScope would need to see to promote it to `validated`.

## How it works

IAMScope is a four-stage pipeline that produces three sidecar files on disk. Each stage has a concrete artifact.

```
┌─────────────────┐  ┌──────────────┐  ┌─────────────┐  ┌─────────────────┐
│  1. Collector   │→ │ 2. Fact      │→ │ 3. Reasoner │→ │ 4. Findings     │
│                 │  │    graph     │  │    phase    │  │    emitter      │
│  AWS APIs       │  │              │  │             │  │                 │
│  read-only      │  │  Nodes,      │  │  Pattern    │  │  Deterministic  │
│  org / account  │  │  edges,      │  │  matching,  │  │  byte-locked    │
│  / lambda / ec2 │  │  constraints,│  │  evidence   │  │  findings.json  │
│                 │  │  bindings    │  │  assembly   │  │  sidecar        │
└─────────────────┘  └──────────────┘  └─────────────┘  └─────────────────┘
       │                    │                 │                   │
       ▼                    ▼                 ▼                   ▼
  (AWS API calls)      scenario.json     (in-memory only)     findings.json
                       binding_metadata.json
```

1. **Collector.** Read-only walk of an AWS Organization (or a single account in standalone mode). Pulls IAM auth details, trust policies, inline and attached policies, Lambda functions, EC2 instance profiles, SCP policies, permission boundaries. Zero writes.

2. **Fact graph.** Parses collected data into a deterministic graph of nodes (principals, roles, services), edges (trust, permission, service bindings), constraints (SCPs, boundaries), and edge-constraint bindings (which constraint applies to which edge with what governance confidence). Every node and edge ID is a SHA-256 hash of its canonical attributes. Emits `scenario.json` + `binding_metadata.json` sidecar.

3. **Reasoners.** Each reasoner is a pattern matcher for a specific privilege escalation shape. Reasoners run against the fact graph via a `Registry`, walking edges and evaluating a sequence of checks. Each check is in one of three states: `PASS`, `FAIL`, or `UNKNOWN`. The tristate is the core of the refuses-to-lie property: a reasoner that cannot determine whether a condition holds must emit `UNKNOWN` explicitly rather than guessing.

4. **Findings emitter.** Assembles reasoner output into a canonical JSON sidecar with deterministic byte-level output. The canonical hash excludes the run timestamp and duration, so two runs over the same data produce byte-identical hashes. Supports hash-stable diffing across scans.

## The four verdict states

| Verdict | Meaning | Emitted when |
|---|---|---|
| **`validated`** | IAMScope has sufficient modeled evidence under its current evidence rules for the scoped scenario. This does not prove end-to-end exploitability, downstream authorization, production impact, or arbitrary enterprise correctness. | All reasoner checks are `PASS`. Severity depends on modeled blast radius (admin-equivalent targets → `critical`; non-admin → `high`). |
| **`blocked`** | IAMScope has sufficient modeled evidence that the scoped chain is blocked by an active control under current evidence rules. This is not a broad exploitability or runtime-impact claim. | A check returned `FAIL` due to an SCP or permission boundary that explicitly denies the required action with `governance_confidence=complete`. Severity = `info`. |
| **`inconclusive`** | IAMScope cannot determine the verdict because at least one check returned `UNKNOWN`. This is the refuses-to-lie verdict. | Wildcard expansion hyperedge, ambiguous condition, SCP parse_status in `partial` / `needs_review`, unsupported condition operator, or any other case where the tool needs more data. Severity = `high` (this is where client review effort goes). |
| **`precondition_only`** | The pattern's core exists but a specific precondition (not a blocker, but a gate) is not met. Distinct from blocked: the chain isn't actively stopped, it's just incomplete as written. | Check 3 fails (e.g., target role doesn't trust Lambda service for `passrole_lambda`), or a condition scoping constraint like `iam:PassedToService` points away from the expected service. Severity = `medium`. |

Every finding carries an `evidence` block with `statement_digests`, `statement_sources`, `edge_refs`, `constraint_refs`, `edge_constraint_refs`, `node_refs`, `condition_context_assumed`, and a full `reasoning_trace`. The trace is an ordered sequence of steps documenting exactly what the reasoner checked and what it found. Every identifier resolves back to `scenario.json` for independent verification.

## Shipping reasoners

| Reasoner | What it detects | Checks |
|---|---|---|
| **`cross_account_trust`** | External principals (cross-account, wildcard, or OIDC-federated) that can assume a role without strong conditions. SCP and same-org-aware severity downgrades. | 6 checks covering trust principal classification, condition strength, SCP blocking, OIDC `:sub` restriction, same-org membership, wildcard detection. |
| **`passrole_lambda`** | Models the structural Lambda PassRole risk pattern where a principal with Lambda create capability and `iam:PassRole` to a Lambda-trusting role may be able to create a Lambda function using that role, subject to service permissions, conditions, boundaries, SCPs, and runtime context. | 8 checks covering: source has lambda:CreateFunction, source has PassRole to target, target trusts Lambda service, no SCP blocks either action, no boundary blocks either action, `iam:PassedToService` scoped to Lambda or absent. Plus admin-equivalence detection on the target role for severity upgrade (admin target → `critical`, non-admin → `high`). |
| **`passrole_ecs`** | Models the structural ECS PassRole risk pattern where task definition/run permissions plus `iam:PassRole` to an ECS-trusting role may enable task execution using that role, subject to service permissions, conditions, boundaries, SCPs, and runtime context. | 8 checks structurally identical to `passrole_lambda`, but **check 1 combines two actions** (RegisterTaskDefinition AND RunTask) via the reusable `_and_tristate` helper. ECS separates task definition registration from task execution. Both actions are required for the modeled chain. Checks 4 and 6 (SCP/boundary blockers) run against BOTH ECS witnesses and combine results, so an SCP blocking either action with complete confidence produces a `blocked` verdict. The `_and_tristate` helper is designed to be reusable for future multi-action reasoners (Secrets blast radius). |
| **`assume_role_chain`** | Multi-hop privilege escalation paths where a principal can transitively reach an admin-equivalent role via 2+ `sts:AssumeRole` hops. The kind of chain that hides in plain sight in big orgs, single-pair reasoners cannot catch it by design. Example: `Alice → DevOpsRole → AdminRole`. | 6 checks: `chain_length_at_least_two`, `endpoint_is_admin_equivalent`, `all_hops_have_valid_trust_and_permission_edges`, `no_scp_blocks_any_hop`, `no_boundary_blocks_any_hop`, `no_hop_traverses_hyperedge`. BFS chain walker with cycle detection (visited-set) and depth limit (4 hops). Per-hop SCP/boundary states combine via `and_tristate_many`; an SCP blocking any single hop with complete confidence produces `blocked`. Severity scaling: validated + admin endpoint + 2-3 hops → `high`; 4+ hops → `critical` (deeper chains harder to spot in audits). Admin equivalence is detected via two-tier matching: explicit `*`/`iam:*` permission edges (unit-test fixtures) OR wildcard expansion hyperedges (real collected data where `Action: "*"` is fanned out by the collector). |
| **`admin_reachability`** | Per-principal "blast forward" reachability. For each starting principal, computes the SET of admin-equivalent roles reachable via any chain of `sts:AssumeRole` hops. The complement to `assume_role_chain`'s "chain to specific target" view. Answers "is this principal effectively admin?" with one finding per principal listing all reachable admin endpoints, instead of N findings per (source, target) chain pair. | 4 checks: `source_has_assumerole_permissions`, `reaches_at_least_one_admin`, `at_least_one_reachable_chain_uses_clean_witnesses`, `walk_terminated_within_depth_limit`. BFS reachability walker with cycle detection and depth limit 4. Verdicts: only `validated` and `inconclusive` (no `blocked`; SCP analysis is per-chain, this reasoner is per-principal). Severity: 1 reachable admin → `high`; 2+ admins → `critical` (multiple paths means SCP can't single-handedly break the chain). Target on the Finding is the lexicographically-first reachable admin (deterministic); the full set of reachable admins lives in `evidence.node_refs`. Better signal-to-noise than `assume_role_chain` for the "who's effectively admin?" pentest question. |
| **`secrets_blast_radius`** | Models per-secret exposure risk across BOTH the IAM layer AND the KMS encryption layer (v2). For each `SecretsManagerSecret` node, enumerates principals that hold `secretsmanager:GetSecretValue` permission AND can decrypt the secret's encryption key via `kms:Decrypt` on the associated KMS key policy. Emits one finding per (principal, secret) pair. A readable secret may expose sensitive material such as DB passwords, API keys, or OAuth tokens, subject to runtime context and the actual secret contents. | **6 checks**: `principal_has_get_secret_value_permission`, `permission_edge_targets_clean_witness`, `no_scp_blocks_get_secret_value`, `no_boundary_blocks_get_secret_value`, `principal_is_not_service_or_root` (early filter), and **`kms_key_policy_allows_decrypt_for_principal`** (v2). Verdicts: SCP/boundary complete-confidence block → `blocked/info`; **KMS key policy blocks decrypt** → `precondition_only/medium` (new in v2); wildcard resource or partial-confidence constraints or conditional KMS policies → `inconclusive/medium`; all clean → `validated` with severity scaling by modeled principal admin-equivalence (`critical` for admin-equivalent, `high` for non-admin). Uses the shared two-tier admin detection from `admin_detection.py` with the ≥3-service-prefix threshold so non-admin principals with scoped wildcard grants don't produce false-positive severity bumps. The KMS layer handles three common cases: AWS-managed default key (delegates to IAM → PASS automatic), CMK with account-root delegation (`Principal: {"AWS": "arn:...:root"}`, behaves like AWS-managed → PASS), and CMK with specific principal grants (evaluates the policy per-principal). Complex cases (Deny statements, Conditions, NotPrincipal/NotAction/NotResource, malformed JSON) → UNKNOWN → inconclusive. **v2 limitations** documented in the module docstring: does not handle `kms:CreateGrant`, does not walk nested Conditions, does not handle cross-account `kms:Decrypt` via ExternalId. |
| **`iam_group_membership_escalation`** | Models the structural IAM group-membership escalation risk pattern where a user with `iam:AddUserToGroup` on an admin-equivalent group may inherit that group's permissions, subject to conditions, boundaries, SCPs, and runtime context. The reasoner enumerates IAMUser sources (v1 excludes role sources because roles cannot directly benefit from adding users to groups without a separate credential-control path), then for each source finds target groups via clean witness edges or, for wildcard/hyperedge witnesses, iterates all groups in the graph. Only admin-equivalent target groups produce findings; non-admin groups are filtered as routine user management. | **5 checks**: `source_has_add_user_to_group_permission`, `witness_edge_is_clean`, `no_scp_blocks_add_user_to_group`, `no_boundary_blocks_add_user_to_group`, `target_group_is_admin_equivalent`. Verdicts: SCP/boundary complete-confidence block → `blocked/info`; check 5 FAIL (group not admin) → no finding (filtered); wildcard/hyperedge witness or partial-confidence constraints → `inconclusive/high`; all clean → `validated/critical` (modeled admin-equivalent group membership risk). Uses the shared two-tier admin detection from `admin_detection.py` on IAMGroup nodes. This requires group-sourced permission edges which are emitted via the v0.2.25 `_process_group` collector enhancement (before that, group policies only flowed to users via R10 inheritance and groups had no outgoing edges for admin detection to walk). |
| **`s3_bucket_takeover`** | Models the structural S3 bucket-policy rewrite risk pattern for principals that can call `s3:PutBucketPolicy` on a bucket. Rewriting a bucket policy may grant broad bucket access depending on the policy written, existing controls, and runtime context. The reasoner is pure IAM-layer analysis: it does not evaluate the current bucket policy content, only whether the principal has modeled authority to rewrite it. Source scoping includes both users AND roles because either identity type can be relevant when its session is in scope. A 5th check filters service principals (`*.amazonaws.com`) and account root because those represent infrastructure rather than actionable principals for this modeled finding. | **5 checks**: `principal_has_put_bucket_policy_permission`, `witness_edge_is_clean`, `no_scp_blocks_put_bucket_policy`, `no_boundary_blocks_put_bucket_policy`, `principal_is_actionable`. Verdicts: SCP/boundary complete-confidence block → `blocked/info`; check 5 FAIL (service principal or root) → no finding (filtered); wildcard/hyperedge witness or partial-confidence constraints → `inconclusive/high`; all clean → `validated/critical` (modeled bucket-policy rewrite risk). Inconclusive cases drop to `high` because wildcard resource grants are common in AWS and would flood pentest reports if classified as critical. Fact-layer dependency: requires S3Bucket nodes in the graph, created by the v0.2.26 S3 collector via `list_buckets`. Before v0.2.26, S3 bucket ARNs were misclassified as IAMRole via the legacy fallback in `_classify_resource_arn` and no S3-aware reasoner was possible. |

Adding a new reasoner is a single-file change: implement the `Reasoner` Protocol, register it in the CLI's `_AVAILABLE_REASONER_FACTORIES` dict, add byte-pinned golden fixtures for the expected verdicts, done. No changes to the emitter, the CLI framework, or the fact graph.

## Documentation

- **[docs/ARCHITECTURE.md](docs/ARCHITECTURE.md)**: the 10 architectural rules that govern how IAMScope is built. Every rule was learned from a concrete incident (bug, false positive, refactor that almost introduced one). The rule is stated first, then the incident that taught us the rule, then the code that enforces it. Required reading before making any non-trivial change to the codebase.
- **[docs/CONTRIBUTING.md](docs/CONTRIBUTING.md)**: the short version for contributors. Before-you-change-anything checklist, the reasoner-addition 6-phase workflow, the "adding a new resource type" checklist (parser AND collector), the golden fixtures workflow, and the PR checklist. Read this if you're adding a reasoner, fixing a bug, or refactoring shared infrastructure.

## Benchmark Status

Current benchmark truth status lives in **[BENCHMARK_STATUS.md](BENCHMARK_STATUS.md)**. The latest frozen snapshot is **[benchmarks/snapshots/phase0-20260509-env27](benchmarks/snapshots/phase0-20260509-env27)**, with the snapshot index at **[benchmarks/snapshots/INDEX.md](benchmarks/snapshots/INDEX.md)**. The latest ten-pair mutation-pair report is **[benchmarks/pair-reports/phase0-20260509-env27-mutation-pairs.md](benchmarks/pair-reports/phase0-20260509-env27-mutation-pairs.md)**. Synthetic degradation benchmark status is tracked in **[docs/specs/benchmark-degradation-family-design.md](docs/specs/benchmark-degradation-family-design.md)**. The current corpus has twenty-four bounded live AWS benchmark cases, including Env22/Env23 cross-account AssumeRole coverage, Env24/Env25 scenario-edge-level S3 resource-policy Allow coverage, and Env26/Env27 controlled same-account multihop-chain coverage, and a `hold_review` decision; these results are focused evidence, not proof of broad IAMScope correctness, arbitrary enterprise graph correctness, or production readiness, and no composite score is claimed. Env24/Env25 do not claim finding-level resource-policy reachability or generic resource-policy Deny support. Env26/Env27 provide bounded evidence for one controlled same-account multihop pair only.

## The `why` subcommand: finding introspection

When the reasoners emit a finding that looks surprising, you can ask IAMScope *why*:

```bash
# Explain a specific finding by finding_id prefix
iamscope why --finding-id abc123

# Explain by pattern + source/target substring
iamscope why --pattern secrets_blast_radius --source Alice --target prod/db

# Full reasoning trace
iamscope why --pattern assume_role_chain --source Alice --verbose

# Pipe-friendly output (no color)
iamscope why --finding-id abc123 --no-color | less
```

The output shows each check's state with a color-coded marker (`[✓]` PASS, `[✗]` FAIL, `[?]` UNKNOWN), the reasoner's exit reason, any blockers observed, the evidence bundle contents, and optionally the full step-by-step trace. For `INCONCLUSIVE` verdicts, a prominent "refuses-to-lie" callout names the specific UNKNOWN check(s) that forced the verdict and reminds the reviewer that IAMScope refuses to guess PASS or FAIL when a check is ambiguous. This is the single most important differentiator between IAMScope and commodity scanners, and the `why` subcommand makes it a first-class user experience.

Typical output for a KMS-blocked secret read (`PRECONDITION_ONLY/medium`):

```
Finding e35bfe3f3cf6… [PRECONDITION-ONLY/MEDIUM]
Pattern: secrets_blast_radius
Title:   Precondition-only secret read: Alice can call GetSecretValue on prod/db-cmk-restricted

Source: arn:aws:iam::123456789012:user/Alice
Target: arn:aws:secretsmanager:us-east-1:123456789012:secret:prod/db-cmk-restricted

Verdict reasoning: KMS key policy does not allow kms:Decrypt for principal

Checks:
  [✓] principal_has_get_secret_value_permission — permission edge witnessed
  [✓] permission_edge_targets_clean_witness — clean witness edge
  [✓] no_scp_blocks_get_secret_value — no SCP bindings observed
  [✓] no_boundary_blocks_get_secret_value — no permission boundary bindings observed
  [✗] kms_key_policy_allows_decrypt_for_principal — no KMS policy Allow statement covers principal

Blockers observed:
  ● kms_key_policy 3d89cdd4… on edge 80a07bf8acb9…: no KMS policy Allow statement covers principal

Evidence bundle:
  • 1 statement digest(s), 1 edge ref(s), 0 constraint ref(s), 3 node ref(s)
```

## Advanced: live AWS collection requires explicit authorization

The commands below are not the default quickstart. They can call live AWS APIs and should only be used with explicit authorization, a scoped test profile/account, and a separately reviewed plan. Do not run these against production by default. For safe local reviewer commands, use the validation commands near the top of this README.

```bash
# Install
pip install -e ".[dev]"

# Collect: full org mode (requires Organizations + IAM read access)
# Produces: scenario.json + binding_metadata.json + findings.json
iamscope collect --profile my-org-profile --output ./results

# Collect: standalone mode (single account, no org access needed)
iamscope collect --standalone --profile my-account-profile --output ./results

# Collect: only run specific reasoners
iamscope collect --profile my-profile --reasoners cross_account_trust --output ./results

# Collect: pedantic mode (demote validated passrole_lambda findings)
iamscope collect --profile my-profile --assume-no-session-policies --output ./results

# Collect: back-compat path (skip findings.json emission entirely)
iamscope collect --profile my-profile --no-findings --output ./results

# Generate security report from collected data
iamscope report ./results/scenario.json --output report.md

# Validate structural integrity
iamscope validate ./results/scenario.json

# Compare two snapshots
iamscope diff ./baseline/scenario.json ./results/scenario.json

# Enrich with GhostGates CI/CD bypass data
iamscope enrich --scenario ./results/scenario.json \
                --ghostgates ./ghostgates-report.json \
                --output enrichment.json
```

After a default `collect` run you'll have three files in the output directory:

| File | Contents | Consumer |
|---|---|---|
| `scenario.json` | Fact graph: nodes, edges, constraints, bindings. ARF-RT-compatible schema. | ARF-RT Bayesian scoring; `iamscope report`; `iamscope diff`; independent verification. |
| `binding_metadata.json` | Per-binding governance metadata (`governance_confidence`, `likely_blocking`, `binding_reason`) that doesn't fit ARF-RT's strict schema. | Standalone report; future ARF-RT integration when `extra="forbid"` relaxes. |
| `findings.json` | Pattern-reasoner output: verdicts, evidence, reasoning traces. Byte-locked canonical hash excludes timestamp. | Direct pentest reporting; FindingsForge integration; cross-scan diffing. |

## Standalone mode

Not every engagement starts with org-level access. `--standalone` collects the current account directly without requiring AWS Organizations permissions:

```bash
iamscope collect --standalone --profile my-profile -v -o ./output
```

What you get: trust edges, OIDC subject extraction, naked trust classification, permission analysis, PassRole chains, Lambda/EC2 service edges, **both reasoners run against the standalone fact graph, findings.json written as usual.**

What you don't get: SCP constraints, OU hierarchy, cross-account collection. The scenario.json has `constraints: []` and `metadata.org_id: "standalone"`. Reasoner behavior: reasoners that depend on SCP bindings (like `cross_account_trust` checking for SCP blockers) treat missing SCPs as "no blocker observed" rather than "unknown blocker." This is the correct interpretation in standalone mode because the absence is due to the collection scope, not a parsing failure.

Use standalone mode when:
- The account isn't in an org
- You only have IAM read access, not `organizations:*`
- You want a quick single-account assessment before deploying the collection role org-wide

## Architecture

```
┌──────────────────────────────────────────────────────────────────────┐
│                             CLI (cli.py)                              │
│   collect │ report │ enrich │ diff │ validate                         │
│   Flags: --reasoners, --no-findings, --assume-no-session-policies     │
└──────────────────────────────┬───────────────────────────────────────┘
                               │
┌──────────────────────────────▼───────────────────────────────────────┐
│                       Pipeline (pipeline.py)                          │
│   Phase 1: Org Discovery    → OrgData (OUs, SCPs, accounts)          │
│            (skipped in standalone mode)                               │
│   Phase 2: Per-Account IAM  → AccountData (nodes, trust, permission  │
│            + Lambda/EC2       results, role ARNs)                    │
│   Phase 3: Resolution       → Nodes, edges, constraints, bindings    │
│            (pure computation, zero API calls)                         │
│   Phase 4: Emission         → scenario.json + binding_metadata.json  │
│                                + canonical_hash                       │
└──────────────────────────────┬───────────────────────────────────────┘
                               │
┌──────────────────────────────▼───────────────────────────────────────┐
│                      Reasoner phase (cli.py)                          │
│   1. FactGraph wrapper from PipelineResult                           │
│   2. Registry.register() each reasoner from --reasoners               │
│   3. preconditions_met() for each → track reasoners_skipped           │
│   4. Registry.run_all() → list of Finding                             │
│   5. Optional --assume-no-session-policies post-processor             │
│   6. emit_findings() → canonical bytes + canonical_hash               │
└──────────────────────────────┬───────────────────────────────────────┘
                               │
                               ▼
                          findings.json
```

### Phase 3 Resolution Pipeline (no network calls)

```
Trust parse results ──► build_trust_edges()
                        ──► resolve_synthetic_nodes() (external accounts, wildcards)
                        ──► classify_naked_trust()
                        ──► extract_oidc_subject() (GitHub Actions, Cognito, etc.)

Permission parse results ──► build_permission_edges() (with expansion controls)
                             ──► per-principal cumulative budget tracking
                             ──► detect PassRole chains → hyperedge nodes

Lambda/EC2 data ──► service nodes + service edges

SCP constraints ──► bind_all_scps() → edge_constraints
Permission boundaries ──► build + bind → edge_constraints

All ──► edge budget check ──► dedup by ID ──► emit_scenario() → canonical JSON + SHA-256 hash
```

### Reasoner phase (post-resolution, pre-emission)

```
PipelineResult.nodes/edges/constraints/edge_constraints
    ──► FactGraph(..., scenario_hash=canonical_hash)
         │
         ├── has_action(principal, action, resource?) → PASS | FAIL | UNKNOWN  (the tristate)
         ├── edges_from / edges_to / trust_policy_of / passrole_edges_from
         ├── bindings_for_edge / constraint_by_id
         └── (defensive: sorted edge order for determinism)

FactGraph ──► Registry.register(reasoner) × N
              ──► Registry.run_all(facts) → list[Finding]
                  │
                  ├── Each Finding carries:
                  │   • pattern_id, pattern_version
                  │   • source / target NodeRef
                  │   • verdict + severity
                  │   • required_checks (each with PASS/FAIL/UNKNOWN + reason + evidence_refs)
                  │   • blockers_observed (for blocked / precondition_only)
                  │   • assumptions (session_policy, etc.)
                  │   • evidence: EvidenceBundle
                  │       • statement_digests, statement_sources
                  │       • edge_refs, constraint_refs, edge_constraint_refs, node_refs
                  │       • condition_context_assumed
                  │       • reasoning_trace (10-step ordered sequence per finding)
                  │   • finding_id (deterministic SHA-256 of canonical attributes)
                  │   • scenario_hash (link back to scenario.json)
                  │
                  └── Registry tracks reasoners_skipped (for preconditions_met failures)

list[Finding] ──► (optional) _demote_validated_findings() if --assume-no-session-policies
              ──► emit_findings(findings, scenario_hash, reasoners_used, ...)
                  ──► canonical JSON with hash scope excluding timestamp + duration
                      ──► findings.json
```

## Output Format

### scenario.json

Deterministic, canonically sorted JSON with SHA-256 content hash:

```json
{
  "nodes": [
    {
      "node_id": "a1b2c3...",
      "node_type": "IAMRole",
      "provider": "aws",
      "provider_id": "arn:aws:iam::123456789012:role/Admin",
      "properties": { "account_id": "123456789012" }
    }
  ],
  "edges": [
    {
      "edge_id": "d4e5f6...",
      "edge_type": "sts:AssumeRoleWithWebIdentity_trust",
      "src": { "provider_id": "token.actions.githubusercontent.com", "node_type": "OIDCProvider" },
      "dst": { "provider_id": "arn:aws:iam::123456789012:role/DeployRole", "node_type": "IAMRole" },
      "features": {
        "naked_trust": "CONDITIONED",
        "oidc_subject_pattern": "repo:MyOrg/MyRepo:ref:refs/heads/main"
      }
    }
  ],
  "constraints": [ ],
  "edge_constraints": [ ],
  "metadata": {
    "collector": "iamscope",
    "collector_version": "0.2.14",
    "canonical_hash": "sha256hex..."
  }
}
```

### findings.json

Canonical reasoner output with deterministic byte-level hash:

```json
{
  "schema_version": "1.0",
  "source_tool": "iamscope",
  "source_tool_version": "0.2.14",
  "scenario_hash": "027150984a2fe2ea...",
  "reasoner_versions": {
    "cross_account_trust": "1.0.0",
    "passrole_lambda": "1.0.0"
  },
  "findings": [
    {
      "finding_id": "9d5cab1f99ee2d42...",
      "pattern_id": "passrole_lambda",
      "pattern_version": "1.0.0",
      "pattern_title": "Lambda PassRole Privilege Chain",
      "source": {
        "provider": "aws",
        "node_type": "IAMUser",
        "provider_id": "arn:aws:iam::123456789012:user/Alice"
      },
      "target": {
        "provider": "aws",
        "node_type": "IAMRole",
        "provider_id": "arn:aws:iam::123456789012:role/LambdaExec"
      },
      "verdict": "inconclusive",
      "severity": "high",
      "title": "Inconclusive Lambda PassRole chain from ...",
      "required_checks": [
        {
          "name": "source_has_passrole_to_target",
          "description": "Source can PassRole to the target role",
          "state": "unknown",
          "evidence_refs": ["edge_id:a3f2..."],
          "reason": "matching iam:PassRole edge has ambiguity flag (hyperedge dst)"
        }
      ],
      "blockers_observed": [ ],
      "assumptions": [ ],
      "evidence": {
        "statement_digests": ["...", "...", "..."],
        "statement_sources": { "...": ["policy_arn", 0, "summary"] },
        "edge_refs": ["edge_id:...", "edge_id:...", "edge_id:..."],
        "constraint_refs": [ ],
        "edge_constraint_refs": [ ],
        "node_refs": ["node_id:...", "node_id:..."],
        "condition_context_assumed": [ ],
        "reasoning_trace": [
          { "step": 1, "action": "check_source_has_lambda_create_function", "...": "..." },
          { "step": 2, "action": "check_source_has_passrole_to_target", "...": "..." }
        ],
        "bundle_digest": "..."
      },
      "reasoner_exit_reason": "check(s) UNKNOWN: source_has_passrole_to_target"
    }
  ],
  "metadata": {
    "collector": "iamscope",
    "collector_version": "0.2.14",
    "findings_count": 1,
    "reasoners_run": ["cross_account_trust", "passrole_lambda"],
    "reasoners_skipped": {},
    "reasoning_timestamp": "2026-04-08T20:31:00Z",
    "reasoning_duration_seconds": 0.07,
    "verdict_breakdown": {
      "validated": 0,
      "blocked": 0,
      "inconclusive": 1,
      "precondition_only": 0
    },
    "id_algorithm": "sha256_null_separated_v2",
    "hash_scope": "canonical_hash excludes canonical_hash, reasoning_timestamp, reasoning_duration_seconds",
    "canonical_hash": "d26ef2d033c0040f..."
  }
}
```

The `canonical_hash` excludes `reasoning_timestamp` and `reasoning_duration_seconds` by design, so two scans over the same fact graph produce byte-identical hashes even hours apart. The `verdict_breakdown` IS in the hash payload. Any silent change in verdict counts breaks the hash and surfaces on the next test run.

### binding_metadata.json (sidecar)

Governance metadata that doesn't fit ARF-RT's strict schema:

```json
[
  {
    "edge_id": "d4e5f6...",
    "constraint_id": "...",
    "binding_metadata": {
      "scp_name": "DenyDeleteBucket",
      "governance_confidence": "complete",
      "actions_denied": ["s3:DeleteBucket"]
    }
  }
]
```

## Key Design Decisions

**Invariant #1: IAMScope refuses to guess.** The reasoner layer's `CheckState` is a tristate: `PASS`, `FAIL`, or `UNKNOWN`. `UNKNOWN` is a first-class state, not a fallback. A reasoner that cannot determine whether a condition holds must emit `UNKNOWN` explicitly. Any `UNKNOWN` check in a finding forces the verdict to `inconclusive`, which is the signal to a reviewer that human judgment is required. The tool never emits `validated` unless every check is modeled as `PASS` with complete confidence under the current evidence rules.

**Invariant #2: Read-only only.** IAMScope never modifies any AWS resource. All API calls are `List` / `Get` / `Describe` operations.

**Invariant #3: Deterministic IDs and byte-locked output.** Every node, edge, constraint, edge-constraint, and finding ID is a SHA-256 hash of its canonical attributes. Same input always produces the same output, bit-for-bit. Two runs over the same scenario produce byte-identical `findings.json` canonical_hash (after excluding the timestamp and duration fields, which are outside the hash scope). This is enforced by 18 byte-pinned golden fixtures. Any silent regression surfaces as a hash mismatch on the next test run.

**Invariant #4: Two-layer edge semantics.** Trust and permission are tracked separately. A trust edge means "the trust policy allows it." A permission edge means "the IAM permission exists." Downstream reasoners derive feasibility by intersecting these layers with additional constraints.

**Invariant #5: SCP binding, not evaluation.** IAMScope binds SCPs to edges with confidence scores but does not simulate SCP evaluation. Reasoners read the binder's `likely_blocking` flag and `governance_confidence` to classify SCP impact. `complete` + `likely_blocking=True` → `blocked` verdict. `partial` or `needs_review` → `UNKNOWN` check state → `inconclusive` verdict. The reasoner never re-implements SCP logic.

**Invariant #6: ARF-RT native output.** The scenario.json schema passes ARF-RT's Pydantic validation directly. Extra metadata goes in the sidecar file. `findings.json` is a separate, standalone contract that does not depend on ARF-RT.

**Invariant #7: Emit facts, not derivations.** IAMScope emits raw trust, permission, and service edges in `scenario.json`, not pre-computed intersections. The reasoners apply their own logic in-memory to derive findings; the fact graph itself stays neutral. This keeps `scenario.json` reusable across different reasoner sets and downstream consumers.

**Invariant #8: Edge budget circuit-breaker.** `MAX_TOTAL_EDGES` (100,000) truncates the graph if it grows too large. If `edge_budget_exhausted=True`, the `passrole_lambda` reasoner refuses to run because a dropped edge could invalidate any `validated` verdict. It emits `reasoners_skipped` metadata instead of producing degraded findings.

## CLI Reference

```
iamscope collect [options]
  --profile PROFILE              AWS CLI profile name
  --region REGION                AWS region (default: us-east-1)
  --role-name ROLE               Collection role name (default: IAMScopeReader)
  --external-id ID               External ID for AssumeRole
  --standalone                   Single-account mode (no org access needed)
  --accounts 111,222             Whitelist specific accounts
  --skip-accounts 333            Blacklist specific accounts
  --expansion-mode MODE          warn|expand|skip (default: warn)
  --passrole-mode MODE           Override for PassRole expansion
  --lambda-mode MODE             Override for Lambda expansion
  --ec2-mode MODE                Override for EC2 expansion
  --include-service-linked       Include service-linked roles
  --include-aws-managed          Include AWS-managed policies
  --output DIR                   Output directory (default: .)
  -v / -vv / -q                  Verbosity control

  # Reasoner flags (S14)
  --reasoners LIST               Comma-separated list of reasoners to run
                                 (default: all registered). Available:
                                 cross_account_trust, passrole_lambda
  --no-findings                  Skip findings.json emission. Produces only
                                 scenario.json + binding_metadata.json.
                                 Back-compat path for callers that don't
                                 want the new sidecar file.
  --assume-no-session-policies   Pedantic-reviewer mode. Demotes every
                                 passrole_lambda VALIDATED finding to
                                 INCONCLUSIVE by adding a condition_context
                                 assumption. IAMScope cannot see AWS session
                                 policies at collection time, so every
                                 validated finding implicitly assumes no
                                 session policy restricts the chain. This
                                 flag makes that assumption explicit and
                                 forces the more cautious verdict.

iamscope report SCENARIO [--binding-metadata FILE] [--enrichment FILE] [-o FILE]
iamscope enrich --scenario FILE --ghostgates FILE [-o FILE]
iamscope diff BEFORE AFTER [--json] [-o FILE]
iamscope validate SCENARIO
```

## Required IAM Permissions

### Full org mode

Management account needs Organizations read + `sts:AssumeRole`. Each member account needs the `IAMScopeReader` role:

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": [
        "organizations:ListAccounts",
        "organizations:ListOrganizationalUnitsForParent",
        "organizations:ListRoots",
        "organizations:ListPolicies",
        "organizations:ListTargetsForPolicy",
        "organizations:DescribeOrganization",
        "organizations:DescribePolicy",
        "organizations:ListAccountsForParent",
        "iam:GetAccountAuthorizationDetails",
        "iam:ListInstanceProfiles",
        "lambda:ListFunctions",
        "sts:GetCallerIdentity"
      ],
      "Resource": "*"
    }
  ]
}
```

### Standalone mode

Only needs IAM read on the current account:

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": [
        "iam:GetAccountAuthorizationDetails",
        "iam:ListInstanceProfiles",
        "lambda:ListFunctions",
        "sts:GetCallerIdentity"
      ],
      "Resource": "*"
    }
  ]
}
```

## OIDC Federation Analysis

IAMScope extracts the `:sub` claim pattern from OIDC trust policies and uses it for naked trust classification:

| OIDC Trust Configuration | Classification | Risk |
|--------------------------|---------------|------|
| No `:sub` condition at all | `BROAD_NAKED` | Any identity from the provider can assume |
| `sub: *` (explicit wildcard) | `BROAD_NAKED` | Same as above |
| `sub: repo:Org/Repo:ref:refs/heads/main` | `CONDITIONED` | Restricted to specific identity |
| Multiple `:sub` patterns | `CONDITIONED` | Restricted to listed identities |

The `oidc_subject_pattern` field appears in trust edge features for all OIDC-federated trust edges. The report includes a dedicated **OIDC Federation Details** section that splits trusts into unrestricted (no `:sub`) and restricted (specific `:sub`).

The `cross_account_trust` reasoner is OIDC-aware: `BROAD_NAKED` OIDC trusts produce `validated` findings; `CONDITIONED` OIDC trusts produce no finding.

Supports both URL-form principals (`token.actions.githubusercontent.com`) and ARN-form (`arn:aws:iam::...:oidc-provider/token.actions.githubusercontent.com`).

## Naked Trust Classification

| Level | Meaning | Example |
|-------|---------|---------|
| `CRITICAL_NAKED` | Any AWS principal can assume | `Principal: "*"` with no conditions |
| `BROAD_NAKED` | Entire external account, or unconditioned OIDC | Account root no conditions; OIDC without `:sub` |
| `NARROW_NAKED` | Cross-account but partially scoped | Specific external role with ExternalId only |
| `CONDITIONED` | Cross-account with strong conditions | `aws:PrincipalOrgID`, MFA, or OIDC with specific `:sub` |
| `INTRA_ACCOUNT` | Same-account trust | Internal trust, SAML federation |

## Expansion Controls

Wildcard resource grants (`Resource: "*"`) can produce thousands of edges. Three layers of protection:

**Per-expansion limit**: Wildcard grants expanding to >500 targets collapse to a single hyperedge node (in `warn` mode). The hyperedge is intentional. It signals to reasoners that the wildcard exists but cannot be resolved to specific targets. Reasoners treat hyperedge witnesses as `UNKNOWN` for check-state purposes, which is exactly the refuses-to-lie behavior: the tool knows the grant exists but refuses to claim it covers any specific target it cannot verify.

**Per-principal cumulative budget**: Tracks total expanded edges per source principal. Warns at 200, hard-caps at 500. Prevents the N² scenario where 3 users with `iam:PassRole *` against 50 roles produce 900+ edges.

**Global circuit-breaker**: `MAX_TOTAL_EDGES` (100,000) truncates the entire graph. If this triggers, `passrole_lambda` refuses to run (per Invariant #8) and emits `reasoners_skipped` metadata.

## Module Map

```
iamscope/
├── cli.py                    # 5 subcommands: collect, report, enrich, diff, validate
│                             # + reasoner phase wiring, 3 new flags
├── pipeline.py               # 4-phase orchestrator (org + standalone modes)
├── models.py                 # Node, Edge, Constraint, EdgeConstraint dataclasses
├── constants.py              # Pinned invariants, confidence mappings, enums
├── diff.py                   # Scenario comparison engine
├── validate.py               # Structural integrity validator
│
├── auth/
│   ├── session.py            # boto3 session factory
│   └── assume_role.py        # Cross-account AssumeRole
│
├── collector/
│   ├── organization.py       # Phase 1: OU tree, SCPs, account discovery
│   ├── account.py            # Phase 2: GetAccountAuthorizationDetails
│   ├── lambda_collector.py   # Lambda function → execution role edges
│   ├── ec2_collector.py      # Instance profile → role edges
│   └── passrole.py           # Permission edge builder with cumulative budget
│
├── parser/
│   ├── trust_policy.py       # Trust policy → TrustParseResult + OIDC :sub + DIG-1 digests
│   ├── permission_policy.py  # Permission policy → PermissionParseResult + raw_conditions
│   ├── scp_policy.py         # SCP → Constraint with confidence scoring
│   └── condition_extractor.py # IAM condition key extraction (6 canonical keys)
│
├── resolver/
│   ├── cross_account.py      # Trust edge construction + synthetic nodes
│   ├── naked_trust.py        # Naked trust classification (5-level + OIDC-aware)
│   ├── scp_binder.py         # SCP → edge constraint binding
│   └── permission_boundary.py # Boundary → edge constraint binding (post-BND-1 intersection)
│
├── controls/
│   ├── expansion.py          # Graph explosion controls (warn/expand/skip)
│   └── noise_filter.py       # Service-linked, AWS-managed filtering (NF-1)
│
├── output/
│   ├── scenario_json.py      # Canonical JSON emission + SHA-256 hashing
│   └── findings_json.py      # Findings JSON emitter + byte-locked canonical_hash
│
├── reasoner/                 # S08-S13 reasoner layer
│   ├── verdict.py            # Verdict enum, CheckState, Check, Blocker, Assumption, Finding
│   ├── evidence.py           # EvidenceBundle, TraceEntry, bundle_digest
│   ├── fact_graph.py         # FactGraph wrapper with tristate has_action
│   ├── base.py               # Reasoner Protocol (runtime_checkable)
│   ├── registry.py           # Reasoner registration + run_all
│   ├── cross_account_trust.py # First reasoner: 6-check cross-account trust analysis
│   └── passrole_lambda.py    # Flagship reasoner: 8-check Lambda PassRole chain
│
├── enrichment/
│   └── ghostgates.py         # GhostGates CI/CD gate bypass annotation
│
└── report/
    └── generator.py          # Markdown report with OIDC section
                              # (next rewrite: findings-first, not graph-first)

tests/                        # 1106 tests across ~44 files
├── fixtures/
│   └── expected_output/
│       ├── minimal_scenario.json           # Scenario.json golden (S05 re-pin)
│       ├── scp_binding_scenario.json       # Scenario.json golden (S05 re-pin)
│       └── findings/
│           ├── cross_account_trust/         # 9 byte-pinned findings.json fixtures
│           └── passrole_lambda/             # 7 byte-pinned findings.json fixtures
├── test_*.py                 # Unit + integration + golden + hardening + CLI
├── test_cross_account_reasoner.py   # 25 tests for cross_account_trust
├── test_passrole_lambda_reasoner.py # 27 tests for passrole_lambda (incl. fixture F guard)
└── test_golden_findings.py          # 18 tests pinning all 16 findings.json fixtures
```

## Development

```bash
pip install -e ".[dev]"
pytest                                          # 1106 tests
mypy iamscope/ --config-file pyproject.toml     # strict mode
ruff check iamscope/ tests/                     # lint
```

## Changelog

### v0.2.28: Performance profiling + 4 hot-spot fixes

**IAMScope's reasoner layer is fast on the current synthetic benchmark.** This release records benchmark numbers and applies four O(N²) → O(1) fixes that deliver a 2.1× speedup on the scaled fixture. The reasoner layer was already fast in this benchmark; v0.2.28 is polish, not rescue.

**Benchmark baseline on a 1850-node / 1010-edge synthetic AWS org:**
- **Pre-fix:** 48.46 ms total wall time for the full 8-reasoner pipeline
- **Post-fix:** 22.69 ms total (2.1× speedup)
- **Biggest winner:** `s3_bucket_takeover` at 3.9× speedup (29.78 ms → 7.61 ms)

Linearly extrapolated to a 10,000-node synthetic graph, the reasoner pipeline is projected at roughly 125 ms. This is benchmark evidence for reasoner overhead, not proof of real-world scalability. The collector layer (boto3 API calls with ratelimiting) dominates total runtime for live collection, not the reasoner layer.

**The four hot-spot fixes**, all the same bug pattern: a reasoner doing its own linear scan through `facts.nodes` to look up a node by `provider_id`, when the `FactGraph` class already provided an O(1) `node_by_provider_id(...)` lookup via an index built at `__post_init__` time. The index was there; the reasoners just weren't using it.

1. **`secrets_blast_radius._find_node`**: was doing `for node in facts.nodes: if node.provider_id == provider_id`. Replaced with a one-line delegation to `facts.node_by_provider_id(...)`. Pre-fix cProfile showed this consuming **18 ms of 73 ms total pipeline cumulative time (~25%)** across 400 calls with zero children: the clearest "pure linear scan" signal in the profile. Post-fix: essentially zero-cost dict lookup.

2. **`secrets_blast_radius` KMS node lookup**: was scanning all KMS nodes to match either `provider_id` or the `key_id` property. Added an O(1) fast path via `node_by_provider_id` that verifies the returned node is a KMSKey; retained the O(N-across-KMS-nodes-only) scan as a fallback for the short-form `key_id` case where a secret cites the raw key ID (not the ARN) and the lookup needs the property match.

3. **`s3_bucket_takeover.run` clean-witness lookup**: was iterating all 200 buckets inside the per-witness-edge loop to match the dst provider_id. Replaced with `facts.node_by_provider_id(dst_provider_id)` plus a node_type check to ensure the returned node is actually an S3Bucket, falling back to the "iterate all buckets" UNKNOWN path only when no direct match exists. **Biggest winner at 3.9× speedup**: 300 witness edges × O(200 buckets) = 60,000 comparisons per run, replaced with 300 dict lookups.

4. **`iam_group_membership_escalation.run` clean-witness lookup**: same pattern as #3. Replaced the group-iteration loop with `facts.node_by_provider_id(...)` plus IAMGroup node_type verification.

**Why `s3_bucket_takeover` won the biggest speedup despite the cProfile showing `secrets_blast_radius._find_node` as the top hot spot:** the pre-fix profile ranked by cumulative time, which favored explicit function calls with their own line in the breakdown (`_find_node`). The S3 clean-witness lookup was INLINED inside the `run()` method and didn't appear as a distinct function in the profile. It was invisible to "top by cumulative time" but still consumed real wall time. The lesson is documented in `docs/PERFORMANCE.md`. After running `cProfile`, also grep for `for node in facts.nodes` in the reasoner source tree; any such loop inside a per-finding path is a candidate for replacement with an indexed lookup, even if the profile doesn't flag it.

**New benchmark harness `tests/benchmark_reasoners.py`** (~370 lines), generates a deterministic synthetic fact graph at two scales (200-node baseline and 1850-node XL), runs all 8 reasoners with per-reasoner wall-clock timing, and supports a `--profile` flag that runs under `cProfile` and prints the top-30 hot spots by cumulative time. It is self-contained, has no network or disk dependencies, and is reproducible across runs. Future contributors can use it to diagnose new performance issues; the harness is part of the shipping tarball so regression testing on reasoner performance is a one-command check.

**New documentation `docs/PERFORMANCE.md`**: full writeup of the benchmark methodology, baseline + after-fix numbers, the four hot-spot fixes with before/after code, scaling projections for 200 → 50,000 node graphs, and rules for future contributors ("never write `for node in facts.nodes` inside a per-finding path," "run the benchmark after adding a new reasoner," "if you need a new index, add it to FactGraph rather than building an ad-hoc dict in your reasoner module"). This is the first performance-focused doc in the codebase and establishes the discipline that future reasoner additions can be measured against.

**Tests: 1106 → 1106 (unchanged).** The fixes are pure refactors that don't change any observable behavior, so no test updates were needed. All 1106 tests still pass. Ruff clean.

**What's intentionally NOT in v0.2.28:** BFS walker optimization in `assume_role_chain` and `admin_reachability`. Those reasoners showed up in the profile at sub-millisecond per-run costs, well below the threshold worth optimizing. A future release could generate an XL benchmark with many trust-chain edges to exercise the BFS walker at scale, but at the current benchmark density those reasoners are not measurable and any "optimization" would be speculation against imaginary numbers. **Rule of thumb:** don't optimize what you can't measure.

### v0.2.27: Property-based testing for Finding invariants

**The first property-based test infrastructure in the codebase.** Introduces `hypothesis` strategies for the core domain objects and a `tests/test_finding_properties.py` module exercising the `Finding` class's structural invariants across thousands of randomly-generated instances per test run.

**Why property-based testing now:** the 8-reasoner suite has reached a scope where the combinatorial invariant space is too large for example-based tests alone. Before v0.2.27, the Finding invariants (VALIDATED requires all-PASS checks, BLOCKED requires a FAIL and a blocker, PRECONDITION_ONLY requires PASS-AND-FAIL-AND-blocker, cross-reference validity, trace step contiguity, evidence_refs scope restrictions) were tested with ~3 example cases each. Those examples cover the canonical happy paths but cannot exercise pathological shapes like "what if a VALIDATED finding has 12 checks, 11 PASS and one FAIL?" or "what if an INCONCLUSIVE finding has a Check referencing a statement digest that isn't in the bundle?" Property tests generate these shapes automatically and shrink to minimal counterexamples when an invariant breaks, which is exactly the kind of bug class the refuses-to-lie discipline depends on catching structurally rather than relying on reasoner authors to never make a mistake.

**New module `tests/strategies.py`** (~350 lines) with hypothesis strategies for every domain object in the Finding/Check/EvidenceBundle construction graph:

- **Primitives:** `severity_strategy()` (5 canonical values), `check_state_strategy()` (3 states), `verdict_strategy()` (4 verdict shapes), `_opaque_id_strategy(prefix)` (integer-mapped ref IDs), `sha256_digest_strategy()` (integer-concatenated 64-char hex), `provider_id_strategy()` (closed set of plausible AWS ARNs)
- **Model objects:** `node_ref_strategy()`, `trace_entry_strategy(step)`, `trace_strategy(min_size, max_size)` (generates a contiguous step-numbered trace), `blocker_strategy()`, `assumption_strategy(exclude_condition_context)`, `check_strategy(state, evidence_refs_pool)` (Check with optional forced state and ref pool constraint), `evidence_bundle_strategy(min_refs, max_refs, max_trace)` (returns the bundle AND its reference pool so downstream Check strategies can draw cross-reference-valid refs)
- **Finding shapes, one strategy per verdict:** `validated_finding_strategy()` (all PASS checks, no blockers, no condition_context assumption), `blocked_finding_strategy()` (≥1 FAIL check, ≥1 blocker), `inconclusive_finding_strategy()` (permissive with at least one UNKNOWN check), `precondition_only_finding_strategy()` (≥1 PASS + ≥1 FAIL + ≥1 blocker), `any_finding_strategy()` (union of all four)

**Critical design decision, strategies respect invariants:** a `validated_finding_strategy` only produces findings where every check is PASS. This means the strategies test the strategies as well as the invariants; a bug in the Finding class that weakens an invariant would cause the strategies to produce findings the dataclass silently accepts but that violate the documented contract. The strategies are the first layer of defense; `__post_init__` is the second.

**Critical performance fix, do not use `from_regex`:** my first pass used `st.from_regex(r"^[a-f0-9]{64}$", fullmatch=True)` for the statement digest strategy. This caused every property test to hang because hypothesis spends enormous effort exploring regex shrinking candidates for hex character sets. Replaced with `st.tuples(st.integers(min_value=0, max_value=2**128-1), ...).map(lambda pair: f"{pair[0]:032x}{pair[1]:032x}")` which is substantially faster; integers are first-class shrinkable primitives in hypothesis and the resulting digest strings are well-typed. Same pattern for `_opaque_id_strategy` which now maps an integer counter to a padded hex suffix. Lesson: for fixed-shape hex/opaque-id strategies, integer-mapped generators are 50-100× faster than regex-based ones in hypothesis, and the resulting string space is adequate for property coverage.

**New module `tests/test_finding_properties.py`** (~300 lines) with 15 property tests across 6 test classes:

- **`TestConstructionInvariants`** (4 tests, 200 examples each): verifies that each strategy's output satisfies the invariants it was designed to respect. A validated strategy produces all-PASS findings with no blockers and no condition_context assumptions. A blocked strategy produces findings with ≥1 FAIL check and ≥1 blocker. Etc.
- **`TestRefusesToLie`** (3 tests, 50 examples each): **the core differentiator.** Takes a valid VALIDATED finding from the strategy, mutates it to inject a FAIL/UNKNOWN check or a condition_context assumption, and asserts that reconstructing the Finding raises `InvalidFindingError`. This property validates that the three-layer refuses-to-lie enforcement (fact / reasoner / invariant) actually catches structural violations. If a bug weakened `_validate_validated_invariants` to accept a VALIDATED finding with a FAIL check, this test would catch it immediately with a shrunk counterexample.
- **`TestDeterminism`** (3 tests, 100 examples each): verifies that `finding_id` and `bundle_digest` are deterministic across multiple invocations on the same finding. Also verifies that `finding_id` is always a 64-character lowercase hex string regardless of which verdict shape generated it.
- **`TestTraceContiguity`** (1 test, 200 examples): verifies that every generated finding's reasoning_trace has steps 1,2,...,n (the EvidenceBundle invariant). This tests both the strategy and the dataclass guard.
- **`TestCrossReferenceValidity`** (1 test, 200 examples): verifies the §3.5 invariant 1: every `Check.evidence_refs` value appears in the bundle's `statement_digests`, `edge_refs`, or `constraint_refs` pool. Dangling references prevent auditors from verifying checks, and a bug in the strategy that produced dangling refs would cause `__post_init__` to raise immediately, so this test also validates the strategy's pool-sharing design.
- **`TestStructuralInvariants`** (3 tests, 100 examples each): severity is one of the 5 canonical values, verdict is a Verdict enum member, title is non-empty.

**Total: ~2000 random Finding instances exercised per test run across 15 tests.** Runs in ~20 seconds on first run; subsequent runs are faster due to hypothesis's example database caching interesting cases.

**What's explicitly NOT in scope for v0.2.27** (deferred to future versions):
- Reasoner-level property tests (would require FactGraph strategies which are substantially more complex, coordinated Node/Edge/Constraint generation respecting domain rules). Target: v0.2.27.1 or v0.2.28.
- Parser robustness property tests (would require policy document generators). Target: v0.2.27.2.
- FactGraph composition property tests (would test the fact graph construction rules themselves). Target: v0.2.27.3.
- Edge case tests for malformed input handling (would require "near-valid" generators that produce inputs at the boundary of the valid space). Target: v0.2.28.

**New dependency: `hypothesis` 6.x** added as a test-only dependency. No runtime impact on the shipping `iamscope` package. The property tests only run when the test suite runs.

**Tests: 1091 → 1106 passing (+15 property tests).** Ruff clean.

**v0.2.27 is a foundation change, not a feature change.** No new reasoners, no new fact-layer types, no new CLI commands. The point is to provide the infrastructure that future reasoner additions can plug into for automatic invariant coverage. Every reasoner shipped after v0.2.27 can reuse the strategies to test its own Finding construction without writing bespoke example-based test fixtures, just `@given(validated_finding_strategy())` and the reasoner-specific predicate. That's how the combinatorial coverage scales with the reasoner count.

### v0.2.26: s3_bucket_takeover reasoner (the 8th reasoner)

The **eighth shipping reasoner**: models principals (users + roles) with authority to rewrite an S3 bucket's policy via `s3:PutBucketPolicy`. This is a structural bucket-policy rewrite risk: a future policy change may grant broad bucket access depending on the policy written, existing controls, and runtime context. IAMScope records the modeled permission path; it does not prove object access, data exposure, or downstream authorization.

**The pattern:** Alice (user) OR DeployerRole (role) has `s3:PutBucketPolicy` with `Resource: arn:aws:s3:::corp-secrets`. If runtime context and AWS enforcement allow the action, that principal may be able to submit a new bucket policy granting broader access to that bucket. This is modeled as a high-impact S3 policy-control risk, not proof that objects were accessed or data was exposed.

**v1 scope decision, minimal viable primitive:** only `s3:PutBucketPolicy`. Explicitly out of scope for v1: `s3:PutBucketAcl` (the legacy ACL mechanism, similar impact but less common), `s3:DeleteBucket` + `s3:CreateBucket` (the subdomain-takeover variant, requires prior deletion and separate runtime conditions), `s3:PutPublicAccessBlock` (disabling public access block as a precursor), `s3:PutObject`-based tampering (data integrity risk, not policy-control risk). A v2 could add any of these as additional primitives reusing the same scaffolding. The v1 scope is the cleanest single-primitive version of the reasoner and the common case in real pentest findings.

**Source scoping:** users AND roles (unlike `iam_group_membership_escalation` which is user-only). Both identity types can matter when the corresponding credentials or role session are in scope. The 5th check (`principal_is_actionable`) filters service principals (`*.amazonaws.com`) and account root because those represent infrastructure, not actionable principals for this modeled finding. A Lambda execution role with `s3:PutBucketPolicy` can be relevant, but the AWS service principal `s3.amazonaws.com` itself is not. Root accounts already have owner-level authority on buckets they own, so `s3:PutBucketPolicy` on root is a non-finding.

**Target scoping:** all S3Bucket nodes in the graph. For each (principal, bucket) pair where the principal holds a clean or wildcard `s3:PutBucketPolicy` permission edge, emit one finding. Deduplicated across multiple witness statements so a principal with the action granted via three separate policy statements gets one finding per bucket, not three.

**Fact-layer changes needed (parser AND collector per Rule 2, now a fully greenfield new resource type, not just a new action on an existing type):**

1. **New constant:** `NODE_TYPE_S3_BUCKET: str = "S3Bucket"` in `iamscope/constants.py`.

2. **Parser 3-touch**: added `S3_ACTIONS = {"s3:putbucketpolicy"}` to `iamscope/parser/permission_policy.py`, extended `RELEVANT_ACTIONS` union, added `"s3:putbucketpolicy": "s3:PutBucketPolicy"` to `canonical_map`.

3. **ARN classifier update in `_classify_resource_arn`**: added `:s3:::` → `NODE_TYPE_S3_BUCKET` branch. S3 uses a global namespace (no region, no account in ARN), so the triple-colon substring `:s3:::` is unique to S3 ARNs. Both bucket-level ARNs (`arn:aws:s3:::my-bucket`) and object-level ARNs (`arn:aws:s3:::my-bucket/path/to/key.txt`) classify as S3Bucket. This is a breaking change for any user of `_infer_node_type_from_arn` that was relying on S3 ARNs falling back to IAMRole: `tests/test_passrole.py::TestTyp1NodeTypeInference::test_unknown_arn_falls_back_to_iam_role` was updated to use a DynamoDB table ARN as the "truly unknown" example, and a new `test_s3_bucket_arn_maps_to_s3_bucket` verifies both bucket-level and object-level S3 ARNs classify correctly.

4. **New S3 collector** `iamscope/collector/s3_collector.py` (~90 lines): minimal discovery via `s3.list_buckets()`, which is the ONLY boto3 call in the collector. No `get_bucket_policy`, no `get_bucket_acl`, no `get_public_access_block`: the reasoner only cares that a principal CAN rewrite the policy, not what the current policy is. Per Invariant #1 (READ-ONLY ONLY), `list_buckets` is the only permission the collector requires. Per Invariant #18, `list_buckets` is NOT a paginated API (boto3 returns all buckets in a single call), so no pagination loop is needed. One `S3Bucket` node created per discovered bucket with `provider_id=arn:aws:s3:::{name}`, `region=aws-global`, and properties `{"account_id": ..., "bucket_name": name, "is_synthetic": False}`. No service edges emitted: S3 buckets don't have an execution-role lateral-movement primitive like Lambda or EC2; they're pure target nodes that the reasoner walks to from IAM principals.

5. **Pipeline wiring**: added `collect_s3: bool = True` config flag to `PipelineConfig`, imported `collect_s3_buckets` at the top, wired into both single-account and org-mode flows after the `collect_kms` call, exported from `iamscope/collector/__init__.py` in the `__all__` list.

**New reasoner module `iamscope/reasoner/s3_bucket_takeover.py`** (~400 lines): `S3BucketTakeoverReasoner` with `pattern_id="s3_bucket_takeover"`, 5-check structure, verdict mapping, severity always critical when validated.

**5-check structure:**
1. `principal_has_put_bucket_policy_permission`: enumeration invariant, always PASS (candidate wouldn't be enumerated otherwise; included for audit trail)
2. `witness_edge_is_clean`: PASS if the witness resolves to a specific bucket, UNKNOWN if the edge is a hyperedge or wildcard-resource (in which case the reasoner iterates all buckets as potential targets)
3. `no_scp_blocks_put_bucket_policy`: SCP blocker check, same pattern as other reasoners
4. `no_boundary_blocks_put_bucket_policy`: permission boundary blocker check
5. `principal_is_actionable`: filter out service principals (`*.amazonaws.com`) and root; failing check 5 drops the finding entirely (not emitted)

**Verdict mapping:**
- Check 3/4 FAIL → `blocked/info`
- Check 5 FAIL → no finding emitted (filtered, not actionable for this modeled risk)
- Any check UNKNOWN → `inconclusive/high`
- All PASS → `validated/critical` (modeled bucket-policy rewrite authority on the selected bucket)

**19 new unit tests** in `tests/test_s3_bucket_takeover_reasoner.py` across 8 test classes: `TestPreconditions` (4), `TestValidatedFindings` (5, including contiguous-trace-step-numbers invariant), `TestWildcardInconclusive` (2, including hyperedge iteration), `TestSCPBlockers` (2), `TestBoundaryBlockers` (1), `TestActionabilityFilter` (2, root filtered, service principal filtered), `TestMultiplePairs` (2; two users one bucket, one user two buckets), `TestDeterminism` (1). All 19 passing on first run.

**3 new golden fixtures** in `TestS3BucketTakeoverGoldens`: A (validated/critical Alice → corp-secrets bucket), B (inconclusive/high wildcard resource witness), C (blocked/info SCP denies PutBucketPolicy). All 3 passing against the canonical byte-pinned JSON after regeneration.

**E2E smoke test** with moto, passes on first run with no diagnostic iterations needed. This is the first greenfield reasoner where the smoke test caught ZERO unexpected interactions on first execution; normally new fact-layer types surface at least one edge-classifier or node-matching bug. The clean first run is a signal that the architecture scaffolding from previous versions (parser 3-touch, ARN classifier, collector pattern, pipeline wiring pattern) is stable enough that adding a new resource type is becoming a mechanical process rather than a diagnostic adventure.

**1 additional test in `tests/test_passrole.py`**, `test_s3_bucket_arn_maps_to_s3_bucket` verifies both bucket-level and object-level S3 ARNs classify as S3Bucket. The existing `test_unknown_arn_falls_back_to_iam_role` was updated to use a DynamoDB table ARN as the unknown-pattern example.

**Tests: 1068 → 1091 passing (+23 = 19 unit + 3 goldens + 1 classifier).** Ruff clean. **8 shipping reasoners** now (was 7).

### v0.2.25: iam_group_membership_escalation reasoner (the 7th reasoner)

The **seventh shipping reasoner**: models users who may be able to gain admin-equivalent group membership via `iam:AddUserToGroup` by adding themselves, or another controlled user, to an admin-equivalent IAM group. This is a structural IAM group-membership risk pattern, subject to action/resource scope, conditions, boundaries, SCPs, and runtime context.

**The pattern:** IAMUser Alice has `iam:AddUserToGroup` with `Resource: arn:aws:iam::111:group/Admins`. The `Admins` group has a managed policy granting `iam:*` or similar admin-equivalent permissions. If the action is permitted in runtime context, adding Alice to that group may grant admin-equivalent permissions. IAMScope models the permission path; it does not prove the API call was made or that downstream authorization succeeded.

**Source scoping (v1):** only `IAMUser` sources. Roles are excluded because a role session cannot directly benefit from adding a user to a group without a separate credential-control path, which is outside this pattern. A v2 could extend to role sources where there is a back-path via `sts:AssumeRole` from a user.

**Target scoping:** only admin-equivalent `IAMGroup` nodes. If the target group isn't admin-equivalent, adding users to it isn't privilege escalation, it's routine user management. No finding emitted. This is the check 5 filter at the reasoner layer.

**Fact-layer changes needed (parser AND collector per Rule 2):**

1. **Parser 3-touch**: added `IAM_GROUP_ACTIONS = {"iam:addusertogroup"}` to `iamscope/parser/permission_policy.py`, extended `RELEVANT_ACTIONS` union, added `"iam:addusertogroup": "iam:AddUserToGroup"` to `canonical_map`.

2. **Collector enhancement for group-sourced permission edges**: the existing `_process_group` in `iamscope/collector/account.py` only created group NODES; group permissions flowed to users via R10 inheritance but the group itself had no outgoing permission edges. This made admin-equivalence detection via the shared `admin_detection.find_admin_witness_edge` helper impossible for groups (it walks `facts.edges_from(group)` and would find nothing). **The fix:** extend `_process_group` to also parse the group's policies with `source_arn=group_arn, source_node_type=NODE_TYPE_IAM_GROUP`, producing parallel group-sourced permission edges alongside the existing user-inheritance edges. Both the user edge and the group edge carry the same statement digests: this is correct; both represent real permission paths that a reasoner might want to audit separately.

3. **ARN classifier update in `_classify_resource_arn`**: the existing classifier in `iamscope/collector/passrole.py` handled `:role/`, `:function:`, `:cluster/`, `:instance/`, `:secret:` but NOT `:group/`. Without this, `iam:AddUserToGroup` edges pointing to group ARNs were classified as `IAMRole` via the legacy fallback, and the scenario-json validator rejected the edge because the dst node_type didn't match the actual IAMGroup node. Added `:group/` → `NODE_TYPE_IAM_GROUP` branch. This caught me during the E2E smoke test: the unit tests and golden fixtures all built their facts directly without going through the edge builder, so the bug was invisible until the live moto pipeline ran.

**The existing `test_group_permissions_attributed_to_user` test** (in `tests/test_account_collector.py`) was updated to reflect the new dual-sourcing invariant. The R10 user-inheritance path still produces user-sourced permission results; the test now verifies that at least one user-sourced result exists for `policy_source=group_inline` rather than asserting ALL are user-sourced (now they're split between user-sourced via inheritance and group-sourced via the new direct parse).

**New reasoner module `iamscope/reasoner/iam_group_membership_escalation.py`** (~500 lines): `IAMGroupMembershipEscalationReasoner` with `pattern_id="iam_group_membership_escalation"`, 5-check structure, verdict mapping, severity scaling. The reasoner delegates admin-equivalence detection to the shared `admin_detection.find_admin_witness_edge(facts, group_node)`, the helper's `target_role` parameter name is misleading but the function is typed as `Node` and works on any node with outgoing permission edges.

**5-check structure:**
1. `source_has_add_user_to_group_permission`: enumeration invariant, always PASS (candidate wouldn't be enumerated otherwise; included for audit trail so a reviewer running `iamscope why` sees the full check list)
2. `witness_edge_is_clean`: PASS if the witness resolves to a specific group, UNKNOWN if the edge is a hyperedge or wildcard-resource (hyperedge → iterate all groups as potential targets)
3. `no_scp_blocks_add_user_to_group`: SCP blocker check, same pattern as other reasoners
4. `no_boundary_blocks_add_user_to_group`: permission boundary blocker check
5. `target_group_is_admin_equivalent`: delegate to shared `admin_detection.find_admin_witness_edge` on the group node; PASS if admin witness edge found, FAIL if not (no finding emitted)

**Verdict mapping:**
- Check 3/4 FAIL → `blocked/info`
- Check 5 FAIL → no finding emitted (not an escalation pattern)
- Any check UNKNOWN → `inconclusive/high`
- All PASS → `validated/critical` (modeled admin-equivalent group membership risk)

**Severity rationale:** validated findings are critical because modeled admin-equivalent group membership can confer the full group permission set under the scoped scenario. Inconclusive = high (not critical) because the wildcard case is common and would flood pentest reports if classified as critical.

**20 new unit tests** in `tests/test_iam_group_membership_escalation_reasoner.py` across 8 test classes: `TestPreconditions` (4), `TestValidatedFindings` (6), `TestNonAdminTargetFiltered` (2), `TestWildcardInconclusive` (2, including the hyperedge case), `TestSCPBlockers` (2), `TestBoundaryBlockers` (1), `TestRoleSourceFiltered` (1), `TestMultipleUsers` (1), `TestDeterminism` (1). All 20 passing on first run.

**3 new golden fixtures** in `TestIAMGroupMembershipEscalationGoldens`: A (validated/critical Alice → admin group), B (inconclusive/high wildcard resource witness), C (blocked/info SCP denies AddUserToGroup). Follows the same aliased-import pattern as the priority 3b/3c/3d goldens.

**E2E smoke test** with moto: creates `Admins` group with `iam:*` managed policy, creates Alice user with inline `iam:AddUserToGroup` grant targeting the Admins group ARN, runs the full pipeline, verifies the `iam_group_membership_escalation` finding shows up with `verdict=validated, severity=critical`. **7 reasoners now registered**; the smoke test shows all 7 in `metadata.reasoners_run` even though only IGME fires on this minimal fixture.

**Tests: 1045 → 1068 passing (+23 = 20 unit + 3 goldens).** Ruff clean. **7 shipping reasoners** now (was 6).

### v0.2.24: The `why` subcommand: finding introspection with refuses-to-lie UX

**New subcommand: `iamscope why <filter>`**: explains why a specific finding was emitted with the verdict it got. Walks the finding's check results, evidence bundle, blockers, and optional reasoning trace to show the exact reasoning path from raw fact graph to final verdict. The core design principle: **the refuses-to-lie invariant should be visible in the output**. When a finding is INCONCLUSIVE because a check returned UNKNOWN, the `why` output calls that out explicitly, naming the specific ambiguity (wildcard resource, condition block, hyperedge) that prevented the reasoner from guessing.

**Why this UX change matters:** IAMScope's architectural differentiator is the tristate UNKNOWN discipline enforced at three layers (fact, reasoner, invariant). Before this release, that discipline was visible in the code and architecture docs, but a reviewer still had to read raw JSON to ask why a finding was inconclusive instead of validated. The `why` subcommand makes that path visible in the CLI. Every INCONCLUSIVE finding gets a `⚠  Why this is inconclusive (refuses-to-lie)` callout that names the UNKNOWN check(s) and explains that IAMScope refuses to guess PASS or FAIL when a check is ambiguous. The finding needs human review.

**Filtering flexibility:** findings can be located by `--finding-id <prefix>` (so `abc123` matches `abc123def456...`), `--pattern <pattern_id>` exact match, `--source <arn_substring>` + `--target <arn_substring>` substring match, or any AND combination of the above. When filters match multiple findings, the CLI produces a disambiguation list with finding_id prefixes and source/target info so the user can refine without having to read the raw JSON.

**Rich terminal output with auto-detected colors.** `[✓]` green for PASS, `[✗]` red for FAIL, `[?]` yellow for UNKNOWN (the "refuses-to-lie" color). Verdict labels are color-coded: validated=green, blocked=red, inconclusive=yellow, precondition_only=blue. Severity labels scale with impact: critical=red-bold, high=red, medium=yellow, low=blue. Colors auto-disable when stdout is not a TTY (piped to `less`, `grep`, etc.) and can be forced off with `--no-color`. A dedicated `_ambiguity_hint` helper translates reason strings into descriptive phrases, "wildcard-resource or hyperedge-expansion ambiguity," "runtime-dependent Condition block in source policy," "constraint parse incomplete; governance confidence partial," etc.; so reviewers get actionable context without having to memorize the reason-string vocabulary.

**The `--verbose` flag** adds the full `reasoning_trace` from the evidence bundle, step-by-step evaluation with inputs, result, and reason for each check. Useful when a finding's top-level checks look fine but something in the trace (a per-hop result, a per-blocker binding) reveals the actual issue. This is the kind of output that matters when a pentester is debugging a weird finding at 2am during a real engagement.

**New module `iamscope/why.py`** (~350 lines) containing:
- `_Colors` class, ANSI color helpers with an `enabled` flag that no-ops all wrapping when disabled
- `should_use_color(explicit_no_color)`, auto-detect via `sys.stdout.isatty()`, respecting explicit override
- `locate_finding(findings, ...)`, filter by finding_id prefix, pattern_id exact, source/target substring, returns (matches, error) tuple for the caller to disambiguate
- `explain_finding(finding, verbose, use_color)`, the main renderer; produces a multi-line string with header, source/target, verdict reasoning, per-check breakdown, UNKNOWN callout (for inconclusive), blockers, evidence bundle summary, optional trace, and footer
- `format_disambiguation_list(matches, use_color)`, multi-match disambiguation with refine hint
- `_verdict_color`, `_severity_color`, `_check_state_marker`, `_ambiguity_hint`, rendering helpers

**New CLI subcommand** wired into `iamscope/cli.py`:
- `why_parser` defined inline with the other subparsers (collect, report, enrich, diff, validate)
- `_cmd_why(args)` handler that loads findings.json, calls `locate_finding`, dispatches to `explain_finding` or `format_disambiguation_list` based on match count, returns 0 on success, 1 on error or multi-match

**42 new unit tests** in `tests/test_why_explainer.py` covering:
- `TestColors` (2 tests), disabled vs enabled ANSI wrapping
- `TestShouldUseColor` (2 tests), explicit no_color override + TTY detection
- `TestLocateFinding` (8 tests), no filter error, finding_id prefix match, no match, pattern exact, source substring, target substring, combined AND filter, multiple matches
- `TestExplainFinding` (14 tests), verdict header, PASS check markers, refuses-to-lie callout, ambiguity hint, blocker rendering for precondition_only and blocked, verbose trace, non-verbose omit, source/target shown, verdict reasoning shown, no-color ANSI-free output, color ANSI-present output, evidence bundle counts, scenario_hash footer
- `TestAmbiguityHint` (5 tests), wildcard/condition/partial/deny hint translation + raw-reason fallback
- `TestDisambiguationList` (3 tests), count header, all matches shown, refine hint shown
- `TestCliIntegration` (8 tests), end-to-end via `main()` with a temp findings.json: success path, missing file, no match, multi match, combined narrow filter, verbose flag, empty findings, captured stdout verification

**All 42 tests pass on first run.** The clean separation between CLI handler and render module made both testable in isolation.

**Live demo in the README** using a PRECONDITION_ONLY/medium KMS-blocked secret read shows the full output format so a new user can see what to expect before running the tool. Linked from a new "The `why` subcommand" section right after the documentation section.

**Tests: 1003 → 1045 passing (+42).** Ruff clean. Zero changes to reasoners, fact layer, or golden fixtures. This is a UX feature layered on top of the existing architecture. The byte-pinned goldens, the 6 reasoners, the pipeline, the fact graph, the constraints, and the collectors are untouched.

This feature makes the evidence-bound invariant visible in normal review workflows. Every INCONCLUSIVE finding includes a built-in explanation of why the reasoner could not prove the verdict, for example an UNKNOWN result on `check_2_clean_witness` caused by wildcard-resource or hyperedge-expansion ambiguity that needs human review.

### v0.2.23: KMS v2 for secrets_blast_radius

Closes the documented v1 limitation from priority 3d: the `secrets_blast_radius` reasoner now checks whether the candidate principal can actually decrypt the secret's encryption key via the KMS key policy, not just whether IAM grants `secretsmanager:GetSecretValue`. The IAM layer and the KMS layer both have to say yes for the reasoner to emit a `validated` finding.

**New fact-layer infrastructure (parser AND collector per Rule 2):**

- `NODE_TYPE_KMS_KEY = "KMSKey"` in `iamscope/constants.py`
- `iamscope/collector/kms_collector.py` (new, ~155 lines), minimal boto3-based collector following the `lambda_collector.py` pattern. Pulls keys via `list_keys` + `describe_key` + `get_key_policy`, creates `KMSKey` nodes with the raw policy JSON stored as a `key_policy` property and metadata (`key_id`, `key_manager`, `description`, `key_state`). No service edges; KMS keys don't have a lateral-movement primitive; the reasoner that consumes these nodes looks them up by ARN from the secret's `kms_key_id` property.
- `iamscope/pipeline.py` wiring: `collect_kms_keys` imported, `collect_kms: bool = True` and `kms_regions: list[str] = ["us-east-1"]` config flags added to `CollectionConfig`, wired into both single-account and org-mode flows.
- `iamscope/collector/__init__.py`, `collect_kms_keys` exported.

**New reasoner helpers in `iamscope/reasoner/secrets_blast_radius.py`:**

- `_kms_policy_allows_decrypt(policy_json, principal_arn, principal_account_id, key_arn)`, the KMS policy evaluator. Returns `(CheckState, reason)`. Handles three common Allow patterns: account-root delegation (`Principal: {"AWS": "arn:...:root"}`), specific principal grants (`Principal: {"AWS": "arn:...:user/Alice"}`), and wildcard principals (`Principal: "*"`). Handles `Action` as string or list, `Resource` as string or list, and `_DECRYPT_ALLOWING_ACTIONS = {kms:decrypt, kms:*, *}`. **Refuses to guess on complex cases:** any Deny statement → UNKNOWN (conservative), any matching Allow with a Condition block → UNKNOWN, `NotPrincipal`/`NotAction`/`NotResource` clauses → UNKNOWN, malformed JSON → UNKNOWN.
- `_principal_matches(principal, principal_arn, account_root_arn)`, the principal field matcher. Handles `"*"`, dict with `AWS` key (string or list), and accepts either the specific principal ARN or the account root ARN.
- `_resource_matches_kms(resources, key_arn)`, the resource field matcher. Handles string or list, accepts `"*"` or the exact key ARN.

The helpers are module-level private functions (not a shared module) because only one reasoner consumes them, Rule 7 says clone until the 3rd caller. If a future KMS-aware reasoner appears, extract then.

**Reasoner integration:**

- New method `_check_kms_decrypt_allowed(facts, principal, secret)` on `SecretsBlastRadiusReasoner`. Looks up the secret's `kms_key_id` property. If empty or equal to `alias/aws/secretsmanager`, returns `(PASS, "secret uses AWS-managed default KMS key (delegates to IAM)", None)`, the AWS-managed default key case is always PASS because access is fully gated by IAM. If the kms_key_id is a CMK ARN, walks `facts.nodes` looking for a `KMSKey` node whose `provider_id` or `key_id` matches. If no matching node is found, returns `UNKNOWN`; the reasoner can't verify the KMS layer without the key in the graph. If a matching node is found, reads its `key_policy` property and delegates to `_kms_policy_allows_decrypt`.

- New Check 6 `kms_key_policy_allows_decrypt_for_principal` appended to `check_results` in `_build_finding`. Traced at step 5 (contiguous from 1, the trace invariant requires this; check 5 the principal filter doesn't produce a trace entry because it's an early-exit).

- Updated `_compute_verdict_and_severity` with new Rule 2.5: if check 6 is FAIL, return `(PRECONDITION_ONLY, "medium", "KMS key policy does not allow kms:Decrypt for principal")`. The existing Rule 4 scan catches check 6 UNKNOWN via the general `unknown_checks = [c.name for c in check_results if c.state is CheckState.UNKNOWN]` pattern.

- When check 6 is FAIL, the reasoner appends a `Blocker(kind="kms_key_policy", constraint_id=<kms_node_id>, edge_id=permission_edge.edge_id, reason=...)` to `blockers_observed`. This satisfies the `_validate_precondition_only_invariants` guard on `Finding` construction which requires PRECONDITION_ONLY findings to have at least one blocker attributing the path block.

- When check 6 resolves to any state (PASS/FAIL/UNKNOWN), the KMSKey node's `node_id` is added to the evidence bundle's `node_refs` so reviewers can audit which key was evaluated.

**Semantic rationale for PRECONDITION_ONLY mapping:** the KMS layer blocking a secret read is semantically identical to "principal has `lambda:CreateFunction` but target role doesn't trust Lambda" in `passrole_lambda`, IAM allows the action but an enforcement layer (KMS, Lambda trust policy) blocks the modeled chain as written. Both cases map to PRECONDITION_ONLY rather than BLOCKED because the principal still has the IAM permission and may have other scoped paths to review.

**Severity rationale for medium:** KMS-blocked secret reads are interesting for pentesters to investigate (the CMK policy might be misconfigured or change in the future) but not immediately actionable. Medium severity puts them in the "worth noting" tier without flooding high-value findings.

**17 new unit tests:**

- `TestKmsPolicyAllowsDecrypt` (11 tests), the helper evaluator: account-root delegation PASS, specific principal grant PASS, wildcard principal PASS, wildcard action PASS, specific resource ARN PASS, no matching Allow FAIL, malformed JSON UNKNOWN, Deny statement UNKNOWN (with pre-pass scan to catch Deny regardless of statement order), conditioned Allow UNKNOWN, NotPrincipal clause UNKNOWN, empty policy UNKNOWN.
- `TestKmsIntegration` (6 tests), reasoner-level integration: AWS-managed default still validated, CMK with account-root delegation validated, CMK blocks principal precondition_only, CMK with conditions inconclusive, CMK not in graph inconclusive, AWS-managed alias still validated.

**2 new golden fixtures** added to `TestSecretsBlastRadiusGoldens`:

- **Fixture D**: CMK blocks principal → `precondition_only/medium` (Alice reads secret encrypted with CMK whose policy only grants Bob)
- **Fixture E**: CMK policy has Condition → `inconclusive/medium` (Alice reads secret encrypted with CMK whose account-root delegation is conditioned on aws:SourceVpc)

Fixtures A, B, C from priority 3d were regenerated because check 6 is now part of the finding's `required_checks` tuple and the trace has a new step. They still assert the same verdict/severity for the non-KMS cases (fixtures A/B/C don't have KMSKey nodes, so check 6 returns PASS automatically via the AWS-managed default branch). Total SBR goldens: 5 (was 3).

**Tests: 984 → 1003 passing (+19 = 17 unit tests + 2 goldens).** Ruff clean.

**E2E smoke test** with a real moto `kms.create_key` + restrictive policy + `secretsmanager.create_secret(KmsKeyId=...)` verified both paths end-to-end: Alice reading an AWS-managed-default secret produces `validated/high`, Alice reading a CMK-restricted secret produces `precondition_only/medium`. The `findings_hash` changed (expected, intentional behavior change).

**v2 limitations documented in the module docstring:** the reasoner does NOT handle KMS grants (`kms:CreateGrant`), does NOT handle explicit Deny statements that might override Allows (conservative: any Deny → UNKNOWN), does NOT handle cross-account `kms:Decrypt` via ExternalId, and does NOT walk nested conditions across multiple statements. Complex cases fall through to UNKNOWN, producing inconclusive findings. A v3 pass could extend the evaluator to handle grants and explicit Deny cancellation, deferred until a real pentest engagement surfaces a case where the current conservative behavior produces too many inconclusive findings.

**Bonus: passrole_ecs enumeration `OR → AND` fix.** The `passrole_ecs` reasoner's candidate enumeration at line 229 was using `state_register is not CheckState.FAIL or state_run is not CheckState.FAIL`, which over-enumerated principals with only one of the two required ECS actions (RegisterTaskDefinition, RunTask). The over-enumeration was correctness-preserving because `_build_finding` correctly short-circuits on `_and_tristate(register_state, run_state) == FAIL`, so the final findings were unchanged, but the reasoner wasted cycles evaluating candidates that couldn't possibly produce findings. Fixed to `and`: principals now need both actions in some form (PASS or UNKNOWN on both) to be enumerated. **Verified byte-stable** by running the 7 ECS golden fixtures + 35 ECS unit tests + the full 1003-test suite: zero drift. The inefficiency was flagged during the priority 4 UNKNOWN discipline audit (v0.2.22) and deferred because I wasn't certain the fix was byte-stable. It is. Fix shipped now.

### v0.2.22: Priority 4 audit complete + architectural decisions documentation

**Priority 4, UNKNOWN discipline audit; complete, zero bugs found.** Audited 8 subsystems across two invocations looking for places where the tristate UNKNOWN state might be silently collapsed to PASS or FAIL: (1) `has_action` in fact_graph.py, (2) `and_tristate` / `and_tristate_many` combinators, (3) all 6 reasoners' `_compute_verdict_and_severity` methods, (4) `Finding._validate_validated_invariants` as last-line-of-defense, (5) enumeration patterns across all 6 reasoners using `state is not CheckState.FAIL` to include UNKNOWN candidates, (6) bool-to-tristate ternaries (all 6 locations found are on deterministic binary conditions), (7) report renderer `findings_renderer.py` with its dedicated "Why this is inconclusive" callout, (8) `has_action` call-site `resource_pattern` usage. **Zero bugs.** The 4-month-old rebuild baseline has been disciplined about refuses-to-lie from the start, and the shared modules extracted in priority 3c-refactor preserved the discipline.

One defensive-pattern finding worth highlighting: `passrole_lambda.py:274-275` has an explicit "bail to UNKNOWN" path for the unexpected internal-inconsistency scenario where `has_action` returns non-FAIL but `_find_witness_edge` can't produce a concrete witness. This is the exact shape of "when in doubt, say unknown" that the audit was looking for, and it's already there. One minor inefficiency noted (the `passrole_ecs.py:229` enumeration uses `OR` instead of `AND`, over-enumerating candidates without affecting correctness; deferred because the fix would perturb 7 golden fixtures).

**Architectural decisions documentation**: `docs/ARCHITECTURE.md` (328 lines) and `docs/CONTRIBUTING.md` (~180 lines). ARCHITECTURE.md captures the 10 architectural rules learned from priorities 1-4: (1) UNKNOWN is a first-class tristate, (2) new resource types need BOTH parser AND collector changes, (3) admin equivalence detection is two-tier with ≥3 service prefix threshold, (4) Check.evidence_refs can only reference edges/statements/constraints, (5) refuses-to-lie is enforced at three layers, (6) byte-pinned golden fixtures are the ground truth, (7) shared modules extracted only when 3+ reasoners share a primitive, (8) Finding construction requires explicit node_ref + edge_ref + constraint_ref tracking, (9) severity scaling is per-reasoner not centralized, (10) the 6-phase reasoner-addition workflow. Each rule is stated first, then the incident that taught us the rule, then the code that enforces it, so a future contributor reading the doc can trace any rule back to its provenance.

CONTRIBUTING.md is the lighter contributor-facing companion: before-you-change-anything checklist, refuses-to-lie invariant explanation, 6-phase reasoner-addition workflow, new-resource-type checklist, golden fixtures workflow, PR checklist, and a quick-reference table. Links from README.md new "Documentation" section.

**Priority 3 and Priority 4 are now completely shipped.** The original post-rebuild scope is closed with zero deviations from the S01-S14 rebuild contract. At that checkpoint: 6 shipping reasoners, clean ruff, the then-current full suite passing, 32 byte-pinned golden fixtures, end-to-end smoke verified with all 6 reasoners producing findings, architectural decisions documented, contribution guide in place.

### v0.2.21: Priority 3d: secrets_blast_radius reasoner + tier-2 admin detection tightening

The **sixth and final shipping reasoner**: `secrets_blast_radius`. Per-secret IAM-layer blast radius analysis for SecretsManager secrets. For each Secret node in the fact graph, enumerates principals with `secretsmanager:GetSecretValue` permission and emits one finding per (principal, secret) pair. A readable secret may expose sensitive material such as a DB password, API key, or OAuth token, depending on the actual secret contents and runtime context.

**5-check structure:** `principal_has_get_secret_value_permission`, `permission_edge_targets_clean_witness`, `no_scp_blocks_get_secret_value`, `no_boundary_blocks_get_secret_value`, `principal_is_not_service_or_root` (early filter excluding service principals and account-root as structural-not-actionable). Verdicts: SCP/boundary complete-confidence block → `blocked/info`; wildcard resource or partial-confidence constraints → `inconclusive/medium`; all clean → `validated` with severity scaling by principal admin-equivalence (`critical` for admin-equivalent, `high` for non-admin).

**v1 KMS limitation explicitly documented:** the reasoner does NOT check `kms:Decrypt` permission on the secret's encryption key. Secrets encrypted with a customer-managed KMS key the principal can't decrypt will still produce findings because the IAM-layer permission is real even if KMS gates it. KMS layer analysis is deferred to v2 because it requires a separate enforcement layer with its own trust/policy semantics. The reasoner docstring documents this limitation so pentest reviewers can triage findings against known KMS-restricted secrets.

**Fact-layer work (two-tier pattern, larger than priority 3a):**

1. **Parser change** (3-touch, same as priority 3a ECS pattern): `iamscope/parser/permission_policy.py` added `SECRETS_ACTIONS = {"secretsmanager:getsecretvalue"}`, extended `RELEVANT_ACTIONS` union, added `"secretsmanager:getsecretvalue": "secretsmanager:GetSecretValue"` to `canonical_map`. Creates permission edges when the parser sees `secretsmanager:GetSecretValue` actions in IAM policies.

2. **Collector change** (`iamscope/collector/secrets_collector.py`, ~95 lines, new): minimal boto3-based discovery following the exact `lambda_collector.py` pattern. `collect_secrets(session, account_id, regions)` returns a list of `SecretsManagerSecret` nodes via `secretsmanager:list_secrets` pagination. Unlike `lambda_collector`, there are no service edges: secrets don't have an execution-role lateral-movement primitive. Wired into `iamscope/pipeline.py` at both single-account and org-mode flows with a new `collect_secrets: bool = True` config flag and `secrets_regions: list[str] = ["us-east-1"]` field.

**Key lesson: adding a new resource type requires BOTH a parser change (to create permission edges) AND a collector change (to create the target nodes that edges reference).** My initial estimate of "no collector code needed" was wrong. I thought the parser could create Secret nodes implicitly from resource ARNs in IAM policies, but the `scenario_json.py` validator enforces that every edge references a pre-existing node. Lambda, EC2, ECS all have dedicated collectors for this exact reason. The fix was writing a proper `secrets_collector.py` matching the Lambda pattern (~95 lines, minimal surface).

**Tier-2 admin detection tightening (bug fix in shared `admin_detection.py`):** the E2E smoke test exposed a real false-positive in the tier-2 wildcard-hyperedge detection introduced in priority 3b. The original tier-2 logic treated ANY wildcard hyperedge dst as admin-equivalent evidence, which over-triggered on source principals with single-service scoped wildcard grants (e.g., Alice with `Action: "lambda:CreateFunction", Resource: "*"` was classified as admin-equivalent, which is wrong). **The fix:** tier-2 now requires wildcard hyperedges across **≥3 distinct service prefixes** to fire, distinguishing `Action: "*"` (spans sts/iam/lambda/ec2/ecs/secretsmanager = 6+ prefixes) from single-service scoped wildcards (1 prefix). Verified via the then-current full suite; no existing test or golden fixture used tier-2 because unit tests all use explicit `iam:*_permission` edges which are tier-1. The fix benefits all 5 previous reasoners that use shared admin detection, not just secrets_blast_radius.

**Unit tests:** 16 new tests across 8 test classes covering preconditions, validated non-admin/critical admin, wildcard inconclusive, SCP complete/partial, boundary blocks, service principal filter, multiple principals + secrets, determinism. **All 16 passed on first run**, smoothest reasoner debut of the priorities 3 series, because the shared `admin_detection` and `chain_walking` modules from priority 3c-refactor provided well-tested foundations and the priority 3a ECS experience had walked me through the fact-layer pattern.

**Golden fixtures:** 3 new byte-pinned fixtures for secrets_blast_radius (A validated/high non-admin, B blocked/info by SCP, C inconclusive/medium wildcard resource). Reuses fact-graph builders from `tests/test_secrets_blast_radius_reasoner.py` via the same aliased-import pattern as the priority 3b/3c goldens.

**End-to-end smoke test with all 6 reasoners:** the extended moto fixture now creates a real secret via `boto3.client("secretsmanager").create_secret(...)` plus Alice's `secretsmanager:GetSecretValue` policy grant. **9 findings across all 6 reasoners** in a single emit: 1 cross_account_trust validated/high, 1 assume_role_chain validated/high, 2 admin_reachability validated/high, 2 passrole_lambda inconclusive/high, 2 passrole_ecs inconclusive/high, **1 secrets_blast_radius validated/high (Alice correctly classified as non-admin via the tightened tier-2)**.

**Tests: 965 → 984 passing (+19 = 16 unit tests + 3 goldens).** Ruff clean. **Priority 3 is now complete.** All 6 reasoners in the original post-rebuild scope ship with unit tests, golden fixtures, and end-to-end smoke verification.

### v0.2.20: Priority 3c-refactor: shared admin detection + chain walking modules

A pure consolidation pass extracting duplicated logic from the 5 shipping reasoners into 2 new shared modules. **Zero behavior change**, verified by 965/965 tests passing AND the smoke-test `findings_hash` byte-matching the pre-refactor baseline (`2cc99fe793169a65cfc3830c47f08e035e4b05fe0e07e56f2e2052c2dcb51219`) across the 8-finding all-5-reasoner output.

**`iamscope/reasoner/admin_detection.py`** (new, ~80 lines), canonical source of truth for the two-tier admin equivalence detection:

- `find_admin_witness_edge(facts, target_role) -> Edge | None`, returns the edge proving admin equivalence (explicit `*`/`iam:*` permission edge OR wildcard expansion hyperedge dst), or None
- `is_admin_equivalent(facts, target_role) -> bool`, convenience wrapper

Replaces 4 inline copies of the same logic across `passrole_lambda`, `passrole_ecs`, `assume_role_chain`, and `admin_reachability`. Future fixes (e.g., supporting AWS SSO permission sets, detecting `Action: "iam:Put*"` patterns) now land in one place instead of four.

**`iamscope/reasoner/chain_walking.py`** (new, ~120 lines), pure helper functions for walking `sts:AssumeRole` chains in the fact graph:

- `find_node(facts, provider_id) -> Node | None`, linear lookup
- `assumerole_permission_edges_from(facts, src_provider_id) -> tuple[Edge, ...]`, filtered outgoing edges
- `find_admitting_trust_edge(facts, *, current_arn, next_arn) -> Edge | None`, admission logic with account-root principal handling

Replaces 2 inline copies across `assume_role_chain` and `admin_reachability`. The account-root handling rule (a trust edge with `arn:aws:iam::ACCOUNT:root` src admits any same-account principal even if their ARN doesn't appear in the trust policy) lives in one place now, matching AWS IAM's actual semantics.

**Reasoner updates:** all 5 reasoners' private helpers (`_is_admin_equivalent`, `_find_admin_witness_edge`, `_find_node`, `_assumerole_permission_edges_from`, `_find_admitting_trust_edge`) survive as **thin delegates** to the shared modules. Call sites are unchanged. The delegate methods preserve the existing private API (so test files that monkey-patch these for unit tests still work) while the actual logic lives in one place.

**Why this refactor was deferred until now:** with only 2-3 reasoners sharing a helper, premature abstraction was the bigger risk. With 5 reasoners and 4 copies of identical admin detection, the cost of inconsistency (one reasoner getting a fix the others don't) outweighs the cost of the refactor. The 29 byte-pinned golden fixtures locked the behavior so any drift would be caught immediately. None drifted, so the refactor is byte-clean.

**Tests: 965 passing (no count change, pure refactor).** Ruff clean. Smoke-test findings_hash byte-matches baseline. Zero risk of behavioral regression.

### v0.2.19: Priority 3c cleanup: golden fixture parity + smoke test extension

A focused cleanup pass following priority 3c. **10 new byte-pinned golden fixtures** bring all five shipping reasoners to fixture coverage parity:

- **`assume_role_chain` goldens** (3 new fixtures): A (validated 2-hop chain Alice → DevOps → Admin → high), B (SCP blocks Alice→DevOps hop with complete confidence → blocked/info: exercises the per-hop `and_tristate_many` propagation), C (wildcard resource on first hop's permission edge → check 6 UNKNOWN → inconclusive/high, the §4B.6 row 1 false-positive guard for the chain reasoner). Reuses fact-graph builders from `tests/test_assume_role_chain_reasoner.py` via direct import.

- **`admin_reachability` goldens** (3 new fixtures): A (1 reachable admin via 2-hop chain → validated/high, with both Alice and DevOps as starting principals each producing a finding), B (2 reachable admins from Alice via DevOps → AdminRole AND DevOps → ProdAdmin → validated/critical from the count-based severity scaling), C (wildcard resource on the DevOps→Admin hop so BOTH Alice's walk AND DevOps's walk traverse the ambiguous edge → both findings produce inconclusive verdicts via check 3 UNKNOWN). The fixture C iteration exposed a subtle test-design mistake: placing the wildcard on the first hop only made Alice's walk ambiguous while DevOps's walk stayed clean and produced a conflicting `validated` first finding under lex-sorted output ordering. Moving the wildcard to the second hop (which both walks traverse) made both findings inconclusive and the structural assertion held.

- **`passrole_ecs` deferred fixtures** (4 new fixtures, completing the suite): B (target trusts EC2-only, not ecs-tasks → 0 findings emitted, documents the non-trusting-role guard), D (permission boundary with `allowed_actions={s3:*, dynamodb:*}` blocks ecs:RegisterTaskDefinition with `governance_confidence=complete`: exercises the priority-3a per-witness boundary check combined via `and_tristate` → blocked/info), E (SCP with `parse_status=partial` and `governance_confidence=partial` → check 4 UNKNOWN → inconclusive/high), G (`iam:PassedToService=ec2.amazonaws.com` condition on the passrole edge → check 8 FAIL → precondition_only/medium). These complete the ECS golden suite at parity with passrole_lambda's 7-fixture coverage.

**Smoke test extension:** the multi-reasoner moto fixture now includes an EcsTaskRole trusted by `ecs-tasks.amazonaws.com` plus Alice's ECS permissions (`ecs:RegisterTaskDefinition`, `ecs:RunTask`, `iam:PassRole` to EcsTaskRole). End-to-end run produces **8 findings from all 5 reasoners** in a single emit: 1 cross_account_trust validated/high (external trust), 1 assume_role_chain validated/high (Alice → DevOps → AdminRole 2-hop chain), 2 admin_reachability validated/high (Alice and DevOps both reach AdminRole), 2 passrole_lambda inconclusive/high (Alice → LambdaExec wildcard resource, plus AdminRole → LambdaExec from tier-2 admin detection), 2 passrole_ecs inconclusive/high (Alice → EcsTaskRole and AdminRole → EcsTaskRole, both inconclusive from the wildcard resource scope on the ECS permission edges). The byte-stable findings_hash confirms determinism across runs.

**Fixture coverage by reasoner:** cross_account_trust (9), passrole_lambda (7), passrole_ecs (7, at parity), assume_role_chain (3), admin_reachability (3). The two newest reasoners ship with 3 fixtures each (validated, blocked-equivalent, inconclusive false-positive guard); sufficient coverage for the canonical verdict shapes; can grow as needed.

**Tests: 955 → 965 passing (+10).** Ruff clean across the entire codebase. Zero existing test or fixture broken. The 5-reasoner end-to-end smoke test demonstrates that all priority 3 work composes correctly in production.

### v0.2.18: Priority 3c: admin_reachability reasoner

The fifth shipping reasoner: `admin_reachability`. The "blast forward" complement to `assume_role_chain`, where AssumeRoleChain emits one finding per (source, target) chain pair, AdminReachability emits one finding per starting principal listing ALL admin-equivalent roles reachable via any chain of `sts:AssumeRole` hops. The two reasoners are complementary, not redundant: AssumeRoleChain answers "what's the chain from Alice to AdminRole?" with full per-hop SCP/boundary analysis; AdminReachability answers "is Alice effectively an admin?" with a single yes-or-no plus the set of admin endpoints. Better signal-to-noise for the pentest question "who in this org is effectively admin?"

Implementation: BFS reachability walker with cycle detection (visited-set) and depth limit (4 hops, same as AssumeRoleChain). 4-check structure: `source_has_assumerole_permissions`, `reaches_at_least_one_admin`, `at_least_one_reachable_chain_uses_clean_witnesses`, `walk_terminated_within_depth_limit`. No `blocked` verdict, SCP analysis is per-chain, this reasoner is per-principal. Verdicts are only `validated` (clean walk) and `inconclusive` (any wildcard/hyperedge in the walk). Severity: 1 reachable admin → `high`; 2+ admins → `critical` (multiple paths means a single SCP can't break the chain because there's no single chain). Target on the Finding is the lexicographically-first reachable admin (deterministic); the full set of reachable admins lives in `evidence.node_refs`. Reuses the two-tier admin equivalence detection from priority 3b (explicit `*`/`iam:*` edges OR wildcard hyperedge expansions).

Helpers cloned inline from `assume_role_chain.py` rather than extracted to a shared module because abstraction was still premature at this stage. Three reasoners now want admin equivalence detection (`passrole_lambda`, `passrole_ecs`, `assume_role_chain`/`admin_reachability` which already share the same two-tier helper), and two reasoners want BFS chain walking. If a third BFS reasoner is added, the BFS primitives can be promoted to a shared `_chain_walking.py` module then.

16 new tests across 7 test classes: preconditions (2), 2-hop reachability (4), multi-admin reachability (4) including a new `_build_two_admins_facts` helper that constructs Alice → DevOps → AdminRole AND Alice → DevOps → ProdAdmin to verify the severity bump and lex-sorted target selection, no-reachable-admin cases (2), hyperedge-induced inconclusive (1), 3-hop reachability through non-admin intermediates (1), determinism + sorted output (2). Reuses the fact-graph builder helpers from `tests/test_assume_role_chain_reasoner.py` via direct import (`from tests.test_assume_role_chain_reasoner import _user, _role, _trust_edge, ...`).

End-to-end smoke test: 5 reasoners produce 6 findings against the same moto fixture used in priority 3b's smoke (multi-hop chain Alice→DevOps→AdminRole + Lambda chain + external trust). Output: 1 cross_account_trust validated/high, 2 passrole_lambda inconclusive/high, 1 assume_role_chain validated/high, 2 admin_reachability validated/high (one for Alice, one for DevOps, both reach AdminRole). The byte-stable findings_hash confirms determinism across runs.

**Tests: 939 → 955 passing (+16).** Ruff clean across the entire codebase. Zero existing test broken.

### v0.2.17: Priority 3b: AssumeRole chain reasoner + combinator refactor

The fourth shipping reasoner: `assume_role_chain`. Detects multi-hop privilege escalation paths where a principal can transitively reach an admin-equivalent role via 2+ `sts:AssumeRole` hops. The kind of chain that hides in plain sight in big orgs because each individual hop looks innocuous when reviewed in isolation. Implementation is a BFS chain walker with cycle detection (visited-set), depth limit (4 hops), minimum chain length (2 hops, since single-hop is `cross_account_trust`'s territory), and a 6-check structure where per-hop SCP/boundary states combine via the new `and_tristate_many` helper. Severity scaling: validated + admin endpoint + 2-3 hops → `high`; 4+ hops → `critical` (deeper chains harder to spot in audits). 26 new tests across 8 test classes covering preconditions, 2/3/4-hop validated cases, single-hop no-finding (defers to cross_account_trust), non-admin endpoint (check 2 FAIL), missing trust edge (BFS skips), cycle detection (no infinite loop on A→B→A→...), SCP blockers on first/last/partial-confidence hops, wildcard hyperedge ambiguity on a hop, and double-run determinism.

**Combinator refactor:** the `_and_tristate` helper that was added as a `@staticmethod` on `PassRoleEcsReasoner` in priority 3a is now promoted to `iamscope/reasoner/combinators.py` as a module-level function `and_tristate(a, b)`, plus a new `and_tristate_many(states)` for variable-length combinations (used by AssumeRoleChain to combine per-hop check states across the full chain). The ECS reasoner's staticmethod survives as a thin delegate so call sites are unchanged.

**Two-tier admin equivalence detection:** the existing `_is_admin_equivalent` helper in `passrole_lambda` (and the cloned version in `passrole_ecs`) was silently dead code on real collected data. The collector expands `Action: "*"` policies into per-action permission edges pointing to wildcard expansion hyperedges (`__hyperedge__:wildcard_*`), so an admin role in real data has zero `iam:*_permission` self-edges. The explicit-edge check the helpers were doing never matched outside unit tests. Fixed by adding tier 2 to the detection: ANY outgoing permission edge whose dst provider_id starts with `__hyperedge__:wildcard_` is modeled as wildcard-grant evidence. Tier 1 (explicit `*`/`iam:*` edge matching) is preserved so unit tests and golden fixtures continue to pass unchanged. The new `assume_role_chain` reasoner uses the same two-tier helper from day one.

**End-to-end smoke test:** real `iamscope collect` against a moto fixture with all four chain shapes (single-hop external trust, Lambda PassRole chain, multi-hop AssumeRole chain, no ECS chain in this fixture) produced 4 findings: 1 cross_account_trust validated/high, 2 passrole_lambda inconclusive/high (both Alice→LambdaExec and AdminRole→LambdaExec, with the second emerging because the new tier-2 admin detection now correctly recognizes AdminRole as a candidate principal), and 1 assume_role_chain validated/high (Alice → DevOps → AdminRole, 2-hop chain to admin-equivalent endpoint). The byte-stable findings_hash confirms determinism across runs.

**Tests: 913 → 939 passing (+26).** Ruff clean across the entire codebase. Zero existing test or golden fixture broken by the two-tier admin detection extension. The new code path is purely additive.

### v0.2.16: Post-rebuild priorities 1, 2, 3a

A series of post-rebuild deliverables landed without disturbing the S01–S14 byte-lock. Priority 1 was a README rewrite that promoted IAMScope's identity from "AWS Identity Attack Surface Collector" to "AWS identity privilege escalation analyzer that refuses to guess." Invariant #1 became the refuses-to-lie tristate `CheckState`, and the four verdict states (`validated` / `blocked` / `inconclusive` / `precondition_only`) became the spine of the product framing. Priority 2 was a findings-first report renderer (`iamscope/report/findings_renderer.py`, 355 lines) that prepends a pattern-grouped findings section to the existing graph-only report when `findings.json` is present, with full detail on validated and inconclusive verdicts (including a "Why this is inconclusive" callout citing UNKNOWN check reasons by name) and a collapsed one-liner format for blocked and precondition_only findings. The CLI's `iamscope report` subcommand auto-discovers a sibling `findings.json` in the scenario's directory by default, with `--findings PATH` for explicit selection and `--no-auto-findings` for back-compat graph-only output. Priority 3a was the second flagship reasoner: `passrole_ecs`. Cloned from `passrole_lambda` with one substantive structural change; check 1 now combines two actions (`ecs:RegisterTaskDefinition` AND `ecs:RunTask`) via a new `_and_tristate` static helper, and checks 4 and 6 (SCP/boundary blockers) run against both ECS witnesses and combine results. The helper is designed to be reusable for future multi-action reasoners. ECS-action support landed at the fact layer too: `iamscope/parser/permission_policy.py` got a new `ECS_ACTIONS` set in `RELEVANT_ACTIONS` and two new entries in `canonical_map` so the parser produces proper-cased `ecs:RegisterTaskDefinition_permission` / `ecs:RunTask_permission` edge_types instead of silently dropping ECS action statements. **Adding a new reasoner with a new AWS action string is now a 3-touch change** in the parser: action string in `RELEVANT_ACTIONS`, canonical mapping in `canonical_map`, and the reasoner itself. End-to-end smoke test verified via real `main(["collect", ...])` against a moto fixture with both Lambda and ECS chains plus a cross-account external trust: 3 findings emitted (1 validated cross_account_trust + 1 inconclusive passrole_lambda + 1 inconclusive passrole_ecs, the two inconclusives driven by moto's wildcard `Resource: "*"` triggering tristate UNKNOWN per the refuses-to-lie property). 3 byte-pinned golden fixtures shipped for `passrole_ecs` (A validated/critical, C blocked by SCP, F hyperedge inconclusive; the §4B.6 row 1 false-positive guard). Fixtures B/D/E/G deferred as a follow-up. **851 → 913 tests passing (+62 across the 3 priorities)**, ruff clean, scenario.json byte-locks unchanged.

### v0.2.14: The rebuild (Sessions S01–S14)

A 14-session rebuild that transformed IAMScope from a collector-and-graph tool into a full privilege escalation analyzer with pattern reasoners and byte-locked findings output. Every session followed a 6-phase workflow (ground truth, plan, implement, verify, handoff, tarball). Zero open deviations across the entire rebuild.

**Fact-layer fixes (S01–S07):** PR-1 raw_conditions propagation on permission edges; COND-1 six new condition keys (`aws:PrincipalOrgID`, `aws:SourceAccount`, `aws:SourceVpc`, `aws:SourceIp`, `aws:MultiFactorAuthPresent`, `iam:PassedToService`) with `ConditionSet` field extraction; BND-1 permission boundary action intersection (pre-BND-1 the binder always returned `likely_blocking=False`); TYP-1 node type inference + SCP-1 SCP exception downgrade; DIG-1 statement digest wiring via `allow_controls` ControlRef (post-DIG-1 every reasoner can cite the exact source policy bytes); NF-1 NoiseFilter wired into the resolution pipeline; GC-1 closed governance enum (`EdgeConstraint.governance_confidence` validator + ghostgates field rename to `enrichment_confidence` to stop enum leakage).

**Reasoner-layer (S08–S13):** Verdict taxonomy with `Verdict`, `CheckState`, `Check`, `Blocker`, `Assumption`, `Finding` dataclasses and `__post_init__` invariants enforcing the four verdict rules. Reasoner scaffolding with `finding_id()` (deterministic SHA-256), `EvidenceBundle` + `TraceEntry` + `bundle_digest`, `FactGraph` wrapper with the critical tristate `has_action`, `Reasoner` Protocol via `runtime_checkable`, `Registry` with register/list/get/run_all. First reasoner: `cross_account_trust` (6 checks, 9 fixtures, NF/SCP-aware). Findings emitter `findings_json.py` with canonical-JSON serialization mirroring `scenario_json.py` conventions. Flagship reasoner: `passrole_lambda` (8 checks, 8 fixtures, target-first enumeration, `_classify_check_2_witness` helper for has_conditions delegation, fixture F hyperedge false-positive guard as the highest-priority correctness test). Golden findings fixtures: 16 byte-pinned `findings.json` files (9 cross_account_trust + 7 passrole_lambda) with `_REGEN` toggle pattern and 18 verification tests.

**CLI integration (S14):** Wired the entire reasoner stack into `iamscope collect` so real collection runs produce `findings.json` alongside `scenario.json` and `binding_metadata.json`. Three new operator-facing flags: `--no-findings` (back-compat), `--reasoners` (subset selection with up-front validation), `--assume-no-session-policies` (pedantic-reviewer mode via post-processor). PipelineResult extended with 4 structured-data fields for CLI-side FactGraph construction. End-to-end smoke test verified the full S01–S14 stack via real `main(["collect", ...])` invocation: 2 findings emitted (1 cross_account_trust + 1 passrole_lambda), canonical_hash byte-stable across two separate CLI invocations.

**Tests:** 567 baseline → **851 passing** (+284 across 14 sessions). 1 golden re-pin wave (S05). Zero open deviations.

### v0.2.0 (pre-rebuild)

**New features:**
- **Standalone mode** (`--standalone`): Single-account collection without org access
- **OIDC subject claim extraction**: `:sub` patterns in `features.oidc_subject_pattern`
- **OIDC-aware naked trust**: No `:sub` → `BROAD_NAKED`; specific `:sub` → `CONDITIONED`
- **OIDC report section**: Unrestricted vs restricted OIDC trust breakdown
- **Cumulative PassRole budget**: Per-principal tracking (warn 200, cap 500)
- **mypy strict mode**: Passing across all source files

**Bug fixes:**
- `SCPParseResult.statement_index` → `statement_id` attribute error (runtime crash on SCP processing)
- Naked trust high-risk list filter: `"full"`/`"partial"` → `CRITICAL_NAKED`/`BROAD_NAKED` (list was silently empty)

### v0.1.0 (initial)

Initial implementation: org collection, per-account IAM crawl, trust/permission/service edge model, SCP binding, permission boundaries, GhostGates enrichment, report generator, diff engine, validate command, 516 tests.

## License / Use Status

No open-source license has been selected yet. Until a root `LICENSE` file is added by the maintainer, treat this repository as source-available for review only and do not assume redistribution, reuse, or production-use rights.
