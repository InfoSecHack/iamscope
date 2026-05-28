# Benchmark Status

## Current Snapshot

- Latest frozen snapshot: `benchmarks/snapshots/phase0-20260509-env27`
- Snapshot index: `benchmarks/snapshots/INDEX.md`
- Stability snapshot index: `benchmarks/stability-snapshots/INDEX.md`
- Mutation-pair report: `benchmarks/pair-reports/phase0-20260509-env27-mutation-pairs.md` (`.json` sidecar: `benchmarks/pair-reports/phase0-20260509-env27-mutation-pairs.json`)
- Synthetic degradation design/status: `docs/specs/benchmark-degradation-family-design.md`
- Current corpus decision: `hold_review`
- Current corpus totals: `24` evaluated / `24` passed / `0` failed / `0` blocked promotions

This is bounded live AWS benchmark evidence. It does not prove broad IAMScope correctness, broad AWS production readiness, or complete coverage of every IAM/SCP/trust-condition/PassRole/cross-account trust shape. No composite score is claimed.

## Current Cases

| Env | Case ID | Claim | Result |
| --- | --- | --- | --- |
| Env03 | `env03_identity_deny_group_escalation` | Explicit identity Deny blocks group escalation | Pass |
| Env05 | `env05_permission_boundary_blocked_chain` | Permission boundary blocks assume-role/admin chain | Pass |
| Env06 | `env06_validated_admin_reachability` | Clean positive admin reachability validates | Pass |
| Env07 | `env07_validated_non_admin_reachability` | Non-admin AssumeRole structure exists without false admin claim | Pass |
| Env08 | `env08_trust_condition_blocked_admin` | Named-principal MFA trust condition prevents false validated admin | Pass |
| Env09 | `env09_boundary_removed_validated_admin` | Env05 boundary-removed mutation validates admin reachability | Pass |
| Env10 | `env10_trust_condition_removed_validated_admin` | Env08 trust-condition-removed mutation validates admin reachability | Pass |
| Env11 | `env11_broad_trust_condition_blocked_admin` | Broad-looking trust with MFA condition prevents false validated admin | Pass |
| Env12 | `env12_scp_blocked_assumerole` | Resource-scoped SCP evidence prevents false validated admin claim | Pass |
| Env13 | `env13_complete_scp_blocked_assumerole` | Complete SCP Deny blocks otherwise allowed admin reachability | Pass |
| Env14 | `env14_permission_condition_blocked_admin` | Permission-side MFA condition prevents false validated admin | Pass |
| Env15 | `env15_permission_condition_removed_validated_admin` | Env14 permission-condition-removed mutation validates admin reachability | Pass |
| Env16 | `env16_identity_deny_removed_validated_group_escalation` | Env03 identity-Deny-removed mutation validates group escalation | Pass |
| Env17 | `env17_scp_removed_validated_admin` | Env13 SCP-removed mutation validates admin reachability | Pass |
| Env18 | `env18_lambda_passrole_validated` | Lambda PassRole path validates when CreateFunction, PassRole, Lambda trust, and admin target role align | Pass |
| Env19 | `env19_passedtoservice_scoped_away_nonvalidated` | Env18 iam:PassedToService-scoped-away mutation prevents Lambda PassRole validation and becomes precondition-only | Pass |
| Env20 | `env20_ecs_passrole_validated` | ECS PassRole path validates when RegisterTaskDefinition, RunTask, PassRole, ECS task trust, and admin target role align | Pass |
| Env21 | `env21_ecs_passedtoservice_scoped_away_nonvalidated` | Env20 iam:PassedToService-scoped-away mutation prevents ECS PassRole validation and becomes precondition-only | Pass |
| Env22 | `env22_cross_account_validated_admin` | Cross-account AssumeRole and `cross_account_trust` path validates when caller permission, target trust, org evidence, and admin target role align | Pass |
| Env23 | `env23_cross_account_trust_scoped_away_nonvalidated` | Env22 trust-scoped-away mutation preserves Alice permission but removes matching target trust, so Alice has no validated cross-account admin path | Pass |
| Env24 | `env24_s3_resource_policy_allow` | S3 bucket-policy Allow to the exact reader principal emits a scenario-edge-level resource-policy edge | Pass |
| Env25 | `env25_s3_resource_policy_allow_scoped_away_nonvalidated` | Env24 Allow scoped to a decoy principal leaves the reader resource-policy edge absent while preserving the decoy edge | Pass |
| Env26 | `env26_multihop_chain_validated_admin` | Same-account 3-hop AssumeRole chain validates for Alice to admin | Pass |
| Env27 | `env27_multihop_trust_scoped_away_nonvalidated` | Env26 middle-trust-scoped-away mutation preserves the chain shape but prevents Alice-to-admin validation | Pass |

## Mutation Pairs

The frozen corpus now includes ten bounded mutation-style pairs:

- Env03 -> Env16: explicit identity Deny present blocks group escalation; Deny removed validates group escalation.
- Env05 -> Env09: permission boundary present blocks assume-role/admin chain; boundary removed validates admin reachability.
- Env08 -> Env10: trust-side MFA condition present prevents false validated admin; condition removed validates admin reachability.
- Env14 -> Env15: permission-side MFA condition present prevents false validated admin; condition removed validates admin reachability.
- Env13 -> Env17: complete SCP Deny present blocks admin reachability; SCP absent validates the same target IAM path.
- Env18 -> Env19: Lambda PassRole validates when `iam:PassRole` can be used for Lambda; `iam:PassedToService = ec2.amazonaws.com` prevents Lambda PassRole validation and becomes precondition-only.
- Env20 -> Env21: ECS PassRole validates when `iam:PassRole` can be used for ECS tasks; `iam:PassedToService = ec2.amazonaws.com` prevents ECS PassRole validation and becomes precondition-only.
- Env22 -> Env23: cross-account AssumeRole validates when target trust allows Alice; trust scoped to `env23-decoy` removes the matching trust edge and prevents validated cross-account/admin reachability for Alice.
- Env24 -> Env25: S3 resource-policy Allow to the reader emits a scenario-edge-level resource-policy edge; the Allow scoped to `env25-decoy` leaves the reader edge absent while preserving the decoy edge.
- Env26 -> Env27: same-account 3-hop AssumeRole chain validates; middle trust scoped to `env27-decoy` removes the matching hop1-to-hop2 trust edge and prevents validated Alice-to-admin multihop/admin reachability.

These pairs are evidence for the named benchmark paths only. They do not imply a general pairwise mutation scorer or broad correctness across all related IAM policy variants.

The repo-local mutation-pair report at `benchmarks/pair-reports/phase0-20260509-env27-mutation-pairs.md` compares expected vs observed deltas for all ten pairs. It emits no composite score and remains bounded evidence only; it does not claim broad IAMScope correctness.

Env24 and Env25 are scenario-edge-level resource-policy Allow evidence only. They do not claim finding-level resource-policy reachability and do not claim generic resource-policy Deny support.

Env26 and Env27 prove one controlled same-account multihop pair only. They do not prove arbitrary enterprise graph correctness, deeper-chain behavior, or cross-account multihop behavior.

## Synthetic Degradation Benchmarks

Synthetic degradation benchmarks complement the live twenty-four-case corpus and mutation-pair report. They do not run live AWS and are not counted as live corpus cases. Their purpose is to prevent false confidence when required evidence is missing, stripped, partial, or artifact-insufficient.

Implemented DEG cases:

- DEG07: missing required `scenario_json` or `findings_json` artifacts produce `artifact_insufficient` and block promotion.
- DEG01: permission edge present but trust edge missing does not accept false validated admin reachability.
- DEG02: trust edge present but permission edge missing does not accept false validated admin reachability.
- DEG03: group-escalation path evidence present but identity-Deny blocker/check evidence stripped produces `semantic_mismatch` and blocks promotion.
- DEG04: conditioned AssumeRole path evidence present but permission-side MFA condition evidence stripped produces `semantic_mismatch` and blocks promotion.
- DEG05: malformed or partially parsed caller-side policy evidence produces `semantic_mismatch` and blocks promotion.
- DEG06: partial collection with a skipped target account produces `semantic_mismatch` and blocks promotion.

These cases emit no composite score. They are bounded benchmark-framework evidence for missing-evidence honesty; they do not prove broad IAMScope correctness or production readiness.

## Stability Evidence

Repo-local stability snapshots currently cover:

- Env03: `env03_identity_deny_group_escalation`
- Env05: `env05_permission_boundary_blocked_chain`
- Env06: `env06_validated_admin_reachability`
- Env07: `env07_validated_non_admin_reachability`
- Env18: `env18_lambda_passrole_validated`
- Env19: `env19_passedtoservice_scoped_away_nonvalidated`
- Env20: `env20_ecs_passrole_validated`
- Env21: `env21_ecs_passedtoservice_scoped_away_nonvalidated`

Each stability snapshot records three semantically stable live runs for its case. These snapshots preserve stability summaries only; they do not include raw live AWS archives, Terraform state, provider caches, or run artifact directories. They do not prove broad IAMScope stability or production readiness.

## Directly Proven

- IAMScope truthfully detects the Env03 blocked identity-Deny group-escalation path.
- IAMScope validates the Env16 identity-Deny-removed group-escalation mutation.
- IAMScope truthfully detects the Env05 permission-boundary blocked path without validated admin reachability.
- IAMScope validates the Env09 boundary-removed mutation path.
- IAMScope emits validated admin reachability for the narrow positive Env06 path.
- IAMScope preserves the Env07 non-admin AssumeRole path structurally without a false admin claim.
- IAMScope preserves Env08 trust-condition evidence and does not falsely validate admin reachability through that conditioned trust.
- IAMScope validates the Env10 trust-condition-removed mutation path.
- IAMScope avoids shortcutting Env11 broad-looking conditioned trust into validated admin reachability.
- IAMScope collects Env12 SCP evidence, binds it to the target path, and does not falsely validate admin reachability through partial resource-scoped SCP evidence.
- IAMScope emits blocked admin reachability for the Env13 complete-SCP-blocked target path with SCP blocker evidence.
- IAMScope preserves Env14 permission-side condition evidence and does not falsely validate admin reachability through that conditioned permission edge.
- IAMScope validates the Env15 permission-condition-removed mutation path.
- IAMScope validates the Env17 SCP-removed mutation path and shows the target trust edge is not bound to an SCP constraint.
- IAMScope validates the Env18 Lambda PassRole path when `lambda:CreateFunction`, `iam:PassRole`, Lambda service trust, and admin-equivalent target role evidence align.
- IAMScope does not validate the Env19 Lambda PassRole mutation when `iam:PassedToService` is scoped to `ec2.amazonaws.com`; it emits the target path as precondition-only with passed-to-service blocker/check evidence.
- IAMScope validates the Env20 ECS PassRole path when `ecs:RegisterTaskDefinition`, `ecs:RunTask`, `iam:PassRole`, ECS task-service trust, and admin-equivalent target role evidence align.
- IAMScope does not validate the Env21 ECS PassRole mutation when `iam:PassedToService` is scoped to `ec2.amazonaws.com`; it emits the target path as precondition-only with passed-to-service blocker/check evidence.
- IAMScope validates the Env22 cross-account AssumeRole path when caller-side `sts:AssumeRole` permission, target-side exact trust, same-org evidence, and admin-equivalent target role evidence align; both `admin_reachability` and `cross_account_trust` validate without blockers.
- IAMScope does not validate the Env23 cross-account trust mutation when target trust is scoped to a decoy principal rather than Alice.
- IAMScope emits the Env24 scenario-edge-level `s3:GetObject_resource_policy` edge when the S3 bucket policy allows the exact reader principal.
- IAMScope does not emit the Env25 reader `s3:GetObject_resource_policy` edge when the S3 bucket-policy Allow is scoped to `env25-decoy`; the decoy resource-policy edge remains present.
- IAMScope validates the Env26 same-account 3-hop AssumeRole chain from Alice to admin.
- IAMScope does not validate the Env27 same-account multihop mutation when the middle hop trust is scoped to `env27-decoy` rather than `env27-hop1`.
- The synthetic degradation cases DEG01, DEG02, DEG03, DEG04, DEG05, DEG06, and DEG07 make missing, malformed, partial, or artifact-insufficient evidence explicit instead of silently accepting false validated claims or artifact-insufficient runs.

## Strongly Supported

- The current boundary-handling path is coherent for Env05 and the Env09 boundary-removal mutation.
- The current identity-Deny group-escalation path is coherent for Env03 and the Env16 Deny-removal mutation.
- The current trust-condition guardrail is coherent for Env08, Env10, and Env11.
- The current permission-condition guardrail is coherent for Env14 and the Env15 condition-removal mutation.
- The current complete-SCP blocker path is coherent for Env13 and the Env17 SCP-removal mutation.
- The current Lambda PassRole path is coherent for Env18 and the Env19 `iam:PassedToService` scoped-away mutation.
- The current ECS PassRole path is coherent for Env20 and the Env21 `iam:PassedToService` scoped-away mutation.
- The current cross-account trust path is coherent for the narrow positive Env22 case.
- The current S3 resource-policy Allow scenario-edge path is coherent for Env24 and the Env25 principal-scoped-away mutation.
- The current same-account multihop chain path is coherent for Env26 and the Env27 middle-trust-scoped-away mutation.
- The current positive admin path is coherent for Env06, Env09, Env10, Env15, Env17, Env22, and Env26.
- IAMScope can distinguish reachable non-admin structure from admin reachability for Env07.
- IAMScope can demote partial/unsupported SCP evidence instead of overclaiming validated reachability for Env12.

## Only Implied

- Broader deny coverage remains only implied.
- Broader permission-boundary coverage remains only implied.
- Broader positive-path coverage remains only implied.
- Broader non-admin scoring coverage remains only implied.
- Broader trust-condition coverage remains only implied.
- Broader permission-condition coverage remains only implied.
- Broader SCP-family correctness remains only implied.
- Broader PassRole correctness remains only implied.
- Broader cross-account trust correctness remains only implied.
- Broader mutation-pair behavior outside the named report pairs remains only implied; the report is not a general pairwise scorer.
- Broader degradation behavior remains only implied; the implemented DEG cases cover seven narrow synthetic missing-evidence, malformed-evidence, partial-collection, and artifact-insufficient shapes.

## Still Unknown

- False-negative behavior for partially parsed or malformed deny policies.
- Boundary behavior across longer chains or richer policy shapes.
- Cross-account trust negative mutations, external-principal variants, and richer Organizations/SCP interactions.
- Trust-condition behavior across richer multi-condition trust policies and other condition operators.
- Permission-condition behavior across richer condition operators and runtime contexts.
- Whether `assume_role_chain` consistently validates the same positive path families across richer shapes.
- Broader non-admin finding surface decisions.
- SCP behavior for other resource scopes, inherited policies, OU/root attachments, condition forms, exception forms, and multi-account path shapes.
- PassRole behavior for other services, condition operators, target role shapes, and service-side create/update permissions.
- Degradation behavior for richer malformed policy parses, richer skipped-account or partial-collection states, SCP blocker-binding gaps, and permission-boundary blocker-binding gaps.
- Reasoner interactions outside these twenty-four benchmark families.

## Promotion Decision

- Current decision: `hold_review`
- Why: no promotion gates are blocked and artifacts are sufficient, but every case still requires human review by current Phase 0 policy.
- This is a review hold, not a failure signal.

## Regenerate The Latest Twenty-Four-Case Snapshot

```bash
cd <local-iam-scope-repo>
source .venv/bin/activate
bash scripts/materialize_phase0_corpus.sh \
  --env03-archive /tmp/iamscope-benchmark-env03-20260424T025701Z \
  --env05-archive /tmp/iamscope-benchmark-env05-20260424T203548Z \
  --env06-archive /tmp/iamscope-benchmark-env06-20260425T003000Z \
  --env07-archive /tmp/iamscope-benchmark-env07-20260424T222444Z \
  --env08-archive /tmp/iamscope-benchmark-env08-20260425T002835Z \
  --env09-archive /tmp/iamscope-benchmark-env09-20260425T012013Z \
  --env10-archive /tmp/iamscope-benchmark-env10-20260425T015458Z \
  --env11-archive /tmp/iamscope-benchmark-env11-20260425T020442Z \
  --env12-archive /tmp/iamscope-benchmark-env12-20260425T032022Z \
  --env13-archive /tmp/iamscope-benchmark-env13-20260425T035707Z \
  --env14-archive /tmp/iamscope-benchmark-env14-24940398230 \
  --env15-archive /tmp/iamscope-benchmark-env15-24940398230 \
  --env16-archive /tmp/iamscope-benchmark-env16-24940398230 \
  --env17-archive /tmp/iamscope-benchmark-env17-24940398230 \
  --env18-archive /tmp/iamscope-benchmark-env18-24940398230 \
  --env19-archive /tmp/iamscope-benchmark-env19-24940398230 \
  --env20-archive /tmp/iamscope-benchmark-env20-24940398230 \
  --env21-archive /tmp/iamscope-benchmark-env21-24940398230 \
  --env22-archive /tmp/iamscope-benchmark-env22-20260505T210729Z \
  --env23-archive /tmp/iamscope-benchmark-env23-20260506T020925Z \
  --env24-archive /tmp/iamscope-benchmark-env24-20260508T151202Z \
  --env25-archive /tmp/iamscope-benchmark-env25-20260508T210637Z \
  --env26-archive /tmp/iamscope-benchmark-env26-20260509T012216Z \
  --env27-archive /tmp/iamscope-benchmark-env27-20260509T212354Z \
  --out-root /tmp/iamscope-phase0-runs-all24-env27 \
  --corpus-out /tmp/iamscope-phase0-corpus-all24-env27

bash scripts/freeze_phase0_benchmark_snapshot.sh \
  --runs-dir /tmp/iamscope-phase0-runs-all24-env27 \
  --corpus-dir /tmp/iamscope-phase0-corpus-all24-env27 \
  --snapshot-id phase0-20260509-env27 \
  --out-root benchmarks/snapshots

bash scripts/update_benchmark_snapshot_index.sh \
  --snapshots-dir benchmarks/snapshots \
  --out benchmarks/snapshots/INDEX.md
```

## Inspect The Snapshot

```bash
cd <local-iam-scope-repo>
sed -n '1,220p' benchmarks/snapshots/phase0-20260509-env27/README.md
sed -n '1,260p' benchmarks/snapshots/phase0-20260509-env27/corpus/corpus_report.md
sed -n '/## phase0-20260509-env27/,$p' benchmarks/snapshots/INDEX.md
sed -n '1,220p' benchmarks/stability-snapshots/INDEX.md
```

## Important Warning

- This corpus does **not** prove broad IAMScope correctness.
- It does **not** prove production readiness.
- It shows twenty-four narrow, controlled live AWS benchmark cases that are currently coherent enough for human review and further targeted testing.
- The synthetic degradation benchmarks are separate missing-evidence guardrails and are not live AWS corpus cases.
