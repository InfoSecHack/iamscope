# Deny Audit Report — Session 6b

**Date:** 2026-04-14
**Audit method:** Per-reasoner full module read, walk-through against
`docs/deny-evaluation-spec.md` Sections 1-7 (AWS deny semantics) and
Section 8 (iamscope data flow architecture). Cross-reference between
spec "what AWS does" and data flow "what iamscope preserves" per
finding.
**Spec reference:** `docs/deny-evaluation-spec.md` (Session 6a,
1059 lines, 8 sections)
**Reasoners audited:** 8 (secrets_blast_radius, s3_bucket_takeover,
passrole_lambda, passrole_ecs, iam_group_membership_escalation,
cross_account_trust, assume_role_chain, admin_reachability)
**Total findings:** 5 cross-cutting + 8 reasoner-specific = 13

## Finding severity distribution

| Severity | Cross-cutting | Reasoner-specific | Total |
|----------|--------------|-------------------|-------|
| Critical | 1 (CC-1) | 0 | 1 |
| High | 1 (CC-2) | 1 (AR-1) | 2 |
| Medium | 3 (CC-3, CC-4, CC-5) | 3 (CAT-1, CAT-2, ARC-1) | 6 |
| Low | 0 | 5 (S3-1, PRL-1, PRE-1, SBR-1, SBR-2) | 5 |
| **Total** | **5** | **8** | **13** |

---

## Executive summary

**Headline finding: AR-1.** `admin_reachability` and
`assume_role_chain` produce contradictory verdicts for the same
blocked path. `admin_reachability` BFS-walks through a hop that
`assume_role_chain` marks `blocked` by SCP, emitting a `validated`
finding that claims the principal can reach admin. An operator
reading both findings sees one saying "yes" and one saying "no"
with no signal indicating which is correct. This is the only High
severity reasoner-specific finding in the audit.

**Cross-cutting findings:** CC-1 (Critical) and CC-2 (High) are
parser-layer gaps affecting all 8 reasoners. Identity-policy Deny
and trust-policy Deny statements are discarded at parse time
(`parser/permission_policy.py:12`, `parser/trust_policy.py:169`).
No Constraint objects are created. No EdgeConstraint bindings
reach any reasoner. These are the highest-impact gaps because they
affect every finding iamscope produces — any principal with both an
Allow and a Deny on the same action will have the Allow modeled as
an edge and the Deny invisible.

**Medium-severity findings** cluster around two themes: SCP/boundary
binding architecture (CAT-1 and ARC-1 share a root cause where
reasoner checks query the wrong edge type for the binding they
need) and cross-account source-side evaluation (CAT-2, where the
reasoner evaluates only the target side of a cross-account trust).

**Low-severity findings** are documented scope boundaries or
over-conservative behavior, not incorrect behavior. Session 6c
should evaluate each: expand the scope boundary (make iamscope
handle the case) or accept it (document the limitation and move
on). Expanding scope and fixing bugs are different work.

**Session 6c sequencing** at the end of this report recommends 6
phases, starting with parser-layer foundations (CC-1, CC-2) and
the AR-1 headline fix, proceeding through architectural SCP/boundary
fixes, and ending with Low-severity scope-boundary evaluations.

---

## Audit method

Each reasoner was read in full (not just check methods). For each
spec section 1-7, the auditor asked: "Could this reasoner produce
a wrong verdict because of how AWS handles X?" Cross-reference with
Section 8's data flow determined whether the reasoner had the data
needed to handle X correctly.

**Severity rubric:**
- Critical: wrong verdict for a common pattern
- High: wrong verdict for an uncommon-but-realistic pattern
- Medium: wrong verdict for an edge case or architectural gap
- Low: wrong verdict for a theoretical case or over-conservative
  behavior

**Direction field:** false positive (validated when AWS would deny),
false negative (blocked/inconclusive when AWS would allow), or
conservative (defensible but over-cautious).

**Scope boundary note:** Low-severity findings often reflect
documented scope boundaries (e.g., "this reasoner doesn't model X
variant") rather than incorrect behavior. Session 6c should evaluate
whether to expand scope or accept the boundary, which is different
work from "fix this bug."

---

## Cross-cutting findings

### CC-1: Identity-policy Deny statements discarded at parse time

- **Severity:** Critical
- **Direction:** False positive (validated when AWS would deny)
- **Spec reference:** Section 2 (explicit deny in identity policies),
  Section 6 row 4 (same principal, Allow in policy A + Deny in
  policy B → Explicit Deny)
- **Code reference:** `parser/permission_policy.py:12` — "Only
  processes Allow statements (Deny doesn't create permission edges)"
- **Affects reasoners:** All 8. Six reasoners (passrole_lambda,
  passrole_ecs, s3_bucket_takeover, secrets_blast_radius,
  iam_group_membership_escalation, assume_role_chain) directly
  evaluate permission edges and are affected. cross_account_trust
  uses permission edges in some multi-check patterns.
  admin_reachability is affected transitively through chain reasoners.
- **Scenario:** IAM user has managed policy granting
  `Allow iam:PassRole *` and inline policy with
  `Deny iam:PassRole arn:aws:iam::111:role/Prod*`. AWS denies
  PassRole to Prod roles. iamscope creates a permission edge from
  the Allow, produces a validated passrole_lambda finding for a Prod
  role target.
- **Why it fails:** The parser iterates statements and skips all
  `Effect: Deny`. No `Constraint` object is created. No
  `EdgeConstraint` binding can be generated by the resolver. The
  reasoner's `_check_scp_blockers` / `_check_boundary_blockers`
  pattern queries `facts.bindings_for_edge()` which returns only
  SCP and boundary bindings — there is no "identity-policy-deny
  binding" concept in the data flow.
- **Suggested fix scope (Session 6c):** Three-layer change:
  (1) parser preserves identity-policy Deny as `Constraint` objects
  with a new constraint_type (e.g., `"IDENTITY_DENY"`), (2) a new
  resolver binds identity-deny constraints to permission edges by
  action+resource matching, (3) reasoners gain a
  `_check_identity_deny_blockers` method that follows the same
  `bindings_for_edge` → `likely_blocking` pattern.

### CC-2: Trust-policy Deny statements discarded at parse time

- **Severity:** High
- **Direction:** False positive (validated when AWS would deny)
- **Spec reference:** Section 7 (Deny in trust policies — "A Deny
  statement in a trust policy prevents the denied principal from
  assuming the role"), Section 8 (trust parser skips Deny)
- **Code reference:** `parser/trust_policy.py:169-171` —
  `if effect != "Allow": continue`. Documented at line 11: "Deny
  statements are skipped — they restrict trust but don't create
  edges."
- **Affects reasoners:** cross_account_trust (directly evaluates
  trust edges), assume_role_chain (per-hop trust evaluation),
  admin_reachability (transitively via chain reasoners)
- **Scenario:** Role trust policy has
  `Allow arn:aws:iam::222:root` (broad account trust) +
  `Deny arn:aws:iam::222:role/Restricted` (carve-out for one
  specific role). AWS denies AssumeRole from the Restricted role.
  iamscope creates a trust edge from the Allow for all 222
  principals including Restricted, produces a validated
  cross_account_trust finding for the Restricted role.
- **Why it fails:** The parser discards the Deny statement. The
  trust edge for Restricted is created from the Allow (account root
  grant covers all principals in 222). No constraint reaches the
  resolver or reasoner.
- **Rated High rather than Critical:** Trust-policy Deny is less
  common than identity-policy Deny because trust policies typically
  have only Allow statements (the principal-defining function rarely
  needs subtractive carve-outs). Deny carve-outs in trust policies
  do appear in security-conscious organizations using break-glass
  exclusions, multi-tenant environments, or specific principal
  restrictions, but the pattern is uncommon enough that the
  false-positive rate is bounded.
- **Suggested fix scope (Session 6c):** Similar three-layer change
  to CC-1. Parser preserves trust-policy Deny as `Constraint`
  objects. Resolver matches trust-deny constraints against trust
  edges by principal matching. Reasoners gain a trust-deny check.
  Alternatively, the parser could avoid creating the trust edge
  entirely when a Deny matches the same principal — a parser-only
  fix that's simpler but less general.

### CC-3: SCP condition evaluation absent (beyond exception-principal patterns)

- **Severity:** Medium
- **Direction:** Both — can produce false positive (claims blocked
  when actually allowed; iamscope's verdict reads as blocked for a
  path that AWS would allow) or false negative (claims validated
  when actually denied; iamscope's verdict reads as validated for a
  path AWS would block by SCP condition). Per spec Section 5, the
  false-negative case is the more dangerous direction because
  validated overstates iamscope's epistemic state.
- **Spec reference:** Section 5 (conditional denies, missing-key
  truth table, IfExists interaction)
- **Code reference:** `resolver/scp_binder.py:58-106` — matches
  deny_actions/deny_not_actions and exception_principal_patterns.
  General conditions on SCP Deny statements are not evaluated.
  `parser/scp_policy.py` extracts exception patterns from specific
  condition keys (`aws:PrincipalArn`, `aws:PrincipalOrgID`,
  `aws:PrincipalAccount`) but drops all other condition keys.
- **Affects reasoners:** All 7 reasoners that check SCP blockers.
- **Scenario (false negative):** SCP has
  `Deny sts:AssumeRole` with
  `Condition: StringNotEquals: aws:RequestedRegion: us-east-1`. In
  us-east-1, the deny doesn't fire — AssumeRole is allowed. In
  eu-west-1, the deny fires. iamscope's scp_binder binds the SCP
  to the trust edge as `likely_blocking=True` regardless of region.
  The cross_account_trust finding for a us-east-1 trust is
  incorrectly marked `blocked`.
- **Scenario (false positive):** SCP has
  `Deny iam:PassRole` with
  `Condition: StringEqualsIfExists: iam:PassedToService: ec2.amazonaws.com`.
  For PassRole to a Lambda function, the condition key is present
  and equals `lambda.amazonaws.com` (not `ec2.amazonaws.com`), so
  the deny doesn't fire. iamscope's scp_binder doesn't evaluate
  this condition — it sees `Deny iam:PassRole` and binds as
  blocking. The passrole_lambda finding is incorrectly marked
  `blocked`. However, this is a conservative-deny error (under spec
  Section 5 guidance), which is the less-dangerous direction.
- **Suggested fix scope (Session 6c):** Condition evaluation on SCP
  Deny statements in the resolver. Start with the most common
  condition patterns per spec Section 5's recommendation. Full
  condition evaluation is a multi-session effort; a pragmatic v1
  would handle `aws:RequestedRegion`, `iam:PassedToService`, and
  the IfExists variants.

### CC-4: SCP Allow-ceiling not modeled

- **Severity:** Medium
- **Direction:** False positive (validated when AWS would implicitly
  deny via SCP ceiling)
- **Spec reference:** Section 1 step 2 ("at least one SCP at every
  level of the OU hierarchy must Allow the action"), Section 6 row 2
  (SCP missing Allow → implicit deny)
- **Code reference:** `parser/scp_policy.py:138` —
  `if effect != "Deny": continue` (skips SCP Allow statements).
  `resolver/scp_binder.py` only binds SCP Deny actions, not SCP
  Allow-ceiling constraints.
- **Affects reasoners:** All 7 reasoners that check SCP blockers.
- **Scenario:** Organization has a restrictive SCP with `Allow` only
  for `s3:*` and `ec2:*` (no `iam:*` or `sts:*`). IAM user has
  identity-policy Allow for `iam:PassRole`. AWS implicitly denies
  PassRole because no SCP allows `iam:*`. iamscope doesn't model
  the SCP ceiling — it only sees that no SCP Deny matches
  `iam:PassRole` — so the finding validates.
- **Rated Medium rather than Critical:** Most production SCPs use
  `"Effect": "Allow", "Action": "*", "Resource": "*"` as their
  Allow statement (the AWS default FullAWSAccess SCP), which allows
  everything. Restrictive SCP allow-lists are uncommon outside
  highly-regulated environments.
- **Suggested fix scope (Session 6c):** Parser preserves SCP Allow
  statements. Resolver checks whether the edge's action is in any
  applicable SCP's Allow set (intersection across OU hierarchy). If
  no SCP allows the action, bind as `likely_blocking=True`. This is
  the "SCP as ceiling" model from spec Section 1 step 2.

### CC-5: Permission boundary Resource-level scoping and conditions not evaluated

- **Severity:** Low
- **Direction:** Both (false positive if boundary's Resource field
  would exclude the finding's target resource but iamscope treats
  the boundary as allowing; false negative if boundary's Resource
  field would include the target but iamscope incorrectly blocks)
- **Spec reference:** Section 2 (permission boundary deny
  semantics), Section 8 (resolver/permission_boundary.py)
- **Code reference:** `resolver/permission_boundary.py:162-230` —
  evaluates action-in-allowed-set only, does not match Resource
  fields or evaluate conditions.
- **Affects reasoners:** All 6 reasoners that check boundary
  blockers (all except cross_account_trust and admin_reachability).
- **Scenario:** Boundary allows `iam:PassRole` with
  `Resource: arn:aws:iam::111:role/Lambda*` (only allow PassRole to
  roles starting with "Lambda"). IAM user tries to PassRole to
  `arn:aws:iam::111:role/ProdAdmin`. Boundary should block (Resource
  doesn't match). iamscope's boundary evaluator sees
  `iam:PassRole` in the allowed action set →
  `likely_blocking=False`. Finding validates.
- **Rated Low:** Most permission boundaries in production use
  `Action: *` with `Resource: *` or broad action sets without
  Resource-level scoping. Resource-scoped boundaries exist but are
  uncommon in the patterns iamscope evaluates.
- **Suggested fix scope (Session 6c):** Boundary evaluator matches
  Resource field against the edge's target ARN, similar to how
  scp_binder matches actions. Also evaluate conditions on boundary
  statements.

---

## Patterns observed across reasoners

**SCP/boundary bindings live on specific edge types per the resolver
layer's design.** SCPs are bound to trust edges via
`pipeline.py:632-636` (`trust_edges = [e for e in all_edges if
e.edge_type.endswith(f"_{EDGE_LAYER_TRUST}")]`). Boundaries are
bound to permission edges via `resolver/permission_boundary.py`.
Reasoner checks may query the wrong edge type for the binding they
need:

- **CAT-1:** `cross_account_trust` check 4 walks bindings on trust
  edges (correct for SCP) but no boundary check exists, missing the
  boundary on the source principal's `sts:AssumeRole` permission
  edge.
- **ARC-1:** `assume_role_chain` per-hop SCP check queries the
  permission edge for SCP bindings, but SCPs are bound to trust
  edges in the pipeline.

A unified Session 6c fix might bind both constraint types to both
edge types, or each reasoner check could query both edge types.
The finding-by-finding fixes documented in CAT-1 and ARC-1 are
tactical; an architectural fix would address both at once.

---

## Per-reasoner findings

### Reasoner: secrets_blast_radius

**Module:** `iamscope/reasoner/secrets_blast_radius.py`
**Lines:** 1033
**What it produces:** One finding per (principal, secret) pair where
the principal has a `secretsmanager:GetSecretValue` permission edge
to the secret. Verdicts: validated, blocked, inconclusive,
precondition_only.

**Check sequence:**

| Check | Name | What it evaluates |
|-------|------|-------------------|
| 5 (early) | `principal_is_not_service_or_root` | Principal type filter |
| 1 | `principal_has_get_secret_value_permission` | By construction PASS |
| 2 | `permission_edge_targets_clean_witness` | Wildcard/hyperedge classification |
| 3 | `no_scp_blocks_get_secret_value` | SCP EdgeConstraint bindings |
| 4 | `no_boundary_blocks_get_secret_value` | Boundary EdgeConstraint bindings |
| 6 | `kms_key_policy_allows_decrypt_for_principal` | KMS key policy evaluation |

#### Finding SBR-1: KMS evaluator over-conservative on conditional denies

- **Severity:** Low
- **Direction:** False negative (claims inconclusive when iamscope
  could have evaluated the specific condition pattern)
- **Spec reference:** Section 5 (conditional denies —
  recommendation is conservative-deny when conditions CAN'T be
  statically evaluated, not for ALL conditions)
- **Code reference:** `secrets_blast_radius.py:269-274`
- **Scenario:** KMS key policy has Deny with
  `Condition: StringNotEquals: kms:ViaService: secretsmanager.us-east-1.amazonaws.com`.
  The deny fires only when NOT accessed via Secrets Manager —
  meaning for our use case (GetSecretValue → Decrypt via Secrets
  Manager), the deny does NOT fire. iamscope returns UNKNOWN,
  producing inconclusive. The correct answer for this specific
  condition pattern would be PASS.
- **Why it fails:** The evaluator returns UNKNOWN as a blanket
  fallback for any Condition block, including conditions iamscope
  could evaluate. Spec Section 5 supports conservative UNKNOWN for
  conditions iamscope CAN'T evaluate; this is over-application.
- **Suggested fix scope (Session 6c):** Add pattern-specific
  condition evaluation for the most common KMS Deny conditions
  (`kms:ViaService`, `kms:CallerAccount`). Full condition evaluation
  is multi-session per CC-3; a pragmatic v1 handles 3-5 known
  patterns and falls back to UNKNOWN for the rest.

#### Finding SBR-2: KMS evaluator does not handle KMS Grants

- **Severity:** Low
- **Direction:** False negative (claims precondition_only or
  inconclusive when a KMS Grant might allow decrypt)
- **Spec reference:** Section 7 (edge cases — services iamscope
  doesn't fully model)
- **Code reference:** `secrets_blast_radius.py:69-70` — "the
  reasoner does NOT handle KMS grants (kms:CreateGrant)"
- **Scenario:** KMS key policy denies the principal (check 6 → FAIL
  → precondition_only), but a KMS Grant created by the key owner
  grants the principal `kms:Decrypt` on the same key. AWS would
  allow the decrypt via the grant.
- **Why it's Low:** KMS Grants are uncommon in the Secrets Manager
  context. Most secret encryption uses the AWS-managed default key
  or customer-managed keys with policy-based grants.
- **Suggested fix scope:** Deferred beyond Session 6c. Modeling KMS
  Grants requires collecting Grant data from `kms:ListGrants`.

**Cross-cutting findings affecting this reasoner:**
- CC-1 (identity-policy Deny): no reasoner-specific manifestation —
  gap follows the standard pattern documented in CC-1.
- CC-3 (SCP condition evaluation): scp_binder evaluates SCP bindings
  on the GetSecretValue edge; conditions on those bindings would
  suffer the CC-3 gap.
- CC-4 (SCP Allow-ceiling): if no SCP allows `secretsmanager:*` the
  finding still validates per CC-4.
- CC-5 (boundary Resource scoping): boundary checks for
  GetSecretValue would suffer the CC-5 gap.

---

### Reasoner: s3_bucket_takeover

**Module:** `iamscope/reasoner/s3_bucket_takeover.py`
**Lines:** 548
**What it produces:** One finding per (principal, bucket) pair where
the principal has `s3:PutBucketPolicy`. Verdicts: validated, blocked,
inconclusive.

**Check sequence:**

| Check | Name | What it evaluates |
|-------|------|-------------------|
| 1 | `principal_has_put_bucket_policy_permission` | By construction PASS |
| 2 | `witness_edge_is_clean` | Wildcard/hyperedge classification |
| 3 | `no_scp_blocks_put_bucket_policy` | SCP EdgeConstraint bindings |
| 4 | `no_boundary_blocks_put_bucket_policy` | Boundary EdgeConstraint bindings |
| 5 | `principal_is_actionable` | Filters service principals and root |

#### Finding S3-1: No current-bucket-policy evaluation

- **Severity:** Low
- **Direction:** False positive (deliberate design choice)
- **Spec reference:** Section 6 (cross-policy interaction —
  resource-based policy Deny)
- **Code reference:** `s3_bucket_takeover.py:10-14` — "The reasoner
  does NOT evaluate the CURRENT bucket policy content — it only
  cares that the principal CAN rewrite it."
- **Scenario:** Bucket has a Deny policy blocking all PutObject/
  GetObject from the attacker's account. The attacker has
  PutBucketPolicy permission. iamscope validates the finding because
  the attacker can rewrite the policy — which IS the correct
  assessment: the PutBucketPolicy permission itself IS the attack.
- **Why it's Low:** This is documented as a deliberate design
  choice. PutBucketPolicy is the attack; the current policy is
  irrelevant once the attacker can overwrite it.
- **Suggested fix scope:** Not Session 6c scope.

**Cross-cutting findings affecting this reasoner:**
- CC-1 (identity-policy Deny): A Deny on `s3:PutBucketPolicy` in
  the principal's identity policy would block the takeover; not
  modeled.
- CC-3 (SCP condition evaluation): SCP bindings on the
  PutBucketPolicy edge would suffer the CC-3 gap.
- CC-4 (SCP Allow-ceiling): If no SCP allows `s3:*`, the finding
  still validates per CC-4.
- CC-5 (boundary Resource scoping): Boundary checks for
  PutBucketPolicy would suffer the CC-5 gap.

---

### Reasoner: passrole_lambda

**Module:** `iamscope/reasoner/passrole_lambda.py`
**Lines:** 1196
**What it produces:** One finding per (source_principal, target_role)
pair where the principal has `lambda:CreateFunction` +
`iam:PassRole` targeting a role that trusts
`lambda.amazonaws.com`. Verdicts: validated, blocked, inconclusive,
precondition_only.

**Check sequence (8 checks):**

| Check | Name | What it evaluates |
|-------|------|-------------------|
| 1 | `source_has_lambda_create_function` | `FactGraph.has_action()` tristate |
| 2 | `source_has_passrole_to_target` | PassRole edge to specific target |
| 3 | `target_trusts_lambda_service` | Trust edge from lambda.amazonaws.com |
| 4 | `no_scp_blocks_lambda_create_function` | SCP bindings on CreateFunction edge |
| 5 | `no_scp_blocks_passrole` | SCP bindings on PassRole edge |
| 6 | `no_boundary_blocks_lambda_create_function` | Boundary bindings on CreateFunction edge |
| 7 | `no_boundary_blocks_passrole` | Boundary bindings on PassRole edge |
| 8 | `passrole_condition_scoped_to_lambda_or_absent` | `iam:PassedToService` condition evaluation |

#### Finding PRL-1: Check 8 evaluates only `iam:PassedToService`, not other PassRole conditions

- **Severity:** Low
- **Direction:** False positive (masked by `has_conditions` tristate
  in most cases)
- **Spec reference:** Section 5 (conditional denies — conditions on
  Allow statements)
- **Code reference:** `passrole_lambda.py:960-1043` —
  `_evaluate_passrole_conditions()` walks `raw_conditions` looking
  exclusively for `iam:PassedToService`.
- **Scenario:** PassRole Allow has
  `Condition: StringEquals: aws:RequestedRegion: eu-west-1`. The
  Lambda function is created in us-east-1. AWS denies the PassRole
  because the region condition doesn't match. iamscope's check 8
  sees no `iam:PassedToService` key → returns PASS (unrestricted).
- **Why it's Low:** The `has_conditions=True` flag on the permission
  edge already causes `FactGraph.has_action()` to return UNKNOWN for
  conditioned edges, which propagates to check 2 as UNKNOWN →
  verdict inconclusive. The false-positive scenario requires
  `has_conditions=False` on an edge that actually has conditions.
- **Suggested fix scope (Session 6c):** Low priority. Check 8 could
  evaluate 3-5 common condition keys beyond `iam:PassedToService`.
  Also recommend: separately audit `parser/permission_policy.py` to
  verify `has_conditions` is set correctly for ALL conditioned edges.
  PRL-1 only manifests as false positive if the parser fails to flag
  `has_conditions` on a conditioned PassRole edge — which would
  itself be a parser bug worth investigating.

**Cross-cutting findings affecting this reasoner:**
- CC-1 (identity-policy Deny): A Deny on `lambda:CreateFunction` or
  `iam:PassRole` would block the chain; not modeled. PassRole Deny
  is a common guardrail pattern in production — this is the highest-
  impact CC-1 manifestation.
- CC-2 (trust-policy Deny): A Deny in the target role's trust policy
  excluding the principal; not modeled.
- CC-3 (SCP condition evaluation): SCP bindings on CreateFunction
  and PassRole edges suffer the CC-3 gap.
- CC-4 (SCP Allow-ceiling): If no SCP allows
  `lambda:CreateFunction` or `iam:PassRole`, the finding validates
  per CC-4.
- CC-5 (boundary Resource scoping): Boundary checks for PassRole
  and CreateFunction suffer the CC-5 gap.

---

### Reasoner: passrole_ecs

**Module:** `iamscope/reasoner/passrole_ecs.py`
**Lines:** 1314
**What it produces:** One finding per (source_principal, target_role)
pair where the principal has `ecs:RegisterTaskDefinition` +
`ecs:RunTask` + `iam:PassRole` targeting a role that trusts
`ecs-tasks.amazonaws.com`. Verdicts: validated, blocked,
inconclusive, precondition_only.

**Check sequence (8 checks — structurally identical to
passrole_lambda):**

| Check | Name | What it evaluates |
|-------|------|-------------------|
| 1 | `source_has_ecs_create_and_run_permissions` | `has_action()` for RegisterTaskDefinition + RunTask |
| 2 | `source_has_passrole_to_target` | PassRole edge to specific target |
| 3 | `target_trusts_ecs_tasks_service` | Trust edge from ecs-tasks.amazonaws.com |
| 4 | `no_scp_blocks_ecs_create_or_run` | SCP bindings on ECS edges |
| 5 | `no_scp_blocks_passrole` | SCP bindings on PassRole edge |
| 6 | `no_boundary_blocks_ecs_create_or_run` | Boundary bindings on ECS edges |
| 7 | `no_boundary_blocks_passrole` | Boundary bindings on PassRole edge |
| 8 | `passrole_condition_scoped_to_ecs_or_absent` | `iam:PassedToService` condition evaluation |

#### Finding PRE-1: Check 1 requires BOTH RegisterTaskDefinition AND RunTask, but checks SCP/boundary on a single combined edge

- **Severity:** Low
- **Direction:** Conservative (correct for the modeled pattern)
- **Spec reference:** Section 2 (explicit deny — per-action
  granularity)
- **Code reference:** `passrole_ecs.py:1161` — check 4
  `no_scp_blocks_ecs_create_or_run` checks SCP on the ECS witness
  edge, but the pattern requires TWO actions.
- **Scenario:** SCP denies `ecs:RegisterTaskDefinition` but allows
  `ecs:RunTask`. The attacker can't register a new task definition
  but could run an existing one targeting the role.
- **Why it's Low:** The reasoner's pattern specifically requires
  "create AND run." The "run existing task definition" variant is a
  different attack pattern not modeled by this reasoner.
- **Suggested fix scope:** Not Session 6c scope. A separate
  "run-existing-task-definition" reasoner would address this variant.

**Cross-cutting findings affecting this reasoner:**
- CC-1 (identity-policy Deny): Deny on `ecs:RegisterTaskDefinition`,
  `ecs:RunTask`, or `iam:PassRole` would block; not modeled.
- CC-2 (trust-policy Deny): A Deny in the target role's trust policy
  excluding the principal; not modeled.
- CC-3 (SCP condition evaluation): SCP bindings on ECS and PassRole
  edges suffer the CC-3 gap.
- CC-4 (SCP Allow-ceiling): If no SCP allows the ECS actions, the
  finding validates per CC-4.
- CC-5 (boundary Resource scoping): Same as passrole_lambda.

---

### Reasoner: iam_group_membership_escalation

**Module:** `iamscope/reasoner/iam_group_membership_escalation.py`
**Lines:** 564
**What it produces:** One finding per (user, admin-group) pair where
the user has `iam:AddUserToGroup` targeting an admin-equivalent
group. Verdicts: validated, blocked, inconclusive.

**Check sequence:**

| Check | Name | What it evaluates |
|-------|------|-------------------|
| 1 | `source_has_add_user_to_group_permission` | By construction PASS |
| 2 | `witness_edge_is_clean` | Wildcard/hyperedge classification |
| 3 | `no_scp_blocks_add_user_to_group` | SCP EdgeConstraint bindings |
| 4 | `no_boundary_blocks_add_user_to_group` | Boundary EdgeConstraint bindings |
| 5 | `target_group_has_admin_equivalent_permissions` | Admin equivalence check |

No reasoner-specific findings. The reasoner follows the standard
5-check template with the same verdict mapping as s3_bucket_takeover.

**Cross-cutting findings affecting this reasoner:**
- CC-1 (identity-policy Deny): A Deny on `iam:AddUserToGroup` in
  the user's identity policy would block; not modeled. Org security
  teams sometimes deny `iam:Add*` or `iam:Create*` as guardrails.
- CC-3 (SCP condition evaluation): SCP bindings on AddUserToGroup
  edge suffer the CC-3 gap.
- CC-4 (SCP Allow-ceiling): If no SCP allows
  `iam:AddUserToGroup`, the finding still validates per CC-4.
- CC-5 (boundary Resource scoping): Boundary checks suffer the
  CC-5 gap.

---

### Reasoner: cross_account_trust

**Module:** `iamscope/reasoner/cross_account_trust.py`
**Lines:** 745
**What it produces:** One finding per cross-account trust edge with
a risky `naked_trust` classification. Verdicts: validated, blocked,
inconclusive. Never precondition_only.

**Check sequence (6 checks):**

| Check | Name | What it evaluates |
|-------|------|-------------------|
| 1 | `edge_is_cross_account` | Early exit if not cross-account |
| 2 | `naked_trust_is_risky` | Early exit if INTRA_ACCOUNT or CONDITIONED |
| 3 | `source_principal_resolvable` | Source node exists in graph |
| 4 | `no_scp_blocks_sts_assumerole` | SCP bindings on the trust edge |
| 5 | `trust_conditions_confirm_classification` | Consistency safety net |
| 6 | `target_role_exists_in_graph` | Target role node exists |

#### Finding CAT-1: No permission boundary check

- **Severity:** Medium
- **Direction:** False positive (validated when a permission boundary
  on the source principal would deny `sts:AssumeRole`)
- **Spec reference:** Section 2 (permission boundary deny
  semantics), Section 6 row 5 (boundary missing action → implicit
  deny)
- **Code reference:** `cross_account_trust.py:370-437` — check 4
  walks bindings for SCP-type constraints only. Lines 371-373
  comment: "In V1, all bindings on trust edges are SCPs (permission
  boundaries don't bind to trust edges)." The comment is factually
  correct about the current data flow, but the semantic question is
  whether the reasoner should also check the source principal's
  boundary.
- **Scenario:** IAM user has a permission boundary that allows only
  `s3:*` actions (no `sts:*`). The boundary blocks
  `sts:AssumeRole`. The user has a trust edge to a cross-account
  role. iamscope validates because the SCP check passes and no
  boundary binding exists on trust edges.
- **Why it fails:** The permission boundary resolver
  (`resolver/permission_boundary.py`) binds boundaries to PERMISSION
  edges (`_permission` suffix), not TRUST edges (`_trust` suffix).
  The reasoner's check 4 correctly walks the bindings that exist —
  but the bindings that should exist (boundary on the source
  principal's `sts:AssumeRole` action) are never created.
- **Suggested fix scope (Session 6c):** Two-part fix: (1) extend
  `permission_boundary.py` to also bind boundaries to the source
  principal's `sts:AssumeRole_permission` edge, or (2) add a check
  in cross_account_trust that directly queries the source
  principal's boundary constraints independently of edge bindings.
  Option 2 is more robust.

#### Finding CAT-2: Cross-account evaluation only checks the target side

- **Severity:** Medium
- **Direction:** False positive (validated when the source account's
  policies would deny the AssumeRole)
- **Spec reference:** Section 6 (cross-account evaluation — "The
  request is allowed only if both evaluations return a decision of
  Allow")
- **Code reference:** `cross_account_trust.py:212-552` —
  `_evaluate_edge()` examines the trust edge (target side) and SCPs
  on the trust edge (target account's SCPs). The source account's
  identity policies and SCPs on the source principal are not
  evaluated.
- **Scenario:** External account 222's root is trusted by role in
  account 111. But account 222 has an SCP denying
  `sts:AssumeRole` for all principals. AWS denies the call. iamscope
  validates because it only evaluates the target side.
- **Why it's Medium rather than Critical:** Cross-account trust
  findings are primarily about "the trust policy exists and is
  overly permissive" — the trust configuration is the security
  concern the operator controls. Whether the source account's
  policies actually allow the call is a secondary consideration.
  However, the spec is clear that both sides must allow.
- **Suggested fix scope (Session 6c):** For each cross-account
  trust finding, additionally evaluate whether the source principal
  has an `sts:AssumeRole_permission` edge. If no permission edge
  exists, the finding should be demoted. Source-account SCP
  evaluation requires knowing which SCPs apply to the source
  principal's account. Depends on CC-1 landing first (identity-
  policy Deny must be modeled for source-side evaluation to be
  meaningful).

**Cross-cutting findings affecting this reasoner:**
- CC-1 (identity-policy Deny): A Deny on `sts:AssumeRole` in the
  source principal's identity policy; not modeled. Partially
  overlaps with CAT-2.
- CC-2 (trust-policy Deny): A Deny in the target role's trust policy
  excluding the specific source principal; not modeled. Directly
  relevant — trust-policy Deny carve-outs are the primary deny gap.
- CC-3 (SCP condition evaluation): SCP bindings on the trust edge
  suffer the CC-3 gap.
- CC-4 (SCP Allow-ceiling): If no SCP allows `sts:AssumeRole` in
  the target account, the finding validates per CC-4.

---

### Reasoner: assume_role_chain

**Module:** `iamscope/reasoner/assume_role_chain.py`
**Lines:** 768
**What it produces:** One finding per (source_principal,
admin_endpoint) chain of 2+ AssumeRole hops. Verdicts: validated,
blocked, inconclusive.

**Check sequence (5 checks, with per-hop SCP + boundary):**

| Check | Name | What it evaluates |
|-------|------|-------------------|
| 1 | `chain_length_at_least_two` | Early exit if chain < 2 hops |
| 2 | `target_role_is_admin_equivalent` | Target must be admin |
| 3 | `all_hops_have_clean_witnesses` | Per-hop witness via `and_tristate_many` |
| 4 | `no_scp_blocks_any_hop` | Per-hop SCP via `and_tristate_many` |
| 5 | `no_boundary_blocks_any_hop` | Per-hop boundary via `and_tristate_many` |

#### Finding ARC-1: Per-hop SCP checks query permission edges, SCPs bound to trust edges

- **Severity:** Medium
- **Direction:** False positive (validated when an SCP on a
  mid-chain hop's trust edge would block)
- **Spec reference:** Section 6 (SCP interaction with trust
  policies)
- **Code reference:** `assume_role_chain.py:546-598` —
  `_check_scp_blockers_on_edge` takes an edge parameter and walks
  its bindings. The BFS walk calls this on the PERMISSION edge for
  each hop. But `scp_binder.bind_all_scps()` in `pipeline.py:632-636`
  is called with `trust_edges` specifically. Permission edges get
  boundary bindings but NOT SCP bindings.
- **Scenario:** Chain: Alice → DevOps → AdminRole. The SCP blocking
  `sts:AssumeRole` from DevOps's account is bound to the trust edge
  DevOps → AdminRole. The per-hop SCP check queries the permission
  edge DevOps → AdminRole, which has no SCP bindings. The block is
  missed.
- **Why it's Medium:** The SCP bindings exist in the graph (on the
  trust edge) but the reasoner queries the wrong edge.
- **Suggested fix scope (Session 6c):** The per-hop SCP check should
  query bindings on BOTH the permission edge AND the trust edge for
  each hop. See "Patterns observed" section for the shared root
  cause with CAT-1.

**Cross-cutting findings affecting this reasoner:**
- CC-1 (identity-policy Deny): Deny on `sts:AssumeRole` in any
  mid-chain principal's identity policy; not modeled.
- CC-2 (trust-policy Deny): Deny in any mid-chain role's trust
  policy; not modeled.
- CC-3 (SCP condition evaluation): SCP bindings (on trust edges)
  suffer the CC-3 gap.
- CC-4 (SCP Allow-ceiling): Per-hop SCP ceiling evaluation absent
  per CC-4.
- CC-5 (boundary Resource scoping): Per-hop boundary checks suffer
  the CC-5 gap.

---

### Reasoner: admin_reachability

**Module:** `iamscope/reasoner/admin_reachability.py`
**Lines:** 514
**What it produces:** One finding per starting principal that can
reach at least one admin-equivalent role via any BFS path. Verdicts:
validated, inconclusive. Never blocked (defers to chain reasoners).

**Check sequence (4 checks):**

| Check | Name | What it evaluates |
|-------|------|-------------------|
| 1 | `source_has_assumerole_permissions` | Source has any AssumeRole edges |
| 2 | `reaches_at_least_one_admin` | BFS found ≥1 admin endpoint |
| 3 | `at_least_one_reachable_chain_uses_clean_witnesses` | Hyperedge traversal flag |
| 4 | `walk_terminated_within_depth_limit` | BFS depth cap check |

#### Finding AR-1: BFS walk does not evaluate SCP/boundary per hop

- **Severity:** High
- **Direction:** False positive (validated when SCP/boundary blocks a
  critical hop, making the admin unreachable)
- **Spec reference:** Section 2 (explicit deny overrides Allow at
  any layer), Section 6 (SCP as organizational deny)
- **Code reference:** `admin_reachability.py:30-32` — "No blocked
  verdict — SCP analysis is per-chain, and this reasoner is
  per-principal. SCP/boundary blocking is the territory of
  assume_role_chain." Lines 161-184 (the BFS walk) check only
  trust-edge existence and admin-equivalence; no SCP/boundary
  evaluation.
- **Scenario:** Alice can reach AdminRole only via
  DevOps → AdminRole, but that hop has an SCP block.
  `assume_role_chain` correctly marks that chain as `blocked`. But
  `admin_reachability` BFS walks through DevOps → AdminRole without
  checking the SCP, finds AdminRole is admin-equivalent, and emits
  a `validated` finding claiming Alice can reach admin.
- **Why it's High:** This is a real false-positive production path.
  The two reasoners produce contradictory verdicts for the same path,
  and the operator has no signal indicating which is correct.
- **Suggested fix scope (Session 6c):** Two options:

  Option 1: `admin_reachability`'s BFS walk checks SCP/boundary per
  hop (replicating `assume_role_chain`'s per-hop logic).

  Option 2 (preferred): `admin_reachability` runs AFTER
  `assume_role_chain` and filters out paths that
  `assume_role_chain` marked as blocked. This makes the
  orchestration explicit (`assume_role_chain` is the canonical
  SCP/boundary evaluator for chains; `admin_reachability` consumes
  its results) and avoids duplicating SCP/boundary logic across two
  reasoners.

  Option 2 is preferred. Option 1 duplicates SCP/boundary
  evaluation logic across two reasoners — exactly the architectural
  anti-pattern that creates contradictory-verdict bugs. Option 2
  makes the orchestration explicit: `assume_role_chain` is the
  canonical SCP/boundary evaluator for chains;
  `admin_reachability` consumes its results. Option 2 requires
  changes to the reasoner registry's execution ordering, which is a
  one-time architectural change rather than perpetuating
  duplication.

  Phase 2 can run in parallel with Phases 3-5 since it's an
  orchestration change rather than a constraint-evaluation change.
  Could also run BEFORE Phase 1 if quick — fixing AR-1 doesn't
  depend on CC-1/CC-2's parser changes. A pragmatic Session 6c
  might land AR-1 first as a quick correctness win, then attack
  the bigger parser-layer work in Phase 1.

**Cross-cutting findings affecting this reasoner:**
- CC-1 (identity-policy Deny): inherited transitively — if any
  hop's identity-policy Deny blocks `sts:AssumeRole`, the BFS
  shouldn't traverse that hop.
- CC-2 (trust-policy Deny): same — trust-policy Deny on a mid-chain
  role should prevent BFS traversal.
- CC-3, CC-4, CC-5: inherited transitively via the per-hop edges
  traversed.

---

## Session 6c sequencing recommendation

Proposed order based on severity, direction, and architectural
relationships:

### Phase 1 — Parser-layer foundations (CC-1, CC-2)

Highest impact. CC-1 (Critical) and CC-2 (High) must land first
because they unblock all reasoner-level deny checking. Without
parser-preserved Deny constraints, no reasoner fix can evaluate
identity-policy or trust-policy denies.

- CC-1: identity-policy Deny → Constraint → EdgeConstraint pipeline
- CC-2: trust-policy Deny → Constraint → EdgeConstraint pipeline

### Phase 2 — AR-1 headline fix

Highest-severity reasoner-specific finding. Recommended approach
is Option 2 (orchestration-level fix): `admin_reachability` runs
AFTER `assume_role_chain` and filters out paths that
`assume_role_chain` marked as blocked. This makes the orchestration
explicit (`assume_role_chain` is the canonical SCP/boundary evaluator
for chains; `admin_reachability` consumes its results) and avoids
duplicating SCP/boundary logic across two reasoners.

Phase 2 can run in parallel with Phases 3-5 since it's an
orchestration change rather than a constraint-evaluation change.
Could also run BEFORE Phase 1 if quick — fixing AR-1 doesn't
depend on CC-1/CC-2's parser changes. A pragmatic Session 6c
might land AR-1 first as a quick correctness win, then attack
the bigger parser-layer work in Phase 1.

### Phase 3 — SCP/boundary binding architecture (CAT-1, ARC-1)

Shared root cause. Best addressed with an architectural fix
(bind both constraint types to both edge types) rather than
per-finding tactical patches. See "Patterns observed" section.

### Phase 4 — Cross-account source-side evaluation (CAT-2)

Medium severity. Depends on CC-1 (identity-policy Deny must be
modeled before source-side evaluation makes sense).

### Phase 5 — Resolver improvements (CC-3, CC-4, CC-5)

Medium/Low severity. Can be done incrementally:
- CC-3: SCP condition evaluation (start with top 3-5 patterns)
- CC-4: SCP Allow-ceiling (uncommon in practice)
- CC-5: boundary Resource scoping (uncommon in practice)

### Phase 6 — Low-severity items (evaluate scope boundaries)

SBR-1, SBR-2, S3-1, PRL-1, PRE-1 are all documented scope
boundaries or over-conservative behavior. Session 6c evaluates
each: expand scope (make iamscope handle the case) or accept
the boundary (document the limitation). Expanding scope and
fixing bugs are different work.
