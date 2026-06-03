# Deny Evaluation Specification

**Document type:** Ground-truth specification for AWS IAM deny
semantics and iamscope's data flow for deny information.

**Scope:** This spec describes AWS IAM's deny evaluation semantics
(Sections 1-7) and iamscope's current three-layer data flow for deny
information (Section 8). It does NOT audit whether iamscope's current
behavior matches the spec — that is Session 6b's deliverable. This
spec is the ground truth that Sessions 6b (reasoner audit) and 6c
(gap fixes + pinning tests) measure against.

**Primary AWS reference:**
https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_policies_evaluation-logic.html

---

## Section 1 — AWS IAM evaluation logic overview

### The evaluation algorithm

AWS IAM evaluates every API request against all applicable policies.
The enforcement code processes policies in this order:

1. **Deny evaluation** — scan ALL applicable policies for explicit
   Deny. If any explicit Deny matches, return Deny immediately.
2. **AWS Organizations SCPs** — if the principal's account is an
   Organizations member, at least one SCP at every level of the OU
   hierarchy must Allow the action.
3. **Resource-based policies** — if the target resource has a
   resource-based policy that grants access to the calling principal
   (same-account only for most services; cross-account has different
   rules).
4. **Identity-based policies** — the principal's managed and inline
   policies must contain an Allow.
5. **IAM permissions boundaries** — if a permissions boundary is
   attached to the principal, the action must be in the boundary's
   Allow set.
6. **Session policies** — if the request uses an assumed-role session
   with a session policy, the session policy must Allow.

AWS documentation (verbatim):

> "**Deny evaluation** — By default, all requests are denied. This is
> called an implicit deny. The AWS enforcement code evaluates all
> policies within the account that apply to the request. These include
> AWS Organizations SCPs and RCPs, resource-based policies,
> identity-based policies, IAM permissions boundaries, and session
> policies. In all those policies, the enforcement code looks for a
> `Deny` statement that applies to the request. This is called an
> explicit deny. If the enforcement code finds even one explicit deny
> that applies, the enforcement code returns a final decision of
> **Deny**. If there is no explicit deny, the enforcement code
> evaluation continues."

### Key principle

**Explicit deny overrides everything.** An explicit Deny in ANY
policy layer (identity, resource-based, SCP, boundary, session)
beats an explicit Allow in ANY other policy layer. Explicit Deny
is absolute across all policy layers.

(Note: a related but different rule — that a principal needs an
identity-policy Allow to use a resource — has an exception for
same-account resource-based policies granting access to IAM user
ARNs. That exception bypasses implicit deny from identity policies
and permission boundaries, but does NOT bypass explicit deny.
See Section 6 for the full cross-policy interaction matrix.)

### Policy layers relevant to iamscope

iamscope models these policy layers:

| Layer | Collected? | Deny modeled? | Where in iamscope |
|-------|-----------|--------------|-------------------|
| Identity policies (managed + inline) | Yes | **Allow only** | `parser/permission_policy.py` |
| Trust policies | Yes | **Allow only** | `parser/trust_policy.py` |
| SCPs | Yes | **Deny modeled** | `parser/scp_policy.py` → `resolver/scp_binder.py` |
| Permission boundaries | Yes | **Ceiling modeled** | `resolver/permission_boundary.py` |
| Resource-based policies | **Partial** (KMS only) | **Deny + Allow for KMS** | `reasoner/secrets_blast_radius.py` |
| Session policies | No | No | Not collected |
| Resource Control Policies (RCPs) | No | No | Not collected |

---

## Section 2 — Explicit deny semantics

### Definition

An explicit deny is a policy statement with `"Effect": "Deny"` that
matches the request's action, resource, and conditions. AWS
documentation:

> "If the enforcement code finds even one explicit deny that applies,
> the enforcement code returns a final decision of **Deny**."

> "An explicit deny overrides an explicit allow."

### Where explicit deny can occur

Explicit Deny statements can appear in ALL policy types:

| Policy type | Can contain Deny? | Deny scope | Notes |
|-------------|------------------|------------|-------|
| Identity policy (managed) | Yes | Denies actions for the attached principal | Common pattern: "allow everything except these dangerous actions" |
| Identity policy (inline) | Yes | Same | Same |
| Trust policy | Yes | Denies trust from specific principals | Less common; restricts who can assume the role |
| SCP | Yes | Denies actions for all principals in affected accounts | Most common deny-in-production pattern |
| Permission boundary | Yes (but unusual) | Technically a boundary can have Deny statements, but the standard pattern is Allow-list-only | A Deny in a boundary is redundant — anything not in the Allow set is already implicitly denied by the ceiling |
| Resource-based policy | Yes | Denies access to the resource from specific principals/conditions | Common on S3 buckets, KMS keys, SQS queues |
| Session policy | Yes | Denies actions for the specific assumed-role session | Rare in practice |

### Explicit deny interaction matrix

When multiple policies apply, explicit Deny in ANY layer overrides
Allow in ALL layers:

| Scenario | Identity Allow? | SCP Allow? | Explicit Deny anywhere? | Result |
|----------|---------------|-----------|------------------------|--------|
| Normal allow | Yes | Yes | No | **Allow** |
| SCP missing allow | Yes | No | No | **Implicit Deny** |
| Identity deny | Yes (in policy A) | Yes | Yes (Deny in policy B on same principal) | **Explicit Deny** |
| SCP deny | Yes | Yes (in SCP A) | Yes (Deny in SCP B) | **Explicit Deny** |
| Boundary deny | Yes | Yes | Yes (Deny in boundary) | **Explicit Deny** |
| Cross-layer deny | Yes (identity) | Yes (SCP) | Yes (Deny in resource policy) | **Explicit Deny** |

### SCP-specific deny semantics

SCPs are the most common source of explicit deny in production AWS
environments. AWS documentation:

> "If a permission is blocked at any level above the account, either
> implicitly (by not being included in an `Allow` policy statement) or
> explicitly (by being included in a `Deny` policy statement), a user
> or role in the affected account can't use that permission, even if
> the account administrator attaches the `AdministratorAccess` IAM
> policy with \*/\* permissions to the user."

> "SCPs affect all users and roles in attached accounts, **including
> the root user**."

SCPs affect principals, not resources. An SCP deny on `s3:PutObject`
prevents all principals in the account from putting objects, but does
not affect cross-account principals accessing resources in that
account via resource-based policies (the SCP applies to the
principal's account, not the resource's account).

### Permission boundary deny semantics

Permission boundaries are NOT explicit deny in the traditional
sense — they are implicit-deny ceilings. AWS documentation:

> "A permissions boundary is an advanced feature for using a managed
> policy to set the **maximum permissions** that an identity-based
> policy can grant to an IAM entity."

> "When you use a policy to set the permissions boundary for a user,
> it **limits the user's permissions but does not provide permissions
> on its own**."

The effective permissions are the intersection of the identity policy
and the boundary. Actions not in the boundary's Allow set are
implicitly denied, but this is a different mechanism from an explicit
Deny statement — it's the absence of an Allow in the ceiling.

However, a permission boundary CAN contain explicit Deny statements.
If it does, those denies work the same as any other explicit deny —
they override Allows from identity policies.

**Critical user vs role distinction for resource-based policies:**

> "Within the same account, resource-based policies that grant
> permissions to an IAM user ARN [...] are **not limited by an
> implicit deny in an identity-based policy or permissions boundary**."

> "Resource-based policies that grant permissions to an IAM role ARN
> are **limited by an implicit deny in a permissions boundary or
> session policy**."

This means a resource-based policy granting access to a USER bypasses
the user's permission boundary ceiling (same-account only). But a
resource-based policy granting access to a ROLE is still limited by
the role's boundary. This asymmetry is a known source of confusion.

---

## Section 3 — Implicit deny semantics

### Definition

An implicit deny is the default state: if no policy explicitly
allows an action, the action is denied. AWS documentation:

> "By default, all requests are denied. This is called an implicit
> deny."

### Distinction from explicit deny

| Property | Implicit deny | Explicit deny |
|----------|-------------- |---------------|
| Source | Absence of Allow | Presence of Deny statement |
| Override | Can be overridden by an Allow | Cannot be overridden by any Allow |
| Resource-based policy exception | Same-account resource-based policy for IAM users can override | Cannot be overridden even by resource-based policy |
| Detection | "No matching Allow found" | "Matching Deny found" |

### iamscope's relationship to implicit deny

iamscope constructs edges from Allow statements. An edge exists if
and only if the parser found an Allow. If no Allow exists for an
action, no edge is created — meaning iamscope's graph naturally
lacks edges for actions that AWS would implicitly deny. The
reasoners operate on edges; without an edge, no finding is produced.

Whether this construction-based approach correctly models implicit
deny in all cases (e.g., when actions are not collected at all vs.
when collected but no Allow found) is a Session 6b audit question.
The factual point for the spec is: iamscope models implicit deny
via edge absence, not via explicit constraint propagation.

### iamscope's relationship to explicit deny

For explicit deny, iamscope's data flow varies by policy type.
Identity and trust policy parsers do not create constraints from
Deny statements (see Section 8 for the per-layer responsibility
map). SCP and permission-boundary parsers do model deny semantics
(with the specific scope and limitations also documented in
Section 8). Whether the resulting data flow correctly captures all
cases is a Session 6b audit question.

---

## Section 4 — Action and resource matching for denies

### Action matching

AWS IAM action names are **case-insensitive** for matching purposes.
`iam:PassRole`, `IAM:passrole`, and `iam:PASSROLE` all match the
same action. This applies to both Allow and Deny statements.

**Wildcards in Action field:**

- `"Action": "*"` matches every action across all services.
- `"Action": "s3:*"` matches every S3 action.
- `"Action": "iam:Pass*"` matches `iam:PassRole` and any future
  action starting with `iam:Pass`.
- Multi-character wildcards only: `*` and `?` are the two glob
  metacharacters. `*` matches zero or more characters; `?` matches
  exactly one character.

A Deny statement with `"Action": "*"` denies everything the
principal can do, subject to the statement's Resource and Condition
constraints. `"Action": "*", "Resource": "*"` with no Condition is
the broadest possible deny — it blocks all actions on all resources
unconditionally.

`"Action": "*"` in a Deny is semantically equivalent to
`"Action": ["list", "of", "every", "known", "action"]` plus every
future action. In practice, `"Action": "*"` is strictly stronger
because it matches actions that didn't exist when the policy was
written.

**NotAction (inversion semantics):**

`"NotAction"` in a Deny statement means "deny everything EXCEPT
these actions." This is the most common pattern in SCP deny
statements:

```json
{
  "Effect": "Deny",
  "NotAction": ["sts:AssumeRole", "iam:PassRole"],
  "Resource": "*"
}
```

This denies every action EXCEPT `sts:AssumeRole` and
`iam:PassRole`. The inversion is evaluated at match time: if the
request's action is NOT in the NotAction list, the Deny applies.

Note: this hypothetical example shows the inversion mechanic;
deploying it would deny every API call except STS and PassRole,
which is more restrictive than nearly any real SCP. Production
SCPs typically use NotAction in Deny with narrower scopes
(e.g., Resource scoped to specific account paths, Conditions
limiting to specific principals or regions).

**Key subtlety:** NotAction in a Deny is NOT the same as Action in
an Allow. `Deny + NotAction: [X]` means "deny everything except X"
— it's a broad deny with narrow exceptions. `Allow + Action: [X]`
means "allow only X." The two statements have different evaluation
shapes even though they might seem complementary.

**Malformed or nonexistent action names:** AWS does not validate
action names at policy creation time for all services. A Deny on
`"Action": "fake:NonexistentAction"` is syntactically valid and
stored in the policy, but never matches any real request (because
no service generates that action). It's dead policy weight — it
doesn't cause errors, it just never fires.

### Resource matching

Resource ARNs in Deny statements follow the same matching rules as
Allow statements:

- **Exact match:** `"Resource": "arn:aws:s3:::my-bucket"` matches
  only that bucket.
- **Wildcard match:** `"Resource": "arn:aws:s3:::my-bucket/*"`
  matches all objects in the bucket.
- **Full wildcard:** `"Resource": "*"` matches all resources (most
  common in SCP denies).

**Case sensitivity:** ARN matching is case-sensitive for the
resource-specific portion (everything after the service prefix).
`arn:aws:s3:::My-Bucket` and `arn:aws:s3:::my-bucket` are different
resources. However, the `arn:aws:` prefix and service name portions
are case-insensitive in practice (AWS normalizes them).

**NotResource (inversion semantics):**

`"NotResource"` in a Deny statement means "deny on all resources
EXCEPT these." Pattern:

```json
{
  "Effect": "Deny",
  "Action": "s3:*",
  "NotResource": [
    "arn:aws:s3:::approved-bucket",
    "arn:aws:s3:::approved-bucket/*"
  ]
}
```

This denies all S3 actions on every bucket EXCEPT `approved-bucket`.
NotResource in a Deny is a common guardrail pattern ("you can only
use these specific resources").

**NotResource + NotAction combined:** Valid but confusing. A
statement with both `NotAction` and `NotResource` in a Deny means
"deny everything except these actions on everything except these
resources." In practice this is rare and hard to reason about. AWS
evaluates it correctly but security auditors routinely flag it as a
policy smell.

### iamscope's action and resource matching for denies

iamscope's SCP parser (`parser/scp_policy.py`) extracts both
`deny_actions` and `deny_not_actions` from SCP Deny statements.
The SCP binder (`resolver/scp_binder.py`) matches edge actions
against both lists using case-insensitive fnmatch-based globbing
(Python's `fnmatch` module). This covers the Action and NotAction
matching for SCP denies.

For identity-policy and trust-policy denies, iamscope does not
currently extract or match Deny actions or resources — see
Section 8 for the data flow details.

Resource-level matching on Deny statements (whether the denied
resource pattern matches the specific resource in a finding) is not
performed by any current iamscope module except
`secrets_blast_radius`'s KMS key policy evaluator.

---

## Section 5 — Conditional denies

### Deny statements with Condition blocks

A Deny statement can include a `Condition` block that restricts when
the deny applies. The deny only fires when the condition evaluates
to true. This makes conditional denies narrower than unconditional
denies — they block access only under specific circumstances.

Common patterns:

```json
{
  "Effect": "Deny",
  "Action": "s3:*",
  "Resource": "*",
  "Condition": {
    "StringNotEquals": {
      "aws:RequestedRegion": ["us-east-1", "eu-west-1"]
    }
  }
}
```

This denies S3 actions only when the request is NOT in us-east-1 or
eu-west-1 (a region-restriction guardrail). In us-east-1, the
condition is false and the deny does not apply.

### Missing context keys — the truth table

When a condition key referenced in a Deny statement is absent from
the request context, the behavior depends on the condition operator.
AWS documentation (verbatim):

> "If the key that you specify in a policy condition is not present
> in the request context, the values do not match and the condition
> is *false*. If the policy condition requires that the key is *not*
> matched, such as `StringNotLike` or `ArnNotLike`, and the right
> key is not present, the condition is *true*."

The complete truth table for a MISSING key:

| Operator family | Missing key → condition evaluates to | Effect on Deny |
|----------------|-------------------------------------|----------------|
| `StringEquals`, `StringLike`, `ArnEquals`, `ArnLike`, `IpAddress`, `DateEquals` | **false** | Deny does NOT apply |
| `StringNotEquals`, `StringNotLike`, `ArnNotEquals`, `ArnNotLike`, `NotIpAddress`, `DateNotEquals` | **true** | Deny DOES apply |
| `Null: true` (key is null/absent?) | **true** (key IS absent) | Deny DOES apply |
| `Null: false` (key is NOT null?) | **false** (key IS absent) | Deny does NOT apply |

### IfExists modifier

The `IfExists` suffix changes missing-key behavior:

> "You add `IfExists` to the end of any condition operator name [...]
> to say 'If the condition key is present in the context of the
> request, process the key as specified in the policy. If the key is
> not present, evaluate the condition element as true.'"

For Deny statements, this creates a critical interaction (AWS docs,
verbatim):

> "If you are using an `"Effect": "Deny"` element with a negated
> condition operator like `StringNotEqualsIfExists`, the request is
> still denied even if the condition key is not present."

The IfExists truth table for missing keys:

| Operator | Missing key without IfExists | Missing key with IfExists |
|----------|------------------------------|--------------------------|
| `StringEquals` | false (deny doesn't apply) | **true** (deny DOES apply) |
| `StringNotEquals` | true (deny applies) | **true** (deny applies) |

This means `StringEqualsIfExists` on a Deny is MORE restrictive
than `StringEquals` on a Deny when the key is missing — the deny
fires in both "key present and matches" AND "key absent" cases.

### Conservative vs aggressive handling for iamscope

When iamscope evaluates whether a conditional deny blocks a finding,
it faces uncertainty: the request context keys that would be present
at runtime are not known at static analysis time. Two strategies:

**Conservative-deny (assume the deny applies):** Treat the
conditional deny as if the condition is satisfied. This produces
more `blocked` or `inconclusive` verdicts — more false negatives
(claims a path is blocked when it might work) but fewer false
positives (never claims a path works when a deny would stop it).

**Conservative-allow (assume the deny doesn't apply):** Treat the
conditional deny as if the condition is NOT satisfied. This produces
more `validated` verdicts — more false positives (claims a path
works when a deny might stop it) but fewer false negatives.

**Recommended per-pattern strategy:**

| Pattern | Recommended bias | Rationale |
|---------|-----------------|-----------|
| `cross_account_trust` | Conservative-deny | Verdict semantics: validated should mean unconditional |
| `passrole_lambda` | Conservative-deny | Same |
| `passrole_ecs` | Conservative-deny | Same |
| `s3_bucket_takeover` | Conservative-deny | Same |
| `secrets_blast_radius` | Conservative-deny | Same |
| `admin_reachability` | Conservative-deny | Transitive — inherits from underlying chain reasoners |
| `assume_role_chain` | Conservative-deny | Per-hop: any conditional deny on any hop should demote |
| `iam_group_membership_escalation` | Conservative-deny | Same |

All 8 patterns should bias conservative-deny. The rationale is the
semantics of iamscope's verdicts: a `validated` finding asserts that
the attack path works given the policies as-written. If a conditional
deny could block the path but iamscope can't statically determine
whether the condition fires, the finding's `validated` status
overstates iamscope's epistemic state. Conservative-deny demotes
such findings to inconclusive, preserving the strength of the
`validated` claim for findings where the path genuinely is
unconditional.

The exception would be patterns where under-flagging is the
dominant cost — a compliance tool that needs to enumerate every
possible access path, for instance. iamscope's verdict semantics
mean conservative-deny is the correct default for all current
patterns.

### iamscope's current condition evaluation on denies

iamscope's SCP binder (`resolver/scp_binder.py`) does not evaluate
conditions on SCP Deny statements — it matches actions and resources
only. The `governance_confidence` field on SCP bindings is computed
from parse completeness; condition evaluation is a separate concern
not currently reflected in that field.

The `secrets_blast_radius` reasoner's KMS key policy evaluator
(`reasoner/secrets_blast_radius.py:128-366`) is the only module that
evaluates conditions on Deny statements, and it handles them
conservatively: Deny statements with `NotPrincipal`, `NotAction`, or
`NotResource` return UNKNOWN rather than attempting evaluation.

Identity-policy and trust-policy Deny statements are not parsed, so
their conditions are not evaluated. See Section 8 for the full data
flow.

---

## Section 6 — Cross-policy interaction

### The evaluation flowchart

AWS's policy evaluation is not a simple priority list — it's a
flowchart with branches depending on the request type (same-account
vs cross-account), principal type (user vs role), and which policy
layers are attached. The core flow for a **same-account** request:

```
Request arrives
    │
    ▼
[1] Scan ALL policies for explicit Deny ──── found? ──→ DENY (final)
    │ (no explicit deny found)
    ▼
[2] SCP allows? ─────────────────────── no? ──→ IMPLICIT DENY
    │ (yes, or no SCP attached)
    ▼
[3] Resource-based policy grants? ─────── yes? ──→ ALLOW (for users*)
    │ (no, or principal is a role)
    ▼
[4] Identity policy allows? ────────── no? ──→ IMPLICIT DENY
    │ (yes)
    ▼
[5] Permission boundary allows? ───── no? ──→ IMPLICIT DENY
    │ (yes, or no boundary attached)
    ▼
[6] Session policy allows? ─────────── no? ──→ IMPLICIT DENY
    │ (yes, or no session policy)
    ▼
ALLOW (final)
```

Step 3 exception applies only when the resource-based policy names
a specific IAM user ARN — not when it names a role ARN, not when it
uses `Principal: "*"`. See Section 6 row 11 for the full exception
matrix.

### Cross-account evaluation

For cross-account requests, AWS evaluates BOTH accounts
independently. AWS documentation (verbatim):

> "When you make a cross-account request, AWS performs two
> evaluations. AWS evaluates the request in the trusting account and
> the trusted account."

> "The request is allowed only if both evaluations return a decision
> of `Allow`."

This means:
- The **source account** must allow the action via the principal's
  identity policies (+ SCP + boundary + session policy as applicable)
- The **target account** must allow the action via a resource-based
  policy or trust policy on the target resource/role
- An explicit Deny in EITHER account kills the request

### Cross-policy interaction matrix

This is the table that Section 1's forward reference points to.
For each combination, the result assumes the action/resource match
and any conditions are satisfied.

| # | Scenario | Identity policy | Other layer | Result | Notes |
|---|----------|----------------|-------------|--------|-------|
| 1 | Normal allow | Allow | SCP: Allow | **Allow** | Happy path |
| 2 | SCP implicit deny | Allow | SCP: no matching Allow | **Implicit Deny** | SCP is a ceiling; missing Allow = blocked |
| 3 | SCP explicit deny | Allow | SCP: Deny | **Explicit Deny** | Deny overrides identity Allow |
| 4 | Identity Deny on same action | Allow (policy A) | Identity: Deny (policy B) | **Explicit Deny** | Deny in ANY policy on the principal overrides Allow in ANY other |
| 5 | Boundary missing action | Allow | Boundary: action not in Allow set | **Implicit Deny** | Boundary is ceiling; action outside ceiling = blocked |
| 6 | Boundary explicit Deny | Allow | Boundary: Deny statement | **Explicit Deny** | Rare but valid; works like any other explicit deny |
| 7 | Resource policy Deny (same-account) | Allow | Resource policy: Deny | **Explicit Deny** | Explicit deny is absolute |
| 8 | Resource policy Deny (cross-account) | Allow (source acct) | Resource policy: Deny (target acct) | **Explicit Deny** | Deny in either account kills the request |
| 9 | Session policy Deny | Allow | Session policy: Deny | **Explicit Deny** | Session policies can deny |
| 10 | Session policy missing Allow | Allow | Session policy: no Allow | **Implicit Deny** | Session policy is a ceiling like boundary |

### The user-ARN resource-policy exception (row 11)

This is the exception referenced in Section 1. AWS documentation
(verbatim):

> "Within the same account, resource-based policies that grant
> permissions to an IAM user ARN [...] are **not limited by an
> implicit deny in an identity-based policy or permissions
> boundary**."

> "Resource-based policies that grant permissions to an IAM role
> ARN are **limited by an implicit deny in a permissions boundary
> or session policy**."

| # | Scenario | Principal type | Resource policy | Identity/Boundary | Result |
|---|----------|---------------|----------------|-------------------|--------|
| 11a | Resource grants to user ARN (same-account) | IAM User | Allow | No identity Allow, no boundary Allow | **Allow** (exception) |
| 11b | Resource grants to role ARN (same-account) | IAM Role | Allow | No boundary Allow | **Implicit Deny** (no exception for roles) |
| 11c | Resource grants to user ARN (cross-account) | IAM User | Allow (target acct) | No identity Allow (source acct) | **Implicit Deny** (exception is same-account only) |
| 11d | Resource grants to `*` (same-account) | Any | Allow with `Principal: "*"` | No identity Allow | **Implicit Deny** (exception requires specific user ARN, not `*`) |

Architectural note for iamscope: Row 11a describes an access path
where a resource-based policy grants directly to a user ARN.
iamscope currently models resource-based policy grants only for
KMS key policies (in secrets_blast_radius). Whether to model
resource-based policy grants more broadly — and whether the
absence of such modeling materially affects any pattern's findings
— is a Session 6b audit question.

### SCP interaction with trust policies

SCPs restrict what principals in the affected account can DO, but
they do not restrict what principals in OTHER accounts can do when
accessing resources in the SCP-affected account. Specifically:

- An SCP on account A that denies `sts:AssumeRole` prevents
  principals IN account A from assuming roles (anywhere).
- It does NOT prevent principals in account B from assuming roles
  IN account A — the SCP applies to A's principals, not A's
  resources.
- The trust policy on A's role controls who can assume it; the SCP
  on A controls what A's own principals can do.

For cross-account trust findings, the relevant SCP is the one on
the SOURCE principal's account (where the AssumeRole call
originates), not the TARGET role's account.

---

## Section 7 — Edge cases

### Empty Deny statements

A Deny statement with no `Action` field (or an empty Action list)
is syntactically invalid per IAM policy grammar. AWS's policy
validator rejects it at policy creation time. If it somehow exists
(e.g., in a policy created before stricter validation), it matches
no actions and has no effect.

A Deny statement with `"Action": "*"` and `"Resource": "*"` and no
Condition is not "empty" — it's the broadest possible deny. It
blocks everything unconditionally.

### Deny on services iamscope doesn't model

iamscope models a subset of AWS actions: `sts:AssumeRole`,
`iam:PassRole`, `lambda:CreateFunction`, `lambda:InvokeFunction`,
`ec2:RunInstances`, `ecs:RegisterTaskDefinition`, `ecs:RunTask`,
`secretsmanager:GetSecretValue`, `s3:PutBucketPolicy`,
`iam:AddUserToGroup`, `kms:Decrypt`, and their wildcard variants.

A Deny on an action iamscope doesn't model (e.g.,
`dynamodb:DeleteTable`) has no effect on iamscope's findings because
iamscope doesn't create edges for that action. This is correct
behavior — the deny is real but irrelevant to the attack paths
iamscope evaluates.

A Deny on a WILDCARD action (`"Action": "*"`) that includes actions
iamscope DOES model is material and must be evaluated. This is the
common case for SCP denies — `Deny *` or
`Deny + NotAction: [exceptions]`.

### Malformed policies

Policies with missing required fields (`Effect`, `Action`/`NotAction`,
`Resource`/`NotResource`) are rejected by AWS's policy validator at
creation time. However, iamscope may encounter malformed policy
documents in collection if the policy was created under older
validation rules or through non-standard paths.

iamscope's parsers should handle malformed policies defensively:
log a warning, skip the malformed statement, and continue processing
the remaining statements. A malformed Deny statement should not
crash the parser or silently alter the meaning of surrounding
statements. The current parser behavior for malformed input is a
Session 6b audit target.

### Action + NotAction in the same statement

A statement cannot have both `Action` and `NotAction` — they are
mutually exclusive per IAM policy grammar. AWS rejects this at
policy validation time. If encountered, iamscope should treat the
statement as malformed (log + skip).

Similarly, `Resource` and `NotResource` are mutually exclusive.
`Principal` and `NotPrincipal` are mutually exclusive.

### Resource-based policies with `Principal: "*"`

A resource-based policy with `"Principal": "*"` grants access to
ANY principal from ANY account. This is the "public access" pattern
(common on S3 buckets, SQS queues).

For **same-account** requests: `Principal: "*"` does NOT trigger
the user-ARN resource-policy exception (row 11d in Section 6). The
principal still needs an identity-policy Allow unless the resource-
based policy names the principal's ARN specifically.

For **cross-account** requests: `Principal: "*"` in a resource-
based policy CAN grant cross-account access without the source
account's identity policy explicitly allowing it — but only for
specific services (S3 is the main one). For most services, the
source account's identity policy must also Allow. This is a
service-specific behavior, not a universal IAM rule.

### Wildcards in Principal field

`"Principal": {"AWS": "arn:aws:iam::*:role/*"}` is NOT valid IAM
syntax — the Principal field does not support wildcards within ARN
components. The only valid wildcards in Principal are:
- `"Principal": "*"` (any principal, any account)
- `"Principal": {"AWS": "arn:aws:iam::<redacted-aws-account-id>:root"}` (account
  root = any principal in that account)

ARN-level wildcards like `arn:aws:iam::*:role/Admin*` are NOT
supported in Principal. They ARE supported in Resource and Condition
values.

### Deny in trust policies

Trust policies are evaluated as resource-based policies on the IAM
role resource. A Deny statement in a trust policy prevents the
denied principal from assuming the role, even if the principal has
`sts:AssumeRole` permission via their identity policy.

Trust-policy Deny is evaluated during the `sts:AssumeRole` request.
AWS checks:
1. Does the role's trust policy Allow the caller? (must find Allow)
2. Does the role's trust policy Deny the caller? (explicit deny
   overrides the Allow)
3. Does the caller's identity policy Allow `sts:AssumeRole`?
4. Do SCPs/boundaries/session policies allow?

Trust-policy Deny is particularly relevant for patterns like
"allow account 222 root, but deny specific role
`arn:aws:iam::222:role/Restricted`." The Allow grants broad access;
the Deny carves out an exception for a specific principal.

iamscope's trust policy parser (`parser/trust_policy.py:169-171`)
currently skips all Deny statements:
`if effect != "Allow": continue`. The architectural decision to
skip rather than preserve trust-policy Deny is documented at
`parser/trust_policy.py` line 11. Section 8 documents the per-layer
data flow; whether the current trust-policy parsing approach
correctly handles all relevant cases is a Session 6b audit question.

### Aliased actions

Some AWS services have action aliases where multiple action strings
map to the same underlying API operation. For example,
`s3:ListBucket` and `s3:ListObjects` may resolve to the same
operation depending on the API version.

A Deny on one alias does NOT automatically deny the other alias
unless the Deny uses a wildcard that covers both (e.g., `s3:List*`).
AWS evaluates the action string literally against the policy, not
the underlying API operation.

Aliasing is uncommon for the IAM/STS/Lambda/ECS/S3/SecretsManager
actions iamscope currently models, though a comprehensive alias
audit has not been conducted.

---

## Section 8 — iamscope's current data flow for deny information

### Overview

iamscope processes deny-related information across three layers:
parsers extract policy semantics from collected JSON, resolvers
compute constraints from parsed data and bind them to graph edges,
and reasoners evaluate constraints when producing findings. Each
layer preserves some deny information and drops some. This section
documents what each layer does and does not do, with file and line
references. Whether the current data flow correctly handles all
cases described in Sections 1-7 is a Session 6b audit question.

### Layer 1 — Parsers

Parsers read collected IAM policy documents and produce structured
objects (edges, parse results, constraints) that flow into the
graph. Three parsers handle deny-relevant policy types:

#### `parser/trust_policy.py`

**Input:** Role trust policy JSON documents.

**What it preserves:** Allow statements only. Each Allow statement
with its principal, action, and conditions produces a
`TrustParseResult` that becomes a trust edge in the graph.

**What it drops:** All Deny statements. Lines 169-171:
```python
effect = statement.get("Effect", "")
if effect != "Allow":
    continue
```
Documented at line 11: "Deny statements are skipped — they restrict
trust but don't create edges."

**What this means for the data flow:** Trust-policy Deny statements
do not enter the graph in any form. No `Constraint` objects are
created from them. No `EdgeConstraint` bindings reference them.
Reasoners that evaluate trust edges (`cross_account_trust`,
`assume_role_chain`) have no data from trust-policy Deny statements,
because the information is discarded at parse time.

#### `parser/permission_policy.py`

**Input:** Identity policy JSON documents (managed and inline
policies attached to users, roles, and groups).

**What it preserves:** Allow statements only. Each Allow statement
with its action, resource, and conditions produces a
`PermissionParseResult` that becomes a permission edge in the graph.
Documented at line 12: "Only processes Allow statements (Deny
doesn't create permission edges)."

**What it drops:** All Deny statements. The parser iterates
statements and processes only those with `Effect: Allow`. Deny
statements in identity policies — including patterns like "Allow *
on * EXCEPT Deny iam:PassRole on arn:...:role/Prod*" — do not
enter the graph.

**NotAction handling on Allow:** The parser DOES handle `NotAction`
on Allow statements (`parser/permission_policy.py:216-288`). A
statement with `Allow + NotAction: [X]` is processed as "allow
everything except X" using inverse matching via
`_extract_via_not_action()`. This is Allow-side NotAction only —
Deny-side NotAction is not reached because Deny statements are
skipped entirely.

**What this means for the data flow:** Identity-policy Deny
statements do not enter the graph. A principal with both
`Allow iam:PassRole *` and `Deny iam:PassRole arn:...:role/Prod*`
in their policies will have a permission edge for PassRole to
Prod roles, with no constraint from the Deny. The data flow path
for identity-policy Deny information ends at the parser, which
discards Deny statements before constraint construction.

#### `parser/scp_policy.py`

**Input:** SCP JSON documents collected from AWS Organizations.

**What it preserves:** Deny statement action semantics. The parser
extracts `deny_actions` (from `Action` field on Deny statements)
and `deny_not_actions` (from `NotAction` field on Deny statements),
plus exception principal patterns, into `SCPParseResult` objects.
These become `Constraint` objects in the graph. Line 138:
```python
if effect != "Deny":
    continue  # SCPs: only Deny statements produce constraints
```
Line 201: constructs the SCPParseResult with `effect="Deny"`.

**What it preserves on exceptions:** Exception matching patterns
(`exception_principal_patterns`) are extracted from Condition blocks
that reference `aws:PrincipalArn`, `aws:PrincipalOrgID`, or
`aws:PrincipalAccount` with `StringNotLike`/`ArnNotLike` operators.
These are stored in the Constraint's properties.

**What it drops:** SCP Allow statements (SCPs use Allow as a
ceiling, which iamscope does not model — iamscope only models SCP
Deny). Condition blocks beyond the exception-matching patterns
(general conditions on SCP Deny statements are not evaluated).
Resource-level scoping on SCP Deny statements (the `Resource` field
is not matched against specific edge targets).

**What this means for the data flow:** SCP deny_actions and
deny_not_actions enter the graph as Constraint objects. The
resolver layer (scp_binder) matches them against edges. Reasoners
can query whether an edge has SCP-deny bindings. Condition
evaluation beyond principal-exception matching is not performed.

### Layer 2 — Resolvers

Resolvers take parsed data and compute constraint bindings that
attach to specific edges in the graph. Two resolvers handle deny-
related constraints:

#### `resolver/scp_binder.py`

**Input:** Trust edges + SCP Constraint objects + the Organizations
OU-account mapping.

**What it computes:** For each trust edge, checks whether any
applicable SCP's `deny_actions` or `deny_not_actions` match the
edge's action. Uses Python's `fnmatch` module for case-insensitive
glob matching (line 192:
`fnmatch.fnmatch(action_lower, da.lower())`).

Produces `EdgeConstraint` objects with:
- `likely_blocking`: whether the SCP is assessed as blocking the
  edge's action. Requires `parse_status="complete"` (Invariant #17,
  line 268).
- `governance_confidence`: computed from parse completeness;
  condition evaluation is a separate concern not currently reflected
  in this field (lines 272-286).
- `binding_reason`: human-readable explanation of why the SCP
  matches (lines 310-321).

**Exception matching:** Before setting `likely_blocking=True`, the
binder checks exception principal patterns against the edge's
source ARN using fnmatch (lines 91-103, 217-239). If the source
principal matches an exception pattern, the binding is emitted with
`likely_blocking=False` even though the action matches the deny.
This models the SCP pattern "Deny * except for BreakGlass roles."

**NotAction handling:** The binder handles `deny_not_actions`
(NotAction inversion) at lines 196-201: if the edge's action is NOT
in the deny_not_actions list, the deny applies. This implements the
inversion semantics from Section 4.

**What it does NOT compute:** Resource-level matching (whether the
SCP's Resource field matches the edge's target). Condition
evaluation beyond exception-principal matching. SCP Allow-ceiling
evaluation (whether the action is in any SCP's Allow set).

#### `resolver/permission_boundary.py`

**Input:** Permission edges + permission boundary policy documents
collected from IAM.

**What it computes:** For each permission edge on a principal with
an attached boundary, checks whether the edge's action is in the
boundary's allowed action set. Produces `EdgeConstraint` objects
with:
- `likely_blocking=True` if the action is NOT in the boundary's
  Allow set (line 225)
- `likely_blocking=False` if the action IS in the Allow set
  (lines 188, 202, 214)
- `governance_confidence` based on whether the boundary was
  successfully parsed

**What it does NOT compute:** Explicit Deny statements within
boundary policies (boundaries are modeled as Allow-set ceilings
only). Resource-level boundary scoping (whether the boundary's
Resource field matches the edge's target). Condition evaluation
on boundary statements.

### Layer 3 — Reasoners

Reasoners evaluate edges and their constraint bindings to produce
findings with verdicts. Each reasoner that evaluates deny has two
standard methods: `_check_scp_blockers` and
`_check_boundary_blockers`.

#### Per-reasoner responsibility inventory

────────────────────────────────────────────────────────────────
Reasoner: `cross_account_trust`
`_check_scp_blockers`: Yes (check 4: `no_scp_blocks_sts_assumerole`)
`_check_boundary_blockers`: No
Identity-policy Deny: No
Trust-policy Deny: No
Resource-based policy: No
────────────────────────────────────────────────────────────────
Reasoner: `assume_role_chain`
`_check_scp_blockers`: Yes (per-edge: `_check_scp_blockers_on_edge`)
`_check_boundary_blockers`: Yes (per-edge: `_check_boundary_blockers_on_edge`)
Identity-policy Deny: No
Trust-policy Deny: No
Resource-based policy: No
────────────────────────────────────────────────────────────────
Reasoner: `passrole_lambda`
`_check_scp_blockers`: Yes (checks 4-5: SCP on CreateFunction + PassRole)
`_check_boundary_blockers`: Yes (checks 6-7: boundary on CreateFunction + PassRole)
Identity-policy Deny: No
Trust-policy Deny: No
Resource-based policy: No
────────────────────────────────────────────────────────────────
Reasoner: `passrole_ecs`
`_check_scp_blockers`: Yes (checks 4-5: SCP on RegisterTask/RunTask + PassRole)
`_check_boundary_blockers`: Yes (checks 6-7: boundary on same)
Identity-policy Deny: No
Trust-policy Deny: No
Resource-based policy: No
────────────────────────────────────────────────────────────────
Reasoner: `s3_bucket_takeover`
`_check_scp_blockers`: Yes (check 3: `no_scp_blocks_put_bucket_policy`)
`_check_boundary_blockers`: Yes (check 4: `no_boundary_blocks_put_bucket_policy`)
Identity-policy Deny: No
Trust-policy Deny: No
Resource-based policy: No
────────────────────────────────────────────────────────────────
Reasoner: `secrets_blast_radius`
`_check_scp_blockers`: Yes (check 3: SCP on GetSecretValue)
`_check_boundary_blockers`: Yes (check 4: boundary on GetSecretValue)
Identity-policy Deny: No
Trust-policy Deny: No
Resource-based policy: **KMS only** (check 6: `kms_key_policy_allows_decrypt`)
────────────────────────────────────────────────────────────────
Reasoner: `admin_reachability`
`_check_scp_blockers`: No (defers to chain reasoners; line 30)
`_check_boundary_blockers`: No (defers to chain reasoners)
Identity-policy Deny: No
Trust-policy Deny: No
Resource-based policy: No
Note: "SCP/boundary blocking is the territory of [chain reasoners]"
────────────────────────────────────────────────────────────────
Reasoner: `iam_group_membership_escalation`
`_check_scp_blockers`: Yes (check 3)
`_check_boundary_blockers`: Yes (check 4)
Identity-policy Deny: No
Trust-policy Deny: No
Resource-based policy: No
────────────────────────────────────────────────────────────────

#### How reasoners consume constraint bindings

All reasoners that check SCP/boundary blockers follow the same
pattern:

1. Query the fact graph for `EdgeConstraint` bindings on the
   witness edge
2. Filter for bindings where `likely_blocking=True`
3. Further filter for `governance_confidence="complete"`
4. If any complete-blocking bindings exist → check state = FAIL,
   add Blocker to the finding, finding verdict may downgrade to
   `blocked`
5. If bindings exist but none are complete-blocking → check
   state = UNKNOWN, finding verdict may downgrade to `inconclusive`
6. If no bindings exist → check state = PASS

This pattern is consistent across all 7 reasoners that implement
it. The pattern consumes `EdgeConstraint` objects produced by the
resolver layer — it does not independently evaluate policies.

#### What no reasoner currently does

- **Identity-policy Deny:** The data flow path for identity-policy
  Deny information ends at the parser, which discards Deny
  statements before constraint construction. No reasoner has access
  to identity-policy Deny data.

- **Trust-policy Deny:** The data flow path for trust-policy Deny
  information ends at the parser, which discards Deny statements
  before constraint construction. No reasoner has access to
  trust-policy Deny data.

- **Resource-based policy evaluation (non-KMS):** No reasoner
  evaluates resource-based policies other than KMS key policies.
  S3 bucket policies, SQS queue policies, SNS topic policies, and
  Lambda function policies are not evaluated. The s3_bucket_takeover
  reasoner checks whether a principal can WRITE a bucket policy
  (s3:PutBucketPolicy permission), not whether the CURRENT bucket
  policy grants or denies access.

- **Condition evaluation on deny constraints:** No reasoner
  evaluates conditions on SCP Deny statements or permission
  boundary constraints beyond the exception-principal matching
  in scp_binder.

- **SCP Allow-ceiling evaluation:** No module checks whether the
  action is in any SCP's Allow set. iamscope models only the Deny
  side of SCPs, not the Allow-ceiling side.
