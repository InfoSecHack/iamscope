# Phase 1 Design Plan — CC-1: Identity-Policy Deny Fix

**Status:** Pre-implementation plan. Recon complete (Session 6c). Implementation in next session.  
**Target version:** v0.3.1 (or next available minor bump after v0.3.0).  
**Session reference:** Session 6c recon — two approved checkpoints, no code changes made.

---

## 1. Goal and Scope

### Problem

`CC-1` (Critical severity, false-positive direction): Identity-policy `Effect: "Deny"` statements are
discarded at parse time in `iamscope/parser/permission_policy.py:163-165`:

```python
effect = stmt.get("Effect", "")
if effect != "Allow":
    continue
```

No `Constraint` objects are created. No `EdgeConstraint` bindings reach reasoners. Every `Deny`
statement in every principal's identity policy is silently dropped. This means iamscope can emit
`VALIDATED` for a path that real AWS would block via an explicit deny.

### Fix strategy (3-layer pipeline)

```
parser/permission_policy.py     →  parse Deny stmts into PermissionDenyResult (new dataclass)
                                    collect_account already returns all PermissionParseResult;
                                    Phase 1 adds a parallel deny-result stream

resolver/identity_deny_binder.py  →  new module, binds IDENTITY_DENY constraints to edges
                                    same pattern as scp_binder.py + permission_boundary.py

6 reasoners                      →  add _check_identity_deny_blockers check (one new check slot each)
                                    cross_account_trust and admin_reachability: NO change needed
```

### Out of scope (Phase 1)

- `NotResource` inversion (complex; deferred to CC-4)
- Condition evaluation for Deny conditions (CC-3; conservative-deny used instead)
- `cross_account_trust` identity-deny check (operates only on trust-edge bindings; identity-deny
  binds to permission edges; confirmed by code inspection of `cross_account_trust.py` check 4 comment)
- `admin_reachability` identity-deny check (no `bindings_for_edge` calls; Phase 2 post-processor
  already propagates BLOCKED from `assume_role_chain` via `cross_reasoner_blocked`)
- Organization-level policy types (SCP, RCP) — out of scope for CC-1

---

## 2. Data Model

### 2.1 New constant

**File:** `iamscope/constants.py`

Add after `CONSTRAINT_TYPE_PERMISSION_BOUNDARY`:

```python
CONSTRAINT_TYPE_IDENTITY_DENY = "IDENTITY_DENY"
```

Existing constants for reference (do not change):
```python
CONSTRAINT_TYPE_SCP               = "SCP"
CONSTRAINT_TYPE_PERMISSION_BOUNDARY = "PERMISSION_BOUNDARY"
CONSTRAINT_TYPE_TRUST_CONDITION   = "TRUST_CONDITION"
```

### 2.2 New intermediate dataclass

**File:** `iamscope/models.py`

Add `PermissionDenyResult` dataclass (alongside `PermissionParseResult`):

```python
@dataclass(frozen=True)
class PermissionDenyResult:
    principal_arn: str          # ARN of the principal whose policy contains the Deny
    policy_arn: str             # ARN of the managed policy, or synthetic ID for inline
    statement_id: str           # Sid or auto-generated positional ID
    deny_actions: list[str]     # raw action strings from the statement (may contain wildcards)
    resource_patterns: list[str] # resource ARN patterns (["*"] if omitted)
    has_conditions: bool        # True if Condition block is non-empty
    raw_conditions: dict        # verbatim Condition block, or {}
    parse_status: str           # "complete" | "partial" | "unsupported"
    # "complete"   → no conditions, Action is a plain list
    # "partial"    → NotAction present (inversion not computed; conservative)
    # "unsupported" → NotResource or other unsupported form
```

`parse_status` drives the `governance_confidence` on the `EdgeConstraint`:
- `"complete"` + unconditional → `governance_confidence="complete"`
- `"complete"` + `has_conditions=True` → `governance_confidence="needs_review"` (conservative-deny)
- `"partial"` or `"unsupported"` → `governance_confidence="partial"`

### 2.3 New AccountData field

**File:** `iamscope/collector/account.py`

Add field to `AccountData` dataclass:

```python
permission_deny_constraints: list[Constraint] = field(default_factory=list)
```

This field is populated by `pipeline.py` after the parser emits `PermissionDenyResult` objects and
before the reasoner phase.

---

## 3. Parser Layer Changes

### 3.1 File modified: `iamscope/parser/permission_policy.py`

**Current behavior:** Lines 163-165 skip any statement where `Effect != "Allow"`. Function
`parse_permission_policy` returns `list[PermissionParseResult]` only.

**New behavior:** Parse function gains a parallel deny path. Two options evaluated during recon:

**Option A (preferred):** Add a new top-level function `parse_permission_denies` that accepts the
same `policy_doc: dict` + `principal_arn: str` + `policy_id: str` inputs and returns
`list[PermissionDenyResult]`. Called alongside `parse_permission_policy` in the collector.

**Option B (rejected):** Modify `parse_permission_policy` to return a tuple. Rejected: changes the
return type, breaks all existing callers.

#### New function signature

```python
def parse_permission_denies(
    policy_doc: dict,
    principal_arn: str,
    policy_id: str,
) -> list[PermissionDenyResult]:
    """
    Parse Deny statements from an identity policy document.
    Returns one PermissionDenyResult per Deny statement.
    Allow statements are skipped.
    """
```

#### Deny-statement parsing logic

```python
for i, stmt in enumerate(policy_doc.get("Statement", [])):
    effect = stmt.get("Effect", "Allow")
    if effect != "Deny":
        continue

    sid = stmt.get("Sid") or f"_stmt{i}"
    conditions = stmt.get("Condition") or {}
    has_conditions = bool(conditions)

    # Action vs NotAction
    actions_raw = stmt.get("Action")
    not_actions_raw = stmt.get("NotAction")
    parse_status = "complete"

    if actions_raw is not None:
        deny_actions = _normalize_to_list(actions_raw)
    elif not_actions_raw is not None:
        # NotAction in a Deny = "deny everything EXCEPT these actions"
        # We do NOT invert the set (CC-4). Conservative: treat as partial.
        deny_actions = _normalize_to_list(not_actions_raw)
        parse_status = "partial"
    else:
        # Malformed statement — no Action or NotAction
        deny_actions = []
        parse_status = "unsupported"

    # Resource vs NotResource
    resources_raw = stmt.get("Resource")
    not_resources_raw = stmt.get("NotResource")

    if resources_raw is not None:
        resource_patterns = _normalize_to_list(resources_raw)
    elif not_resources_raw is not None:
        # NotResource in Deny: deny the actions on everything EXCEPT these.
        # Inversion not supported. Conservative: treat as unsupported.
        resource_patterns = ["*"]
        parse_status = "unsupported"
    else:
        resource_patterns = ["*"]

    yield PermissionDenyResult(
        principal_arn=principal_arn,
        policy_arn=policy_id,
        statement_id=sid,
        deny_actions=deny_actions,
        resource_patterns=resource_patterns,
        has_conditions=has_conditions,
        raw_conditions=conditions,
        parse_status=parse_status,
    )
```

Helper `_normalize_to_list` already exists for the Allow path; reuse it.

#### Collector call site

**File:** `iamscope/collector/account.py` (or wherever per-principal policy iteration occurs)

After collecting `PermissionParseResult` objects for a principal, also call:

```python
deny_results = parse_permission_denies(policy_doc, principal_arn, policy_id)
# accumulate into account_data.raw_deny_results (intermediate list, pre-Constraint conversion)
```

The raw `PermissionDenyResult` objects flow to `pipeline.py` where they are converted to
`Constraint` objects. This follows the same pattern used for `SCPParseResult` → `Constraint`
conversion in `pipeline.py`.

---

## 4. Resolver Layer Changes

### 4.1 New file: `iamscope/resolver/identity_deny_binder.py`

**Pattern:** Mirrors `scp_binder.py` structure (bind one constraint to one edge, then bind-all).

#### 4.1.1 Constraint creation function

```python
def build_identity_deny_constraints(
    deny_results: list[PermissionDenyResult],
) -> list[Constraint]:
    """
    Convert PermissionDenyResult objects into Constraint objects.
    One Constraint per PermissionDenyResult.
    """
    constraints = []
    for dr in deny_results:
        if dr.has_conditions:
            confidence_q = CONFIDENCE_Q_PARTIAL   # conservative-deny
        elif dr.parse_status == "complete":
            confidence_q = CONFIDENCE_Q_COMPLETE_BLOCKING
        else:
            confidence_q = CONFIDENCE_Q_PARTIAL

        c = Constraint(
            provider="aws",
            constraint_type=CONSTRAINT_TYPE_IDENTITY_DENY,
            scope_type="Principal",
            scope_id=dr.principal_arn,           # the denying principal's ARN
            policy_id=dr.policy_arn,
            statement_id=dr.statement_id,
            region=None,                         # identity policies are global
            properties={
                "deny_actions":       dr.deny_actions,
                "resource_patterns":  dr.resource_patterns,
                "has_conditions":     dr.has_conditions,
                "raw_conditions":     dr.raw_conditions,
                "parse_status":       dr.parse_status,
            },
            status="active",
            validation_status="not_validated",
            confidence_q=confidence_q,
        )
        constraints.append(c)
    return constraints
```

#### 4.1.2 Action matching pseudocode

```python
def _action_matches_deny(action_to_check: str, deny_actions: list[str]) -> bool:
    """Case-insensitive fnmatch against each deny_actions pattern."""
    action_lower = action_to_check.lower()
    for pattern in deny_actions:
        if fnmatch.fnmatch(action_lower, pattern.lower()):
            return True
    return False
```

Wildcard handling: `sts:AssumeRole` against `sts:*` matches. `*` matches everything.
Case-insensitive: AWS action names are case-insensitive; follow same convention as `scp_binder.py`.

#### 4.1.3 Resource matching pseudocode

```python
def _resource_matches_deny(resource_arn: str, resource_patterns: list[str]) -> bool:
    """ARN glob match. ["*"] always matches."""
    for pattern in resource_patterns:
        if pattern == "*":
            return True
        if fnmatch.fnmatch(resource_arn.lower(), pattern.lower()):
            return True
    return False
```

#### 4.1.4 Edge binding function

```python
def bind_identity_deny_to_edge(
    edge: Edge,
    constraint: Constraint,
) -> EdgeConstraint | None:
    """
    Bind an IDENTITY_DENY constraint to a permission edge.

    Binding conditions:
    1. constraint.scope_type == "Principal"
    2. constraint.scope_id == edge.src.provider_id  (the source of the edge is the denying principal)
    3. The action associated with the edge (sts:AssumeRole for permission edges) matches
       at least one deny_actions pattern
    4. The edge's target ARN matches at least one resource_patterns entry

    Returns None if conditions are not met.
    """
    if constraint.scope_type != "Principal":
        return None
    if constraint.scope_id != edge.src.provider_id:
        return None

    props = constraint.properties
    deny_actions = props.get("deny_actions", [])
    resource_patterns = props.get("resource_patterns", ["*"])
    parse_status = props.get("parse_status", "partial")
    has_conditions = props.get("has_conditions", False)

    # Check action match (edge.action is the action this edge represents)
    if not _action_matches_deny(edge.action, deny_actions):
        return None

    # Check resource match (edge.tgt.provider_id is the target ARN)
    if not _resource_matches_deny(edge.tgt.provider_id, resource_patterns):
        return None

    # Determine governance_confidence and likely_blocking
    if has_conditions:
        governance_confidence = "needs_review"
        likely_blocking = True          # conservative-deny
    elif parse_status == "complete":
        governance_confidence = "complete"
        likely_blocking = True
    else:
        governance_confidence = "partial"
        likely_blocking = True          # partial still warrants caution

    return EdgeConstraint(
        edge_id=edge.edge_id,
        constraint_id=constraint.constraint_id,
        governance_confidence=governance_confidence,
        likely_blocking=likely_blocking,
        binding_reason=(
            f"identity policy Deny on {edge.src.provider_id}: "
            f"actions={deny_actions!r} resources={resource_patterns!r}"
            f"{' (conditional — conservative)' if has_conditions else ''}"
        ),
    )
```

#### 4.1.5 Bind-all function

```python
def bind_all_identity_denies(
    permission_edges: list[Edge],
    constraints: list[Constraint],
) -> list[EdgeConstraint]:
    """
    Bind all IDENTITY_DENY constraints to all matching permission edges.
    Returns only non-None bindings.
    """
    identity_deny_constraints = [
        c for c in constraints if c.constraint_type == CONSTRAINT_TYPE_IDENTITY_DENY
    ]
    bindings = []
    for edge in permission_edges:
        for constraint in identity_deny_constraints:
            binding = bind_identity_deny_to_edge(edge, constraint)
            if binding is not None:
                bindings.append(binding)
    return bindings
```

### 4.2 File modified: `iamscope/pipeline.py`

After permission edges are built (currently around line 650, after permission boundary binding):

```python
# --- Identity-deny binding -----------------------------------------------
from iamscope.resolver.identity_deny_binder import (
    build_identity_deny_constraints,
    bind_all_identity_denies,
)
identity_deny_constraints = build_identity_deny_constraints(
    account_data.raw_deny_results   # new field accumulated by collector
)
identity_deny_bindings = bind_all_identity_denies(permission_edges, identity_deny_constraints)
all_constraints.extend(identity_deny_constraints)
all_bindings.extend(identity_deny_bindings)
```

Note: `all_constraints` and `all_bindings` are the lists passed to `FactGraph` construction.
Identity-deny constraints must be in `all_constraints` so `facts.constraint_by_id` resolves them.

---

## 5. Reasoner Layer Changes

### 5.1 Reasoners that need `_check_identity_deny_blockers`

| Reasoner file | Check slot | Action checked |
|---|---|---|
| `assume_role_chain.py` | check 6 (new, after boundary check 5) | `sts:AssumeRole` per hop |
| `passrole_lambda.py` | check 8 (new, after boundary check 7) | `iam:PassRole` + `lambda:CreateFunction` |
| `secrets_blast_radius.py` | check 5 (new, after boundary check 4) | `secretsmanager:GetSecretValue` |
| `iam_group_membership_escalation.py` | new check slot | `iam:AddUserToGroup` + permission edge |
| `inline_policy_escalation.py` | new check slot | `iam:PutUserPolicy` etc. |
| `managed_policy_escalation.py` | new check slot | `iam:AttachUserPolicy` etc. |

**Reasoners NOT receiving this check:**

- `cross_account_trust.py` — operates only on trust-edge bindings; confirmed by code inspection
  (`check 4` comment: "In V1, all bindings on trust edges are SCPs, so we don't filter by constraint_type").
  Identity-deny binds to permission edges only.
- `admin_reachability.py` — no `bindings_for_edge` calls; Phase 2 post-processor
  (`cross_reasoner_consistency.py`) already propagates BLOCKED from `assume_role_chain` via
  `cross_reasoner_blocked` mechanism. Adding a direct check would duplicate propagation and risk
  ordering dependencies.

### 5.2 Method signature (standardized)

Modeled on the existing `_check_boundary_blockers` signature in each reasoner:

```python
def _check_identity_deny_blockers(
    self,
    facts: FactGraph,
    edge: Edge,
    constraint_refs: list[str],
    edge_constraint_refs: list[str],
    action_label: str,           # human-readable: "sts:AssumeRole", "iam:PassRole", etc.
) -> tuple[CheckState, str, list[Blocker]]:
```

`assume_role_chain` variant (consistent with its existing pattern for `_check_boundary_blockers_on_edge`):

```python
def _check_identity_deny_blockers_on_edge(
    self,
    facts: FactGraph,
    edge: Edge,
    constraint_refs: list[str],
    edge_constraint_refs: list[str],
    *,
    hop_index: int,
) -> tuple[CheckState, str, list[Blocker]]:
```

### 5.3 Core logic (shared across all variants)

```python
def _check_identity_deny_blockers(self, facts, edge, constraint_refs, edge_constraint_refs, action_label):
    bindings = facts.bindings_for_edge(edge.edge_id)
    deny_bindings = [
        b for b in bindings
        if facts.constraint_by_id(b.constraint_id) is not None
        and facts.constraint_by_id(b.constraint_id).constraint_type == CONSTRAINT_TYPE_IDENTITY_DENY
    ]

    if not deny_bindings:
        return CheckState.PASS, "", []

    blockers = []
    worst_state = CheckState.PASS

    for b in deny_bindings:
        constraint = facts.constraint_by_id(b.constraint_id)
        confidence = b.governance_confidence   # "complete" | "partial" | "needs_review"

        if confidence == "complete" and b.likely_blocking:
            state = CheckState.FAIL
            reason = (
                f"identity policy Deny on {edge.src.provider_id} "
                f"blocks {action_label}: "
                f"actions={constraint.properties.get('deny_actions')!r}"
            )
        elif confidence in ("partial", "needs_review"):
            state = CheckState.UNKNOWN
            reason = (
                f"identity policy Deny on {edge.src.provider_id} "
                f"may block {action_label} (conservative — conditions present or partial parse): "
                f"actions={constraint.properties.get('deny_actions')!r}"
            )
        else:
            continue   # non-blocking complete binding; skip

        blockers.append(Blocker(
            kind="identity_deny",
            constraint_id=b.constraint_id,
            edge_id=edge.edge_id,
            reason=reason,
        ))

        if state == CheckState.FAIL:
            worst_state = CheckState.FAIL
        elif state == CheckState.UNKNOWN and worst_state != CheckState.FAIL:
            worst_state = CheckState.UNKNOWN

    return worst_state, reason if blockers else "", blockers
```

`CheckState.FAIL` → reasoner emits `blocked`.  
`CheckState.UNKNOWN` → reasoner emits `inconclusive` (existing handling of `UNKNOWN` state).

### 5.4 Per-reasoner integration notes

**`assume_role_chain.py`** — The per-hop loop iterates over edges and calls checks 4 (SCP) and
5 (boundary). Add check 6 immediately after check 5:

```python
# Check 6: identity-deny blockers on this hop
deny_state, deny_reason, deny_blockers = self._check_identity_deny_blockers_on_edge(
    facts, edge, constraint_refs, edge_constraint_refs, hop_index=hop_index
)
if deny_state != CheckState.PASS:
    # merge into existing blocker accumulation pattern
    ...
```

**`passrole_lambda.py`** — Two permission edges (createfunction + passrole). Calls checks 4+5 for
createfunction, 6+7 for passrole. Add check 8 for passrole identity-deny (passrole edge) and
check 9 for createfunction identity-deny. Or: call once per edge after boundary check.

**`secrets_blast_radius.py`** — One permission edge (GetSecretValue edge from source to secret
resource). Add check 5 after boundary check 4.

**`iam_group_membership_escalation.py`**, **`inline_policy_escalation.py`**,
**`managed_policy_escalation.py`** — Each has a permission edge check. Add identity-deny check
immediately following the boundary check.

---

## 6. Test Plan (~59 tests)

### 6.1 Parser layer (~15 tests)

**File:** `tests/parser/test_permission_deny.py` (new)

| Test name | What it verifies |
|---|---|
| `test_plain_deny_single_action` | `Effect:Deny`, one action, `Resource:*` → `parse_status="complete"`, `has_conditions=False` |
| `test_plain_deny_wildcard_action` | `Action:"sts:*"` → stored as-is in `deny_actions` |
| `test_plain_deny_star_action` | `Action:"*"` → `deny_actions=["*"]` |
| `test_plain_deny_multiple_actions` | list of actions → preserved |
| `test_plain_deny_specific_resource` | `Resource: "arn:aws:iam::123:role/foo"` → `resource_patterns` set correctly |
| `test_conditional_deny_has_conditions_true` | Condition block → `has_conditions=True`, `parse_status="complete"` |
| `test_conditional_deny_raw_conditions_preserved` | raw Condition dict round-trips correctly |
| `test_notaction_deny_parse_status_partial` | `NotAction` present → `parse_status="partial"` |
| `test_notresource_deny_parse_status_unsupported` | `NotResource` → `parse_status="unsupported"`, `resource_patterns=["*"]` |
| `test_allow_stmts_skipped` | mixed Allow+Deny → only Deny results returned |
| `test_no_deny_stmts` | policy with only Allow → empty list |
| `test_empty_policy` | `{}` → empty list, no crash |
| `test_sid_used_when_present` | Sid in statement → `statement_id=Sid` |
| `test_auto_sid_generated` | no Sid → `statement_id="_stmt0"` etc. |
| `test_multiple_deny_stmts` | two Deny stmts → two PermissionDenyResult objects |

### 6.2 Resolver layer (~18 tests)

**File:** `tests/resolver/test_identity_deny_binder.py` (new)

#### `build_identity_deny_constraints` (~5 tests)

| Test name | What it verifies |
|---|---|
| `test_complete_unconditional_deny_confidence_q` | `parse_status="complete"`, no conditions → `confidence_q=CONFIDENCE_Q_COMPLETE_BLOCKING` |
| `test_conditional_deny_confidence_q` | `has_conditions=True` → `confidence_q=CONFIDENCE_Q_PARTIAL` |
| `test_partial_parse_confidence_q` | `parse_status="partial"` → `confidence_q=CONFIDENCE_Q_PARTIAL` |
| `test_constraint_type_identity_deny` | `constraint_type=CONSTRAINT_TYPE_IDENTITY_DENY` on all results |
| `test_scope_type_principal` | `scope_type="Principal"`, `scope_id=principal_arn` |

#### `bind_identity_deny_to_edge` (~8 tests)

| Test name | What it verifies |
|---|---|
| `test_matching_action_binds` | action in deny_actions → binding returned |
| `test_wildcard_action_binds` | `deny_actions=["sts:*"]` matches `sts:AssumeRole` |
| `test_star_action_binds` | `deny_actions=["*"]` matches any action |
| `test_non_matching_action_no_bind` | action not in deny_actions → `None` |
| `test_wrong_principal_no_bind` | `scope_id != edge.src.provider_id` → `None` |
| `test_resource_mismatch_no_bind` | `resource_patterns` doesn't match target ARN → `None` |
| `test_conditional_deny_governance_needs_review` | `has_conditions=True` → `governance_confidence="needs_review"`, `likely_blocking=True` |
| `test_complete_deny_governance_complete` | no conditions → `governance_confidence="complete"`, `likely_blocking=True` |

#### `bind_all_identity_denies` (~5 tests)

| Test name | What it verifies |
|---|---|
| `test_no_deny_constraints_returns_empty` | no IDENTITY_DENY constraints → `[]` |
| `test_single_match` | one edge, one matching constraint → one binding |
| `test_multiple_edges_selective_binding` | constraint matches only edges from the denying principal |
| `test_non_identity_deny_constraints_filtered` | SCP, BOUNDARY constraints in list → ignored |
| `test_multiple_deny_stmts_multiple_bindings` | two deny stmts on same principal → two bindings per matching edge |

### 6.3 Reasoner layer (~18 tests)

**File:** `tests/reasoner/test_identity_deny_check.py` (new) for shared logic;
or inline in each reasoner's existing test file.

#### `_check_identity_deny_blockers` core logic (~6 tests)

| Test name | What it verifies |
|---|---|
| `test_no_deny_bindings_returns_pass` | no IDENTITY_DENY bindings → `CheckState.PASS`, empty blockers |
| `test_complete_blocking_returns_fail` | `governance_confidence="complete"`, `likely_blocking=True` → `CheckState.FAIL` |
| `test_conditional_deny_returns_unknown` | `governance_confidence="needs_review"` → `CheckState.UNKNOWN` |
| `test_blocker_kind_identity_deny` | blocker emitted with `kind="identity_deny"` |
| `test_blocker_constraint_id_set` | blocker `constraint_id` matches the constraint |
| `test_non_deny_bindings_ignored` | SCP/boundary bindings on same edge → not picked up by identity-deny check |

#### `assume_role_chain` integration (~4 tests)

| Test name | What it verifies |
|---|---|
| `test_arc_hop_blocked_by_identity_deny` | complete unconditional deny on hop → `verdict=blocked` |
| `test_arc_hop_inconclusive_by_conditional_deny` | conditional deny → `verdict=inconclusive` |
| `test_arc_clean_path_passes` | no deny on path → `verdict=validated` (regression) |
| `test_arc_deny_wrong_principal_no_effect` | deny on different principal → path not blocked |

#### `passrole_lambda` integration (~4 tests)

| Test name | What it verifies |
|---|---|
| `test_prl_passrole_blocked_by_identity_deny` | deny on iam:PassRole edge → finding blocked |
| `test_prl_createfunction_blocked_by_identity_deny` | deny on lambda:CreateFunction edge → finding blocked |
| `test_prl_clean_path_passes` | no deny → validated (regression) |
| `test_prl_conditional_deny_inconclusive` | conditional deny → inconclusive |

#### Other reasoners (~4 tests, one per reasoner)

| Test name | What it verifies |
|---|---|
| `test_sbr_identity_deny_blocks` | `secrets_blast_radius` — deny on GetSecretValue edge → blocked |
| `test_igme_identity_deny_blocks` | `iam_group_membership_escalation` — deny → blocked |
| `test_ipe_identity_deny_blocks` | `inline_policy_escalation` — deny → blocked |
| `test_mpe_identity_deny_blocks` | `managed_policy_escalation` — deny → blocked |

### 6.4 Integration layer (~8 tests)

**File:** `tests/integration/test_identity_deny_pipeline.py` (new)

These tests build a complete scenario via `emit_scenario()` (not hand-crafted dicts) and assert
end-to-end findings.

| Test name | What it verifies |
|---|---|
| `test_pipeline_deny_produces_blocked_finding` | full pipeline: deny on permission edge → `assume_role_chain` blocked finding emitted |
| `test_pipeline_deny_constraint_in_fact_graph` | IDENTITY_DENY constraint appears in `facts.constraint_by_id` |
| `test_pipeline_deny_binding_in_fact_graph` | EdgeConstraint with `constraint_type=IDENTITY_DENY` in `bindings_for_edge` |
| `test_pipeline_conditional_deny_inconclusive` | conditional deny → inconclusive finding |
| `test_pipeline_notaction_deny_conservative` | `parse_status="partial"` → inconclusive, not blocked |
| `test_pipeline_deny_wrong_principal_no_effect` | deny on a *different* principal → findings unaffected |
| `test_pipeline_no_deny_stmts_clean_run` | policy with only Allow → no new blockers, existing tests unaffected |
| `test_binding_metadata_includes_deny_bindings` | `binding_metadata.json` output includes IDENTITY_DENY entries |

---

## 7. Implementation Order and Hold Checkpoints

The implementation follows a strict bottom-up order with explicit review holds between layers.
Each phase ends with `pytest -q` green before the next begins.

### Phase 1 — Constants + Data Model (~30 min)

1. Add `CONSTRAINT_TYPE_IDENTITY_DENY` to `iamscope/constants.py`
2. Add `PermissionDenyResult` dataclass to `iamscope/models.py`
3. Add `permission_deny_constraints: list[Constraint]` field to `AccountData` in
   `iamscope/collector/account.py`
4. Run `pytest -q` — no test changes needed; new field has default value

**HOLD: show diff to operator. Wait for approval before Phase 2.**

### Phase 2 — Parser layer (~1.5-2h)

1. Implement `parse_permission_denies` in `iamscope/parser/permission_policy.py`
2. Add calls to `parse_permission_denies` in collector (wherever `parse_permission_policy` is called)
3. Accumulate results into `AccountData.raw_deny_results` (add that intermediate field too if needed)
4. Write `tests/parser/test_permission_deny.py` (~15 tests)
5. `pytest -q` — green before proceeding

**HOLD: show parser diff + test results. Wait for approval before Phase 3.**

### Phase 3 — Resolver layer (~2h)

1. Create `iamscope/resolver/identity_deny_binder.py` with all functions
2. Wire into `iamscope/pipeline.py` (after permission boundary binding)
3. Write `tests/resolver/test_identity_deny_binder.py` (~18 tests)
4. `pytest -q` — green before proceeding

**HOLD: show resolver diff + test results. Wait for approval before Phase 4.**

### Phase 4a — Reasoners, flat batch (~2-3h)

Implement `_check_identity_deny_blockers` in these 5 reasoners (not `assume_role_chain`):
- `passrole_lambda.py`
- `secrets_blast_radius.py`
- `iam_group_membership_escalation.py`
- `inline_policy_escalation.py`
- `managed_policy_escalation.py`

Write tests for each. `pytest -q` after each reasoner.

**HOLD: show batch diff + test results. Wait for approval before Phase 4b.**

### Phase 4b — `assume_role_chain` (~1h)

`assume_role_chain` has the most complex per-hop loop structure. Separate hold ensures the
additional complexity is reviewed in isolation.

1. Implement `_check_identity_deny_blockers_on_edge` in `assume_role_chain.py`
2. Wire into per-hop loop at check 6
3. Write 4 `assume_role_chain` integration tests
4. `pytest -q`

**HOLD: show diff + test results. Wait for approval before Phase 5.**

### Phase 5 — Integration tests + pipeline wiring verification (~1h)

1. Write `tests/integration/test_identity_deny_pipeline.py` (~8 tests via `emit_scenario()`)
2. Verify `binding_metadata.json` output includes IDENTITY_DENY entries
3. `pytest -q` — full suite must be green (~59 new tests pass, no regressions)
4. `mypy iamscope/` — 0 errors (strict mode maintained since v0.2.39)
5. `ruff check iamscope/ tests/` — 0 lint errors

**HOLD: show full test run output + mypy + ruff. Wait for commit approval.**

### Phase 6 — Changelog + commit

1. Write `v0_3_1-changelog.md`
2. Commit with message: `feat: CC-1 identity-policy Deny fix — explicit deny now creates IDENTITY_DENY constraints`
3. No zip rebuild until operator confirms ship gate satisfied

---

## 8. Estimated Time per Phase

| Phase | Estimate | Notes |
|---|---|---|
| Phase 1 — data model | ~30 min | Mechanical changes, few lines |
| Phase 2 — parser | ~1.5-2h | New function + 15 tests; NotAction/NotResource edge cases |
| Phase 3 — resolver | ~2h | New module + 18 tests; action matching logic |
| Phase 4a — flat reasoners | ~2-3h | 5 reasoners × ~30 min each |
| Phase 4b — assume_role_chain | ~1h | Complex loop; warrants separate attention |
| Phase 5 — integration | ~1h | `emit_scenario()` tests; pipeline wiring verification |
| **Total** | **~8-10h** | Across multiple sessions if needed |

---

## 9. Risks and Unknowns

### R-1: `AccountData` raw_deny_results field name

The field name `raw_deny_results` is tentative. The actual collector code path for populating this
field needs to be confirmed during implementation. The existing pattern for `permission_results`
(how `PermissionParseResult` objects are accumulated per-principal and stored in `AccountData`)
should be followed exactly. Verify the collection loop in `iamscope/collector/account.py` and
`iamscope/cli.py` or wherever collect is orchestrated.

### R-2: Hyperedge / multi-target destination handling

If an edge's `tgt.provider_id` is not a single ARN (e.g., `"*"` or a placeholder), the resource
matching logic `_resource_matches_deny(edge.tgt.provider_id, resource_patterns)` needs to handle
`tgt.provider_id == "*"` conservatively. Decision: if `tgt.provider_id == "*"`, treat as a match
for any non-`"*"` resource pattern (the deny applies). This should be verified against the actual
edge model during implementation.

### R-3: `edge.action` field

The binding logic in `bind_identity_deny_to_edge` requires `edge.action` (the action this
permission edge represents). Confirm that `Edge` objects in the permission edge list always have
a `.action` attribute populated with the specific action (e.g., `"sts:AssumeRole"`), not a
wildcard or list. If action is stored differently, adapt the matching call.

### R-4: Inline policy vs. managed policy `policy_id`

For managed policies, `policy_id` is the policy ARN. For inline policies (user/role/group inline),
there is no ARN. The `PermissionDenyResult` uses a synthetic `policy_id` in this case (e.g.,
`f"inline:{principal_arn}:{policy_name}"`). Ensure `build_identity_deny_constraints` handles both
cases and that the resulting `constraint_id` is deterministic (it's derived from a hash of the
`Constraint` fields; as long as the fields are deterministic, the ID will be too).

### R-5: `governance_confidence` enum enforcement

`EdgeConstraint.governance_confidence` is a closed string enum in the existing codebase.
Confirm the valid values are exactly `{"complete", "partial", "needs_review"}` before implementing.
The Phase 1 design uses `"needs_review"` for conditional denies; verify this value is already
recognized by existing reasoner check methods (it should be, since permission boundary binder
also uses `"needs_review"` for incomplete parses).

### R-6: Regression risk on existing tests

Adding new constraint types to the pipeline means `build_identity_deny_constraints` will be called
on all accounts during `iamscope collect`. In test fixtures that don't include deny statements,
the function returns `[]` and `bind_all_identity_denies` returns `[]` — no effect on existing
edge bindings. Confirm this zero-deny case produces no regressions in the existing 1236-test
baseline.

### R-7: `NotAction` in Deny — conservative treatment

`NotAction` in a Deny statement means "deny everything EXCEPT these actions." The conservative
treatment (`parse_status="partial"`) produces INCONCLUSIVE rather than BLOCKED. This is correct
per the deny-evaluation spec (Section 5: "bias conservative-deny for all 8 patterns"). However,
it may still be too aggressive: a `NotAction: ["sts:*"]` Deny would produce INCONCLUSIVE for
`sts:AssumeRole` even though `sts:AssumeRole` is in the NotAction exclusion list (i.e., it's NOT
denied). Defer correct handling to CC-4. For Phase 1, document this as a known conservative
over-approximation.

---

## 10. Files Modified / Created Summary

| File | Change type | Description |
|---|---|---|
| `iamscope/constants.py` | Modified | Add `CONSTRAINT_TYPE_IDENTITY_DENY` |
| `iamscope/models.py` | Modified | Add `PermissionDenyResult` dataclass |
| `iamscope/collector/account.py` | Modified | Add `permission_deny_constraints` field to `AccountData` |
| `iamscope/parser/permission_policy.py` | Modified | Add `parse_permission_denies` function |
| `iamscope/resolver/identity_deny_binder.py` | **Created** | New binder module |
| `iamscope/pipeline.py` | Modified | Wire identity-deny binding into pipeline |
| `iamscope/reasoner/assume_role_chain.py` | Modified | Add `_check_identity_deny_blockers_on_edge`, check 6 |
| `iamscope/reasoner/passrole_lambda.py` | Modified | Add `_check_identity_deny_blockers`, check 8 |
| `iamscope/reasoner/secrets_blast_radius.py` | Modified | Add `_check_identity_deny_blockers`, check 5 |
| `iamscope/reasoner/iam_group_membership_escalation.py` | Modified | Add `_check_identity_deny_blockers` |
| `iamscope/reasoner/inline_policy_escalation.py` | Modified | Add `_check_identity_deny_blockers` |
| `iamscope/reasoner/managed_policy_escalation.py` | Modified | Add `_check_identity_deny_blockers` |
| `tests/parser/test_permission_deny.py` | **Created** | 15 parser tests |
| `tests/resolver/test_identity_deny_binder.py` | **Created** | 18 resolver tests |
| `tests/reasoner/test_identity_deny_check.py` | **Created** | ~18 reasoner tests |
| `tests/integration/test_identity_deny_pipeline.py` | **Created** | 8 integration tests |

**Not modified:** `cross_account_trust.py`, `admin_reachability.py`, `cross_reasoner_consistency.py`

Total: 8 files modified, 5 files created, ~59 new tests.
