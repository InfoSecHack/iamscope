"""Secrets blast radius reasoner — IAM-layer secret exfiltration analysis.

For each Secrets Manager secret in the fact graph, enumerate the set
of principals that can retrieve its value via `secretsmanager:GetSecretValue`
and emit one finding per (principal, secret) pair. The IAM-layer pass
catches the blast radius at the permission layer; KMS encryption layer
analysis is deferred to v2.

Pattern shape::

    Principal ──secretsmanager:GetSecretValue──> Secret
              (permission edge with Resource: "arn:aws:secretsmanager:...:secret:*")

Secret nodes are created implicitly by the permission policy parser
from resource ARNs in policies that reference `secretsmanager:GetSecretValue`
— there's no active collector step pulling secrets from the AWS API.
This keeps the fact-layer surface small while still catching the
primary blast-radius case.

Verdict mapping:
    All checks PASS                    → validated
    Check 3 FAIL (SCP blocks)          → blocked / info
    Check 4 FAIL (boundary blocks)     → blocked / info
    Check 6 FAIL (KMS blocks decrypt)  → precondition_only / medium
    Check 2 UNKNOWN (wildcard/hyperedge) → inconclusive / medium
    Check 5 FAIL (principal is service or root) → no finding (filtered)

Severity mapping:
    validated + admin-equivalent principal   → critical
    validated + non-admin principal          → high
    inconclusive                             → medium
    blocked                                  → info
    precondition_only (KMS blocks)           → medium

Rationale for severity: a principal reading secrets is the most direct
credential-theft primitive in AWS. An admin-equivalent principal with
this permission is catastrophic because the attacker also controls the
KMS key policy; a non-admin principal with GetSecretValue is still high
severity because secret exfiltration is the shortest path from "has
permission" to "has credentials for another principal."

KMS v2 (priority 4-continued): the reasoner now checks whether the
principal can actually decrypt the secret's encryption key via the KMS
key policy. Three cases:

1. AWS-managed default key (`aws/secretsmanager` or empty KmsKeyId) →
   access is fully gated by IAM, so check 6 PASSes automatically (the
   IAM-layer permission was already verified by checks 1-4).
2. Customer-managed key with account-root delegation ("Principal":
   {"AWS": "arn:...:root"}) → behaves like AWS-managed, check 6
   PASSes.
3. Customer-managed key with specific principal grants → check 6
   evaluates the key policy for the candidate principal. PASS if an
   Allow statement covers the principal + kms:Decrypt action + the
   key's resource with no conditions. UNKNOWN if the matching statement
   has conditions or NotPrincipal/NotAction semantics. FAIL if no
   matching Allow is found.

Check 6 FAIL produces verdict=precondition_only/medium, semantically
identical to "principal has lambda:CreateFunction but target role
doesn't trust Lambda" in passrole_lambda. IAM allows the action but
the enforcement layer (KMS) blocks it, so the chain isn't exploitable
as written.

Check 6 UNKNOWN produces verdict=inconclusive/medium — the reasoner
cannot evaluate the KMS policy with complete confidence and refuses to
guess.

v2 limitations: the reasoner does NOT handle KMS grants (kms:CreateGrant)
and does NOT handle cross-account kms:Decrypt via ExternalId. It has a
narrow KMS-key-policy Deny pre-pass for this decrypt check only: relevant
unconditional Deny statements fail the KMS check, relevant conditional or
Not* Deny statements return UNKNOWN, and irrelevant Deny statements are
ignored. This is not generic RESOURCE_POLICY_DENY scenario support.
Complex cases fall through to UNKNOWN, producing inconclusive findings.
"""

from __future__ import annotations

import fnmatch
import json
import logging
from typing import Any

from iamscope.constants import (
    NODE_TYPE_IAM_ROLE,
    NODE_TYPE_IAM_USER,
    NODE_TYPE_KMS_KEY,
    NODE_TYPE_SECRETS_MANAGER_SECRET,
)
from iamscope.models import Edge, Node
from iamscope.reasoner.admin_detection import is_admin_equivalent
from iamscope.reasoner.evidence import EvidenceBundle, TraceEntry
from iamscope.reasoner.fact_graph import FactGraph
from iamscope.reasoner.identity_deny import check_identity_deny_blockers
from iamscope.reasoner.verdict import (
    Blocker,
    Check,
    CheckState,
    Finding,
    Verdict,
)

logger = logging.getLogger(__name__)


_GET_SECRET_VALUE_ACTION: str = "secretsmanager:GetSecretValue"
_GET_SECRET_VALUE_EDGE_TYPE: str = f"{_GET_SECRET_VALUE_ACTION}_permission"

# AWS-managed default KMS alias for Secrets Manager. Secrets encrypted
# with this key (or no key_id set) delegate access to IAM, so KMS check
# passes automatically — the IAM-layer permission was already verified
# by checks 1-4.
_AWS_MANAGED_SECRETS_ALIAS = "alias/aws/secretsmanager"

# Action constant — the specific IAM action whose presence we're
# probing in the KMS key policy. Statements matching this action
# (directly, via "kms:*", via "*", or via any fnmatch wildcard that
# covers it) are considered relevant to the decrypt decision.
#
# Pre-BUG-009 the evaluator used a frozenset of exact lowercase
# strings ({"kms:decrypt", "kms:*", "*"}) and a set intersection
# to pick relevant statements. That missed less common but valid
# wildcard patterns like "kms:Decr*" and "kms:De*", and was
# inconsistent with how every other part of the codebase matches
# IAM actions (passrole, permission_policy, fact_graph, boundary
# resolver — all fnmatch-based). The v0.2.30 fix unified on
# fnmatch semantics to remove this false-negative source.
_TARGET_DECRYPT_ACTION = "kms:decrypt"


def _kms_policy_allows_decrypt(
    policy_json: str,
    principal_arn: str,
    principal_account_id: str,
    key_arn: str,
) -> tuple[CheckState, str]:
    """Evaluate a KMS key policy for kms:Decrypt access to a principal.

    Returns (state, reason). Handles the three common patterns:

    1. **Account-root delegation** — `Principal: {"AWS": "arn:aws:iam::<account>:root"}`
       grants IAM-based access. If the principal is in the same account,
       the root delegation covers them and we return PASS. This is the
       default policy shape for AWS-managed keys and the most common
       shape for customer-managed keys.

    2. **Specific principal grant** — `Principal: {"AWS": "arn:aws:iam::<account>:user/Alice"}`
       grants access to exactly that principal. Matches if the candidate
       principal_arn equals the grant.

    3. **Wildcard principal** — `Principal: "*"` or `Principal: {"AWS": "*"}`
       grants access to any principal. Returns PASS.

    The evaluator handles:
    - `Statement` as a list or a single dict
    - `Action` as a string or a list
    - `Principal` as `"*"`, a dict with `AWS` key (string or list),
      or a dict with `Service` key (skipped — we evaluate IAM principals)
    - `Resource` as `"*"` or a list containing the key's ARN or `"*"`

    The evaluator does NOT handle:
    - `NotPrincipal`, `NotAction`, `NotResource` (returns UNKNOWN)
    - `Condition` blocks (returns UNKNOWN)
    - `Effect` other than "Allow" or "Deny" (skipped)

    Refuses-to-lie semantics: if the policy has ANY structure the
    evaluator can't handle cleanly (conditions or Not* clauses on a relevant
    Allow/Deny), the return is UNKNOWN with a reason string. Callers should
    treat UNKNOWN as "cannot prove access, defer to reviewer."
    """
    if not policy_json or policy_json.strip() == "":
        return CheckState.UNKNOWN, "empty KMS policy JSON"

    try:
        policy = json.loads(policy_json)
    except (json.JSONDecodeError, ValueError):
        return CheckState.UNKNOWN, "malformed KMS policy JSON"

    if not isinstance(policy, dict):
        return CheckState.UNKNOWN, "KMS policy is not a dict"

    statements = policy.get("Statement", [])
    if isinstance(statements, dict):
        statements = [statements]
    if not isinstance(statements, list):
        return CheckState.UNKNOWN, "KMS policy Statement is not list/dict"

    account_root_arn = f"arn:aws:iam::{principal_account_id}:root"

    # BUG-009b: Deny pre-pass with relevance filtering.
    #
    # Pre-BUG-009b this loop returned UNKNOWN as soon as ANY Deny
    # statement existed in the policy, with the comment "We can't
    # safely evaluate whether a Deny cancels a later Allow." That's
    # true in the fully general case, but overly conservative for
    # the common case — real-world KMS policies routinely contain
    # Deny statements for rotation restrictions, region locks, VPC
    # restrictions, or encrypt-only grants that have nothing to do
    # with decrypt. Any of those would flip the whole evaluation
    # to UNKNOWN → check 6 UNKNOWN → verdict INCONCLUSIVE, producing
    # the same false-inconclusive failure mode as BUG-009 in the
    # Allow loop.
    #
    # The fix is structurally identical to BUG-009: apply relevance
    # filters (Action → Principal → Resource) BEFORE flagging
    # ambiguity, and only treat a Deny as meaningful if it clears
    # all three dimensions on our (principal, kms:Decrypt, key_arn)
    # target.
    #
    # Additional correctness win: a relevant *unconditional* Deny
    # that passes all three relevance filters is a FAIL, not an
    # UNKNOWN — we can affirmatively say the decrypt is blocked.
    # This turns a previous UNKNOWN/INCONCLUSIVE into a correct
    # FAIL/PRECONDITION_ONLY, which is strictly more useful output.
    #
    # Not* clauses on a Deny are a reasoning minefield (a NotAction
    # Deny means "deny everything except these actions" which could
    # trivially include kms:Decrypt without the statement explicitly
    # naming it), so any Deny with a Not* clause falls through to
    # conservative UNKNOWN without attempting the relevance filter.
    for stmt in statements:
        if not isinstance(stmt, dict):
            continue
        if stmt.get("Effect") != "Deny":
            continue

        has_not_action = "NotAction" in stmt
        has_not_principal = "NotPrincipal" in stmt
        has_not_resource = "NotResource" in stmt

        if has_not_action or has_not_principal or has_not_resource:
            return (
                CheckState.UNKNOWN,
                "KMS policy contains Deny with NotPrincipal/NotAction/"
                "NotResource — refuses to guess whether it applies to "
                "target",
            )

        # Relevance phase 1: Action
        actions = stmt.get("Action", [])
        if isinstance(actions, str):
            actions = [actions]
        action_matched = False
        for a in actions:
            if not isinstance(a, str):
                continue
            if fnmatch.fnmatchcase(_TARGET_DECRYPT_ACTION, a.lower()):
                action_matched = True
                break
        if not action_matched:
            continue  # Deny doesn't cover kms:Decrypt — irrelevant

        # Relevance phase 2: Principal
        if not _principal_matches(
            stmt.get("Principal"),
            principal_arn,
            account_root_arn,
        ):
            continue  # Deny doesn't cover our principal — irrelevant

        # Relevance phase 3: Resource
        resources = stmt.get("Resource", [])
        if isinstance(resources, str):
            resources = [resources]
        if not _resource_matches_kms(resources, key_arn):
            continue  # Deny doesn't cover our key — irrelevant

        # At this point the Deny is RELEVANT on all three dimensions.
        # A relevant Deny with a Condition is runtime-dependent —
        # we can't prove whether it will fire at evaluation time,
        # so conservative UNKNOWN. A relevant Deny with NO Condition
        # will definitely fire → affirmative FAIL.
        if stmt.get("Condition"):
            return (
                CheckState.UNKNOWN,
                "KMS policy contains relevant Deny with Condition block — runtime-dependent, refuses to guess",
            )
        return (
            CheckState.FAIL,
            "KMS policy explicit Deny covers principal for kms:Decrypt",
        )

    found_matching_allow = False
    had_ambiguity = False
    ambiguity_reason = ""

    # BUG-009: the relevance filters (Action, Principal, Resource)
    # MUST run before the ambiguity flags (Condition, Not*) are set.
    # The pre-BUG-009 code set `had_ambiguity = True` on ANY Allow
    # statement with a Condition or Not* clause, without first
    # checking whether the statement even applied to our target.
    # A KMS policy containing, say, a conditional Allow for
    # `kms:Encrypt` to some unrelated principal would cause the
    # evaluator to return UNKNOWN when the correct answer was FAIL
    # (no matching Allow for kms:Decrypt). That flipped findings
    # from `check 6 FAIL → PRECONDITION_ONLY` to
    # `check 6 UNKNOWN → INCONCLUSIVE`, making operators manually
    # review blocks that should have been automatic.
    #
    # The fix is to evaluate each statement's relevance to our
    # (principal, kms:Decrypt, key_arn) tuple FIRST, and only then
    # consider ambiguity factors. Irrelevant statements with
    # Conditions or Not* clauses are correctly skipped.
    #
    # Not* clauses complicate relevance checks on their own
    # dimension: we can't enumerate "all things except X" with the
    # matchers available here, so for each Not* clause we skip the
    # corresponding relevance check and fall through to the
    # ambiguity handling below. This is conservative — a statement
    # with NotPrincipal that explicitly excludes our principal is
    # still treated as "ambiguous" rather than correctly "skipped",
    # but over-emitting UNKNOWN is safer than under-emitting FAIL.
    for stmt in statements:
        if not isinstance(stmt, dict):
            continue
        effect = stmt.get("Effect", "")
        if effect != "Allow":
            continue

        has_not_action = "NotAction" in stmt
        has_not_principal = "NotPrincipal" in stmt
        has_not_resource = "NotResource" in stmt

        # Relevance phase 1: Action match. Action match: any action
        # pattern that fnmatch-covers "kms:decrypt" allows decrypt.
        # This includes "kms:Decrypt" (exact), "kms:*", "kms:Decr*",
        # "kms:De*", and "*". IAM action names are case-insensitive,
        # so both sides are lowercased before the fnmatch comparison.
        if not has_not_action:
            actions = stmt.get("Action", [])
            if isinstance(actions, str):
                actions = [actions]
            action_matched = False
            for a in actions:
                if not isinstance(a, str):
                    continue
                if fnmatch.fnmatchcase(_TARGET_DECRYPT_ACTION, a.lower()):
                    action_matched = True
                    break
            if not action_matched:
                continue  # statement doesn't cover kms:Decrypt

        # Relevance phase 2: Principal match. Wildcard, account
        # root, or specific principal (or fnmatch-pattern after
        # the BUG-007 fix).
        if not has_not_principal:
            principal = stmt.get("Principal")
            if not _principal_matches(
                principal,
                principal_arn,
                account_root_arn,
            ):
                continue

        # Relevance phase 3: Resource match. Wildcard or the key's
        # ARN (or fnmatch-pattern after the BUG-008 fix).
        if not has_not_resource:
            resources = stmt.get("Resource", [])
            if isinstance(resources, str):
                resources = [resources]
            if not _resource_matches_kms(resources, key_arn):
                continue

        # At this point the statement is RELEVANT to our target on
        # all three dimensions it was able to evaluate. Now check
        # ambiguity factors: Not* clauses on any dimension, or a
        # Condition block on the statement as a whole.
        if has_not_principal or has_not_action or has_not_resource:
            had_ambiguity = True
            ambiguity_reason = "matching Allow statement uses NotPrincipal/NotAction/NotResource"
            continue
        # Conditions make the statement runtime-dependent → UNKNOWN.
        if stmt.get("Condition"):
            had_ambiguity = True
            ambiguity_reason = "matching Allow statement has Condition block"
            continue

        found_matching_allow = True
        break

    if found_matching_allow:
        return CheckState.PASS, "KMS policy Allow statement covers principal"
    if had_ambiguity:
        return CheckState.UNKNOWN, ambiguity_reason
    return CheckState.FAIL, "no KMS policy Allow statement covers principal"


def _principal_matches(
    principal: Any,
    principal_arn: str,
    account_root_arn: str,
) -> bool:
    """Does the KMS policy Principal field cover principal_arn or its
    account root?

    Pre-BUG-007 this used exact string comparison (`p in (...)`), which
    produced false negatives on extremely common KMS policy patterns
    like `"arn:aws:iam::123456789012:role/*"` (scope access to all
    roles in an account), `"arn:aws:iam::*:role/OrgRole"` (cross-
    account org grants), or `"arn:aws:iam::123456789012:role/prod-*"`
    (scoped by prefix). The fix is to fnmatch the candidate ARN
    against each principal pattern so wildcards are honored.

    IAM principal ARNs are case-sensitive at the resource name level
    (role names, user names), so `fnmatchcase` is used rather than
    `fnmatch` — matching AWS's documented semantics and the rest of
    the iamscope fnmatch-based matchers (passrole, permission_policy,
    permission_boundary, fact_graph).
    """
    if principal == "*":
        return True
    if not isinstance(principal, dict):
        return False
    aws_principals = principal.get("AWS")
    if aws_principals is None:
        return False
    if isinstance(aws_principals, str):
        aws_principals = [aws_principals]
    if not isinstance(aws_principals, list):
        return False
    for p in aws_principals:
        if not isinstance(p, str):
            continue
        # Fast-path for the common exact/literal cases to avoid
        # fnmatch overhead on every call. fnmatchcase with a literal
        # pattern is equivalent to equality, but this is a hot path.
        if p in ("*", principal_arn, account_root_arn):
            return True
        # Wildcard-bearing patterns fall through to fnmatch. Note
        # that a pattern with no wildcards fnmatches as equality,
        # so the fast-path above is an optimization, not a
        # correctness requirement.
        if "*" in p or "?" in p:
            if fnmatch.fnmatchcase(principal_arn, p):
                return True
            if fnmatch.fnmatchcase(account_root_arn, p):
                return True
    return False


def _resource_matches_kms(resources: list, key_arn: str) -> bool:
    """Does the KMS policy Resource field cover the key_arn?

    Pre-BUG-008 this used exact string comparison (`r == "*" or r ==
    key_arn`), missing common patterns like:

    - `"arn:aws:kms:us-east-1:*:key/*"` — cross-account KMS sharing
      boilerplate, extremely common in multi-account orgs
    - `"arn:aws:kms:*:123456789012:key/*"` — all regions, one account
    - `"arn:aws:kms:us-east-1:123456789012:key/abc-*"` — scoped by
      key-ID prefix

    Any of these would have produced a false-negative
    `check 6 FAIL → verdict PRECONDITION_ONLY` when the real KMS
    layer would have permitted the decrypt. The fix is fnmatch-based
    matching, consistent with the rest of the codebase.
    """
    for r in resources:
        if not isinstance(r, str):
            continue
        # Fast-path for literal/exact cases.
        if r == "*" or r == key_arn:
            return True
        # Wildcard-bearing patterns.
        if ("*" in r or "?" in r) and fnmatch.fnmatchcase(key_arn, r):
            return True
    return False


class SecretsBlastRadiusReasoner:
    """IAM-layer blast radius analysis for SecretsManager secrets."""

    pattern_id: str = "secrets_blast_radius"
    pattern_version: str = "1.0.0"
    pattern_title: str = "Secrets Manager Blast Radius"
    severity_default: str = "high"

    def preconditions_met(self, facts: FactGraph) -> tuple[bool, str]:
        """Run only if there are SecretsManagerSecret nodes in the graph."""
        has_secret = any(n.node_type == NODE_TYPE_SECRETS_MANAGER_SECRET for n in facts.nodes)
        if not has_secret:
            return (False, "no SecretsManagerSecret nodes in graph")
        return (True, "")

    def run(self, facts: FactGraph) -> list[Finding]:
        """Enumerate secrets and emit one finding per (principal, secret)."""
        findings: list[Finding] = []

        for secret in facts.nodes:
            if secret.node_type != NODE_TYPE_SECRETS_MANAGER_SECRET:
                continue
            # Walk incoming GetSecretValue permission edges.
            for edge in facts.edges_to(secret.provider_id):
                if edge.edge_type != _GET_SECRET_VALUE_EDGE_TYPE:
                    continue
                principal_node = self._find_node(facts, edge.src.provider_id)
                if principal_node is None:
                    continue
                finding = self._build_finding(
                    facts=facts,
                    principal=principal_node,
                    secret=secret,
                    permission_edge=edge,
                )
                if finding is not None:
                    findings.append(finding)

        # Stable sort: by source provider_id then target provider_id.
        findings.sort(
            key=lambda f: (f.source.provider_id, f.target.provider_id),
        )
        return findings

    # ---------------------------------------------------------------
    # Finding construction
    # ---------------------------------------------------------------

    def _build_finding(
        self,
        *,
        facts: FactGraph,
        principal: Node,
        secret: Node,
        permission_edge: Edge,
    ) -> Finding | None:
        """Evaluate the 5 checks and assemble the Finding."""
        check_results: list[Check] = []
        blockers: list[Blocker] = []
        statement_digests: set[str] = set()
        statement_sources: dict[str, tuple[str, int, str]] = {}
        edge_refs: list[str] = [permission_edge.edge_id]
        constraint_refs: set[str] = set()
        edge_constraint_refs: set[str] = set()
        trace: list[TraceEntry] = []

        self._absorb_digests(permission_edge, statement_digests, statement_sources)

        # ---- Check 5: principal_is_not_service_or_root (early filter)
        # Run FIRST so we can bail out before doing expensive checks.
        check_5_state = (
            CheckState.PASS if principal.node_type in (NODE_TYPE_IAM_USER, NODE_TYPE_IAM_ROLE) else CheckState.FAIL
        )
        if check_5_state is CheckState.FAIL:
            return None  # service principal / root / wildcard — not actionable

        # ---- Check 1: principal_has_get_secret_value_permission
        # By construction (the caller walked this edge) this is always PASS.
        check_1_state = CheckState.PASS
        check_results.append(
            Check(
                name="principal_has_get_secret_value_permission",
                description=("Principal has a permission edge for secretsmanager:GetSecretValue targeting this secret"),
                state=check_1_state,
                evidence_refs=(permission_edge.edge_id,),
                reason="permission edge witnessed",
            )
        )
        trace.append(
            TraceEntry(
                step=1,
                action="check_principal_has_get_secret_value_permission",
                inputs=(principal.provider_id, secret.provider_id),
                result=check_1_state.value.upper(),
                reason="permission edge witnessed",
            )
        )

        # ---- Check 2: permission_edge_targets_clean_witness
        # UNKNOWN if the edge has wildcard resource or hyperedge dst.
        check_2_state = self._classify_witness_edge(permission_edge)
        check_results.append(
            Check(
                name="permission_edge_targets_clean_witness",
                description=(
                    "Permission edge is not a wildcard-resource grant or "
                    "hyperedge dst (clean witness proves the edge's target)"
                ),
                state=check_2_state,
                evidence_refs=(permission_edge.edge_id,),
                reason=(
                    "clean witness edge"
                    if check_2_state is CheckState.PASS
                    else "edge traverses wildcard/hyperedge ambiguity"
                ),
            )
        )
        trace.append(
            TraceEntry(
                step=2,
                action="check_permission_edge_targets_clean_witness",
                inputs=(permission_edge.edge_id,),
                result=check_2_state.value.upper(),
                reason="clean" if check_2_state is CheckState.PASS else "ambiguous",
            )
        )

        # ---- Check 3: no_scp_blocks_get_secret_value
        # Each check gets its own constraint_refs accumulator so the
        # evidence_refs attributed to check 3 are ONLY the SCPs it
        # evaluated, not a contaminated mix of SCPs and boundaries.
        check_3_constraint_refs: set[str] = set()
        check_3_state, check_3_reason, check_3_blockers = self._check_scp_blockers(
            facts,
            permission_edge,
            check_3_constraint_refs,
            edge_constraint_refs,
        )
        blockers.extend(check_3_blockers)
        check_results.append(
            Check(
                name="no_scp_blocks_get_secret_value",
                description=(
                    "No SCP blocks secretsmanager:GetSecretValue on this edge with complete governance confidence"
                ),
                state=check_3_state,
                evidence_refs=(
                    tuple(sorted(check_3_constraint_refs)) if check_3_constraint_refs else (permission_edge.edge_id,)
                ),
                reason=check_3_reason,
            )
        )
        trace.append(
            TraceEntry(
                step=3,
                action="check_no_scp_blocks_get_secret_value",
                inputs=(permission_edge.edge_id,),
                result=check_3_state.value.upper(),
                reason=check_3_reason,
            )
        )
        constraint_refs.update(check_3_constraint_refs)

        # ---- Check 4: no_boundary_blocks_get_secret_value
        check_4_constraint_refs: set[str] = set()
        check_4_state, check_4_reason, check_4_blockers = self._check_boundary_blockers(
            facts,
            permission_edge,
            check_4_constraint_refs,
            edge_constraint_refs,
        )
        blockers.extend(check_4_blockers)
        check_results.append(
            Check(
                name="no_boundary_blocks_get_secret_value",
                description=("No permission boundary blocks secretsmanager:GetSecretValue on this edge"),
                state=check_4_state,
                evidence_refs=(
                    tuple(sorted(check_4_constraint_refs)) if check_4_constraint_refs else (permission_edge.edge_id,)
                ),
                reason=check_4_reason,
            )
        )
        trace.append(
            TraceEntry(
                step=4,
                action="check_no_boundary_blocks_get_secret_value",
                inputs=(permission_edge.edge_id,),
                result=check_4_state.value.upper(),
                reason=check_4_reason,
            )
        )
        constraint_refs.update(check_4_constraint_refs)

        # ---- Check 5: no_identity_deny_blocks_get_secret_value
        check_5_constraint_refs: set[str] = set()
        check_5_state, check_5_reason, check_5_blockers = check_identity_deny_blockers(
            facts,
            permission_edge,
            check_5_constraint_refs,
            edge_constraint_refs,
            action_label="secretsmanager:GetSecretValue",
        )
        blockers.extend(check_5_blockers)
        check_results.append(
            Check(
                name="no_identity_deny_blocks_get_secret_value",
                description=("No identity-policy Deny blocks secretsmanager:GetSecretValue on this edge"),
                state=check_5_state,
                evidence_refs=(
                    tuple(sorted(check_5_constraint_refs)) if check_5_constraint_refs else (permission_edge.edge_id,)
                ),
                reason=check_5_reason,
            )
        )
        trace.append(
            TraceEntry(
                step=5,
                action="check_no_identity_deny_blocks_get_secret_value",
                inputs=(permission_edge.edge_id,),
                result=check_5_state.value.upper(),
                reason=check_5_reason,
            )
        )
        constraint_refs.update(check_5_constraint_refs)

        # ---- Check 6: kms_key_policy_allows_decrypt_for_principal
        # v2 KMS layer check. See module docstring for the three cases
        # (AWS-managed default, account-root delegation, specific grant).
        check_6_state, check_6_reason, check_6_kms_node_id = self._check_kms_decrypt_allowed(facts, principal, secret)
        if check_6_kms_node_id is not None:
            node_refs_set = {principal.node_id, secret.node_id, check_6_kms_node_id}
        else:
            node_refs_set = {principal.node_id, secret.node_id}
        # Check 6 FAIL means KMS blocks the decrypt path → record a
        # blocker for the PRECONDITION_ONLY verdict invariant. The
        # Finding validator requires blockers_observed to be non-empty
        # for PRECONDITION_ONLY findings.
        if check_6_state is CheckState.FAIL:
            blockers.append(
                Blocker(
                    kind="kms_key_policy",
                    constraint_id=check_6_kms_node_id or "kms_unknown",
                    edge_id=permission_edge.edge_id,
                    reason=check_6_reason,
                )
            )
        check_results.append(
            Check(
                name="kms_key_policy_allows_decrypt_for_principal",
                description=(
                    "KMS key policy on the secret's encryption key allows "
                    "kms:Decrypt for the candidate principal (or the secret "
                    "uses the AWS-managed default key which delegates to IAM)"
                ),
                state=check_6_state,
                evidence_refs=(permission_edge.edge_id,),
                reason=check_6_reason,
            )
        )
        trace.append(
            TraceEntry(
                step=6,
                action="check_kms_key_policy_allows_decrypt",
                inputs=(principal.provider_id, secret.provider_id),
                result=check_6_state.value.upper(),
                reason=check_6_reason,
            )
        )

        # ---- Verdict + severity
        is_admin = is_admin_equivalent(facts, principal)
        verdict, severity, exit_reason = self._compute_verdict_and_severity(
            check_results,
            is_admin=is_admin,
        )
        if verdict is None:
            return None

        title = self._compose_title(principal, secret, verdict, is_admin)

        evidence = EvidenceBundle(
            statement_digests=tuple(sorted(statement_digests)),
            statement_sources=dict(statement_sources),
            edge_refs=tuple(edge_refs),
            constraint_refs=tuple(sorted(constraint_refs)),
            edge_constraint_refs=tuple(sorted(edge_constraint_refs)),
            node_refs=tuple(sorted(node_refs_set)),
            condition_context_assumed=(),
            reasoning_trace=tuple(trace),
        )

        return Finding(
            pattern_id=self.pattern_id,
            pattern_version=self.pattern_version,
            source=principal.to_ref(),
            target=secret.to_ref(),
            verdict=verdict,
            severity=severity,
            title=title,
            required_checks=tuple(check_results),
            blockers_observed=tuple(blockers),
            assumptions=(),
            evidence=evidence,
            scenario_hash=facts.scenario_hash,
            reasoner_exit_reason=exit_reason,
        )

    # ---------------------------------------------------------------
    # Helpers
    # ---------------------------------------------------------------

    def _find_node(self, facts: FactGraph, provider_id: str) -> Node | None:
        return facts.node_by_provider_id(provider_id)

    def _classify_witness_edge(self, edge: Edge) -> CheckState:
        """PASS if the edge is clean, UNKNOWN if wildcard/hyperedge."""
        from iamscope.reasoner.fact_graph import _is_unknown_witness

        if _is_unknown_witness(edge):
            return CheckState.UNKNOWN
        return CheckState.PASS

    def _check_scp_blockers(
        self,
        facts: FactGraph,
        edge: Edge,
        constraint_refs: set[str],
        edge_constraint_refs: set[str],
    ) -> tuple[CheckState, str, list[Blocker]]:
        """Check for SCP blockers on the GetSecretValue edge."""
        blockers: list[Blocker] = []
        state = CheckState.PASS
        reason = "no SCP bindings observed"

        for binding in facts.bindings_for_edge(edge.edge_id):
            if not binding.likely_blocking:
                continue
            constraint = facts.constraint_by_id(binding.constraint_id)
            if constraint is None or constraint.constraint_type != "SCP":
                continue
            edge_constraint_refs.add(f"{binding.edge_id}:{binding.constraint_id}")
            constraint_refs.add(binding.constraint_id)
            confidence = binding.governance_confidence
            if confidence == "complete":
                blockers.append(
                    Blocker(
                        kind="scp",
                        constraint_id=binding.constraint_id,
                        edge_id=binding.edge_id,
                        reason=binding.binding_reason or "SCP denies GetSecretValue",
                    )
                )
                state = CheckState.FAIL
                reason = f"SCP {binding.constraint_id} blocks (complete)"
                break
            elif confidence in ("partial", "needs_review"):
                if state is CheckState.PASS:
                    state = CheckState.UNKNOWN
                    reason = f"SCP {binding.constraint_id} ambiguous ({confidence})"
        return state, reason, blockers

    def _check_boundary_blockers(
        self,
        facts: FactGraph,
        edge: Edge,
        constraint_refs: set[str],
        edge_constraint_refs: set[str],
    ) -> tuple[CheckState, str, list[Blocker]]:
        """Check for permission boundary blockers on the GetSecretValue edge."""
        blockers: list[Blocker] = []
        state = CheckState.PASS
        reason = "no permission boundary bindings observed"

        for binding in facts.bindings_for_edge(edge.edge_id):
            if not binding.likely_blocking:
                continue
            constraint = facts.constraint_by_id(binding.constraint_id)
            if constraint is None or constraint.constraint_type != "PERMISSION_BOUNDARY":
                continue
            edge_constraint_refs.add(f"{binding.edge_id}:{binding.constraint_id}")
            constraint_refs.add(binding.constraint_id)
            confidence = binding.governance_confidence
            if confidence == "complete":
                blockers.append(
                    Blocker(
                        kind="permission_boundary",
                        constraint_id=binding.constraint_id,
                        edge_id=binding.edge_id,
                        reason=binding.binding_reason or "boundary blocks GetSecretValue",
                    )
                )
                state = CheckState.FAIL
                reason = f"boundary {binding.constraint_id} blocks (complete)"
                break
            elif confidence in ("partial", "needs_review"):
                if state is CheckState.PASS:
                    state = CheckState.UNKNOWN
                    reason = f"boundary {binding.constraint_id} ambiguous ({confidence})"
        return state, reason, blockers

    def _check_kms_decrypt_allowed(
        self,
        facts: FactGraph,
        principal: Node,
        secret: Node,
    ) -> tuple[CheckState, str, str | None]:
        """Evaluate the KMS layer for a (principal, secret) pair.

        Returns (state, reason, kms_node_id). The kms_node_id is the
        fact-graph node_id of the KMSKey used to encrypt the secret,
        or None if:
        - The secret has no kms_key_id (AWS-managed default)
        - The KMSKey node isn't in the fact graph (collector disabled)
        - The kms_key_id is the AWS-managed alias

        Semantics:
        - AWS-managed default key (empty kms_key_id or alias) → PASS
          automatically; the IAM layer already gates access.
        - CMK with matching KMSKey node in graph → delegate to the
          policy evaluator.
        - CMK with NO matching KMSKey node → UNKNOWN (can't verify).
        """
        # BUG-023: dangling-reference secrets (referenced by IAM policy
        # but not returned by collection — canonical case is RDS-managed
        # `rds!` secrets which are owned by the RDS service and hidden
        # from ListSecrets) produce SYNTHETIC target nodes with no
        # kms_key_id, which would otherwise flow through the
        # "AWS-managed default → PASS" path below and produce over-
        # confident VALIDATED verdicts. Intercept them here and return
        # UNKNOWN so verdict Rule 4 demotes the finding to INCONCLUSIVE.
        # The operator still sees the finding (the IAM grant IS real
        # and worth investigating) but with a clear reason string that
        # the target wasn't in the collected graph.
        if secret.properties.get("is_dangling_reference", False):
            return (
                CheckState.UNKNOWN,
                (
                    "secret is a dangling reference — referenced by "
                    "IAM policy but not returned by collection. "
                    "Target may be a restricted resource (e.g. rds! "
                    "managed secret owned by the RDS service), in an "
                    "unscanned region, in another account, or deleted. "
                    "Cannot verify KMS-layer decrypt access on an "
                    "uncollected target."
                ),
                None,
            )

        secret_kms_key_id = secret.properties.get("kms_key_id", "") or ""
        # AWS-managed default: empty string or the aws/secretsmanager alias
        if not secret_kms_key_id or secret_kms_key_id == _AWS_MANAGED_SECRETS_ALIAS:
            return (
                CheckState.PASS,
                "secret uses AWS-managed default KMS key (delegates to IAM)",
                None,
            )

        # Find the KMSKey node in the fact graph. Fast path: O(1)
        # lookup by provider_id via the FactGraph index. Slow path:
        # O(N) scan across KMS nodes if the secret cites a key_id
        # (short form, not an ARN) that matches a KMSKey node's
        # `key_id` property rather than its provider_id.
        kms_node: Node | None = facts.node_by_provider_id(secret_kms_key_id)
        if kms_node is not None and kms_node.node_type != NODE_TYPE_KMS_KEY:
            kms_node = None
        if kms_node is None:
            for node in facts.nodes:
                if node.node_type != NODE_TYPE_KMS_KEY:
                    continue
                if node.properties.get("key_id") == secret_kms_key_id:
                    kms_node = node
                    break

        if kms_node is None:
            return (
                CheckState.UNKNOWN,
                f"secret's KMS key {secret_kms_key_id} not in fact graph",
                None,
            )

        # BUG-013b: check the collector's `kms_policy_fetch_failed`
        # marker BEFORE evaluating the policy. An empty `key_policy`
        # string on a CMK could mean either "the customer set no
        # policy" (weird, investigate the key) or "our GetKeyPolicy
        # call failed during collection" (investigate collector IAM).
        # Those are operationally very different, and the previous
        # reasoner behavior collapsed both into a single UNKNOWN with
        # reason "empty KMS policy JSON", forcing the operator to
        # debug backwards. Distinguishing them at this point lets
        # findings explanation text tell the operator exactly what
        # to do next. Verdict is still INCONCLUSIVE (check UNKNOWN
        # flows through verdict Rule 4 unchanged), but the reason
        # string is actionable.
        if kms_node.properties.get("kms_policy_fetch_failed", False):
            return (
                CheckState.UNKNOWN,
                (
                    "KMS key policy fetch failed during collection "
                    "(GetKeyPolicy call raised) — cannot evaluate "
                    "decrypt access. Check collector IAM permissions "
                    "for kms:GetKeyPolicy on this key."
                ),
                kms_node.node_id,
            )

        # Read the stored policy and evaluate
        policy_json = kms_node.properties.get("key_policy", "") or ""
        principal_account_id = principal.properties.get("account_id", "") or ""
        state, reason = _kms_policy_allows_decrypt(
            policy_json=policy_json,
            principal_arn=principal.provider_id,
            principal_account_id=principal_account_id,
            key_arn=kms_node.provider_id,
        )
        return (state, reason, kms_node.node_id)

    def _compute_verdict_and_severity(
        self,
        check_results: list[Check],
        *,
        is_admin: bool,
    ) -> tuple[Verdict | None, str, str]:
        """Apply verdict mapping rules."""
        check_by_name = {c.name: c for c in check_results}
        check_2 = check_by_name["permission_edge_targets_clean_witness"]
        check_3 = check_by_name["no_scp_blocks_get_secret_value"]
        check_4 = check_by_name["no_boundary_blocks_get_secret_value"]
        check_5 = check_by_name["no_identity_deny_blocks_get_secret_value"]
        check_6 = check_by_name.get("kms_key_policy_allows_decrypt_for_principal")

        # Rule 1: SCP blocks with complete confidence → blocked
        if check_3.state is CheckState.FAIL:
            return (Verdict.BLOCKED, "info", "SCP blocks secretsmanager:GetSecretValue")

        # Rule 2: Boundary blocks with complete confidence → blocked
        if check_4.state is CheckState.FAIL:
            return (Verdict.BLOCKED, "info", "permission boundary blocks secretsmanager:GetSecretValue")

        # Rule 2.5: Identity policy Deny blocks with complete confidence -> blocked
        if check_5.state is CheckState.FAIL:
            return (
                Verdict.BLOCKED,
                "info",
                "identity policy Deny blocks secretsmanager:GetSecretValue",
            )

        # Rule 2.6 (v2): KMS key policy blocks kms:Decrypt → precondition_only / medium
        # The principal has the IAM permission but cannot actually use it
        # because the KMS enforcement layer gates key decryption. Semantically
        # identical to "principal has lambda:CreateFunction but target role
        # doesn't trust Lambda" → precondition_only.
        if check_6 is not None and check_6.state is CheckState.FAIL:
            return (
                Verdict.PRECONDITION_ONLY,
                "medium",
                "KMS key policy does not allow kms:Decrypt for principal",
            )

        # Rule 3: Check 2 UNKNOWN (wildcard/hyperedge) → inconclusive / medium
        if check_2.state is CheckState.UNKNOWN:
            return (
                Verdict.INCONCLUSIVE,
                "medium",
                "permission edge has wildcard resource or hyperedge dst",
            )

        # Rule 4: Any remaining UNKNOWN check (SCP, boundary, KMS) →
        # inconclusive / medium. Scans the full check_results for any
        # UNKNOWN state to catch both the pre-v2 cases (check 3/4) and
        # the v2 KMS case (check 6) in one pass.
        unknown = [c.name for c in check_results if c.state is CheckState.UNKNOWN]
        if unknown:
            return (
                Verdict.INCONCLUSIVE,
                "medium",
                f"check(s) UNKNOWN: {', '.join(unknown)}",
            )

        # Rule 5: all clean → validated, severity from principal admin status
        severity = "critical" if is_admin else "high"
        return (
            Verdict.VALIDATED,
            severity,
            f"all checks PASS; principal is {'admin-equivalent' if is_admin else 'non-admin'}",
        )

    def _compose_title(
        self,
        principal: Node,
        secret: Node,
        verdict: Verdict,
        is_admin: bool,
    ) -> str:
        verdict_label = {
            Verdict.VALIDATED: "Validated",
            Verdict.BLOCKED: "Blocked",
            Verdict.INCONCLUSIVE: "Inconclusive",
            Verdict.PRECONDITION_ONLY: "Precondition-only",
        }.get(verdict, "Unknown")
        admin_tag = " (admin-equivalent)" if is_admin and verdict == Verdict.VALIDATED else ""
        return (
            f"{verdict_label} secret read: "
            f"{principal.provider_id}{admin_tag} can call "
            f"secretsmanager:GetSecretValue on {secret.provider_id}"
        )

    def _absorb_digests(
        self,
        edge: Edge,
        digests: set[str],
        sources: dict[str, tuple[str, int, str]],
    ) -> None:
        for ref in (edge.features or {}).get("allow_controls", []) or []:
            if isinstance(ref, dict):
                digest = ref.get("digest", "")
                if digest:
                    digests.add(digest)
                    sources[digest] = (
                        ref.get("policy_arn", ""),
                        int(ref.get("statement_index", 0)),
                        ref.get("summary", ""),
                    )
