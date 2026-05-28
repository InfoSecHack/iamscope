"""Naked trust classifier — classifies trust relationships by exposure level.

Implements architecture doc §5.8:

Classification hierarchy (most dangerous → least):

CRITICAL_NAKED: Principal: "*" with NO conditions at all.
  Any AWS principal from any account can assume this role.

BROAD_NAKED: Cross-account trust to account root (:root) with
  no meaningful conditions. All principals in that account can assume.
  OR: Wildcard principal WITH some conditions (downgraded from critical).

NARROW_NAKED: Cross-account trust to specific role/user WITH ExternalId
  or source IP/VPC conditions. Still cross-account but partially protected.

CONDITIONED: Cross-account trust with OrgID, MFA, or multiple strong
  conditions. Meaningful protection in place.

INTRA_ACCOUNT: Same-account trust or service principal trust.
  Not a cross-account risk.

All classifications are deterministic: same TrustParseResult → same class.
"""

from __future__ import annotations

from iamscope.constants import (
    NAKED_BROAD,
    NAKED_CONDITIONED,
    NAKED_CRITICAL,
    NAKED_INTRA_ACCOUNT,
    NAKED_NARROW,
    NODE_TYPE_OIDC_PROVIDER,
    TRUST_SCOPE_ACCOUNT_ROOT,
    TRUST_SCOPE_ANY_AWS_PRINCIPAL,
    TRUST_SCOPE_FEDERATED,
    TRUST_SCOPE_SERVICE,
    TRUST_SCOPE_SPECIFIC_ROLE,
    TRUST_SCOPE_SPECIFIC_USER,
)
from iamscope.models import TrustParseResult


def classify_naked_trust(tr: TrustParseResult) -> str:
    """Classify the naked trust exposure level of a trust relationship.

    Args:
        tr: A parsed trust policy result.

    Returns:
        One of: CRITICAL_NAKED, BROAD_NAKED, NARROW_NAKED,
        CONDITIONED, INTRA_ACCOUNT.
    """
    # --- OIDC federated principals: classify by :sub claim ---
    # OIDC trusts are not cross-account in the AWS sense, but an unconditioned
    # OIDC trust (no :sub claim) lets ANY identity from that provider assume
    # the role. This is effectively BROAD_NAKED exposure.
    if tr.resolved_node_type == NODE_TYPE_OIDC_PROVIDER:
        return _classify_oidc_trust(tr)

    # --- Non-cross-account cases → INTRA_ACCOUNT ---
    if not tr.cross_account:
        return NAKED_INTRA_ACCOUNT

    # Service principals are not cross-account risk
    if tr.trust_scope == TRUST_SCOPE_SERVICE:
        return NAKED_INTRA_ACCOUNT

    # Federated SAML principals are not cross-account risk
    # (OIDC is handled above with its own classification)
    if tr.trust_scope == TRUST_SCOPE_FEDERATED:
        return NAKED_INTRA_ACCOUNT

    # --- Cross-account cases: classify by scope + conditions ---
    has_any_condition = _has_any_meaningful_condition(tr)

    # Wildcard principal
    if tr.trust_scope == TRUST_SCOPE_ANY_AWS_PRINCIPAL:
        if not has_any_condition:
            return NAKED_CRITICAL
        # Wildcard with conditions → BROAD (downgraded from critical)
        return NAKED_BROAD

    # Account root (cross-account)
    if tr.trust_scope == TRUST_SCOPE_ACCOUNT_ROOT:
        if not has_any_condition:
            return NAKED_BROAD
        # Account root with strong conditions
        if _has_strong_conditions(tr):
            return NAKED_CONDITIONED
        # Account root with weak conditions
        return NAKED_NARROW

    # Specific role or user (cross-account)
    if tr.trust_scope in (TRUST_SCOPE_SPECIFIC_ROLE, TRUST_SCOPE_SPECIFIC_USER):
        if not has_any_condition:
            return NAKED_NARROW
        if _has_strong_conditions(tr):
            return NAKED_CONDITIONED
        return NAKED_NARROW

    # Fallback — shouldn't reach here, but conservative
    return NAKED_BROAD


def _has_any_meaningful_condition(tr: TrustParseResult) -> bool:
    """Check if any meaningful condition is present."""
    return (
        tr.has_external_id
        or tr.has_source_account_condition
        or tr.has_source_ip_condition
        or tr.has_source_vpc_condition
        or tr.has_org_id_condition
        or tr.has_mfa_condition
    )


def _has_strong_conditions(tr: TrustParseResult) -> bool:
    """Check if strong conditions are present.

    Strong conditions provide meaningful protection:
    - OrgID: restricts to principals within the same organization
    - MFA: requires multi-factor authentication
    - Multiple conditions: defense in depth

    Weak conditions (alone):
    - ExternalId: easy to guess/discover
    - SourceIP: can be spoofed or overly broad
    - SourceAccount: single account restriction
    """
    strong_count = 0
    if tr.has_org_id_condition:
        strong_count += 1
    if tr.has_mfa_condition:
        strong_count += 1

    # Multiple weak conditions together count as strong
    weak_count = 0
    if tr.has_external_id:
        weak_count += 1
    if tr.has_source_ip_condition:
        weak_count += 1
    if tr.has_source_vpc_condition:
        weak_count += 1
    if tr.has_source_account_condition:
        weak_count += 1

    return strong_count >= 1 or weak_count >= 2


def _classify_oidc_trust(tr: TrustParseResult) -> str:
    """Classify OIDC federated trust by :sub claim specificity.

    OIDC trusts are unique: the :sub condition is the primary control.
    Without it, any identity from the OIDC provider can assume the role.

    Classification:
    - No :sub claim at all → BROAD_NAKED (any workflow/identity)
    - :sub is "*" → BROAD_NAKED (explicit wildcard)
    - :sub is a specific pattern → CONDITIONED (restricted)
    """
    sub = tr.oidc_subject_pattern

    if sub is None:
        # No :sub claim — any identity from this OIDC provider can assume
        return NAKED_BROAD

    if sub.strip() == "*":
        # Explicit wildcard :sub — same as no restriction
        return NAKED_BROAD

    # Has a specific :sub pattern — this is meaningful restriction
    # e.g. "repo:MyOrg/MyRepo:ref:refs/heads/main"
    return NAKED_CONDITIONED
