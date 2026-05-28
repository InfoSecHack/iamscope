"""Noise filter — default include/exclude policy for roles and edges.

Implements architecture doc §3.5 and §10.6:
- Service-linked roles (/aws-service-role/*): EXCLUDE by default
- AWS-managed roles (/aws-reserved/* except SSO): EXCLUDE by default
- SSO roles (/aws-reserved/sso.amazonaws.com/*): INCLUDE by default
- Same-account self-trust edges (src == dst): EXCLUDE by default
- All filters overridable via configuration

All decisions are deterministic: same config + same input → same result.
"""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass, field

from iamscope.constants import (
    DEFAULT_EXCLUDE_AWS_MANAGED,
    DEFAULT_EXCLUDE_SELF_TRUST,
    DEFAULT_EXCLUDE_SERVICE_LINKED,
    DEFAULT_EXCLUDE_SERVICE_PRINCIPALS,
    DEFAULT_INCLUDE_SSO_ROLES,
)


@dataclass(frozen=True)
class NoiseFilter:
    """Configurable noise filter for roles and edges.

    All boolean fields have sensible defaults matching the architecture
    doc. Override via CLI flags or direct construction.
    """

    exclude_service_linked: bool = DEFAULT_EXCLUDE_SERVICE_LINKED
    exclude_aws_managed: bool = DEFAULT_EXCLUDE_AWS_MANAGED
    include_sso_roles: bool = DEFAULT_INCLUDE_SSO_ROLES
    exclude_self_trust: bool = DEFAULT_EXCLUDE_SELF_TRUST
    exclude_service_principals: bool = DEFAULT_EXCLUDE_SERVICE_PRINCIPALS
    max_role_path_depth: int | None = None  # None = no limit
    exclude_accounts: frozenset[str] = field(default_factory=frozenset)
    include_accounts: frozenset[str] = field(default_factory=frozenset)  # empty = all

    def should_include_role(self, role_path: str, role_arn: str = "", account_id: str = "") -> bool:
        """Determine whether a role should be included in the graph.

        Checks path-based filters in priority order:
        1. Account include/exclude lists
        2. SSO role check (include even when aws-managed excluded)
        3. Service-linked role check
        4. AWS-managed role check
        5. Path depth check

        Args:
            role_path: The IAM role path (e.g., "/", "/aws-service-role/...").
            role_arn: The full role ARN (used for account extraction if account_id empty).
            account_id: The account ID this role belongs to.

        Returns:
            True if the role should be included, False if filtered out.
        """
        # Account-level filters first
        if not self._account_included(account_id):
            return False

        # Normalize path for comparison
        path = role_path.lower() if role_path else "/"

        # SSO roles: /aws-reserved/sso.amazonaws.com/* — check BEFORE aws-managed
        if _is_sso_role(path):
            return self.include_sso_roles

        # Service-linked roles: /aws-service-role/*
        if self.exclude_service_linked and _is_service_linked_role(path):
            return False

        # AWS-managed roles: /aws-reserved/* (other than SSO, already handled above)
        if self.exclude_aws_managed and _is_aws_managed_role(path):
            return False

        # Path depth filter
        if self.max_role_path_depth is not None:
            depth = _path_depth(path)
            if depth > self.max_role_path_depth:
                return False

        return True

    def should_include_edge(
        self,
        src_account_id: str,
        dst_account_id: str,
        is_self_trust: bool = False,
    ) -> bool:
        """Determine whether an edge should be included in the graph.

        Args:
            src_account_id: Source principal's account ID.
            dst_account_id: Destination principal's account ID.
            is_self_trust: True if src and dst are the same principal (role trusts itself).

        Returns:
            True if the edge should be included.
        """
        # Self-trust filter (role trusts itself — usually noise)
        if self.exclude_self_trust and is_self_trust:
            return False

        # Account-level filters
        if not self._account_included(src_account_id):
            return False
        return self._account_included(dst_account_id)

    def should_include_service_principal(self) -> bool:
        """Whether service principal nodes (lambda.amazonaws.com, etc.) are included."""
        return not self.exclude_service_principals

    def _account_included(self, account_id: str) -> bool:
        """Check if an account passes include/exclude filters.

        Logic:
        - If include_accounts is non-empty, account MUST be in the set.
        - If exclude_accounts is non-empty, account must NOT be in the set.
        - Both can be set; include takes priority (account must be in include
          AND not in exclude).
          [ASSUMPTION]: include_accounts takes priority if both are set.
        """
        if not account_id:
            return True  # Can't filter without account ID

        if self.include_accounts and account_id not in self.include_accounts:
            return False

        return not (self.exclude_accounts and account_id in self.exclude_accounts)

    def to_filter_fn(self) -> Callable[[str, str, bool], bool]:
        """Return an edge-level callable suitable for `build_trust_edges`.

        NF-1 (S06): the resolver's `noise_filter_fn` parameter expects a
        callable with signature `(src_account, dst_account, is_self) -> bool`
        where True = keep the edge, False = exclude it. `should_include_edge`
        matches that protocol positionally, so we return it as a bound method
        reference. Using an explicit method rather than letting callers pass
        `filter.should_include_edge` directly makes the wire-through contract
        explicit at the filter side.
        """
        return self.should_include_edge

    def to_config_dict(self) -> dict[str, object]:
        """Serialize filter config for metadata output.

        Returns a dict with sorted keys for deterministic JSON.
        """
        return {
            "exclude_accounts": sorted(self.exclude_accounts),
            "exclude_aws_managed": self.exclude_aws_managed,
            "exclude_self_trust": self.exclude_self_trust,
            "exclude_service_linked": self.exclude_service_linked,
            "exclude_service_principals": self.exclude_service_principals,
            "include_accounts": sorted(self.include_accounts),
            "include_sso_roles": self.include_sso_roles,
            "max_role_path_depth": self.max_role_path_depth,
        }


def _is_service_linked_role(path_lower: str) -> bool:
    """Check if path matches /aws-service-role/*."""
    return path_lower.startswith("/aws-service-role/")


def _is_sso_role(path_lower: str) -> bool:
    """Check if path matches /aws-reserved/sso.amazonaws.com/*."""
    return path_lower.startswith("/aws-reserved/sso.amazonaws.com/")


def _is_aws_managed_role(path_lower: str) -> bool:
    """Check if path matches /aws-reserved/* (excluding SSO, handled separately)."""
    return path_lower.startswith("/aws-reserved/")


def _path_depth(path: str) -> int:
    """Count the depth of a role path.

    "/" → 0, "/app/" → 1, "/app/team/" → 2
    """
    stripped = path.strip("/")
    if not stripped:
        return 0
    return stripped.count("/") + 1
