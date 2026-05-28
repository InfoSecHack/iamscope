"""Cross-account resolver — synthetic node creation and trust edge building.

Implements architecture doc §5.3, §5.6:
- Creates synthetic nodes for principals referenced in trust policies
  but not directly collected (account roots, wildcard, services, federation)
- Builds _trust edges from TrustParseResult objects
- Deduplicates synthetic nodes by (provider, node_type, provider_id)

Synthetic node types:
- AccountPrincipalSet: Represents all principals in an account (arn:...:root)
- WildcardPrincipal: Represents Principal: "*" (any AWS principal)
- AWSService: Represents a service principal (lambda.amazonaws.com, etc.)
- SAMLProvider: Represents a SAML federation provider
- OIDCProvider: Represents an OIDC federation provider
- ExternalAccount: Represents an unrecognized external principal

All operations are deterministic: same inputs → same outputs.
"""

from __future__ import annotations

from typing import Any

from iamscope.constants import (
    EDGE_LAYER_TRUST,
    NODE_TYPE_ACCOUNT_ROOT,
    NODE_TYPE_AWS_SERVICE,
    NODE_TYPE_EXTERNAL_ACCOUNT,
    NODE_TYPE_IAM_ROLE,
    NODE_TYPE_IAM_USER,
    NODE_TYPE_OIDC_PROVIDER,
    NODE_TYPE_SAML_PROVIDER,
    NODE_TYPE_WILDCARD_PRINCIPAL,
    PROVIDER_AWS,
    REGION_GLOBAL,
)
from iamscope.models import ControlRef, Edge, Node, NodeRef, TrustParseResult
from iamscope.resolver.naked_trust import classify_naked_trust


def resolve_synthetic_nodes(
    trust_results: list[TrustParseResult],
    known_account_ids: set[str] | None = None,
) -> list[Node]:
    """Create synthetic nodes for principals referenced in trust policies.

    Deduplicates by (provider, node_type, provider_id). Each unique
    principal produces exactly one synthetic node.

    Args:
        trust_results: Parsed trust policy results from all roles.
        known_account_ids: Account IDs collected in this run (used to
                          mark external vs. internal accounts).

    Returns:
        Sorted list of deduplicated synthetic Node objects.
    """
    known = known_account_ids or set()
    seen: dict[tuple[str, str, str], Node] = {}

    for tr in trust_results:
        key = (PROVIDER_AWS, tr.resolved_node_type, tr.principal_value)

        if key in seen:
            continue

        node = _create_synthetic_node(tr, known)
        if node is not None:
            seen[key] = node

    # Return sorted by node_id for determinism
    return sorted(seen.values(), key=lambda n: n.node_id)


def _create_synthetic_node(
    tr: TrustParseResult,
    known_account_ids: set[str],
) -> Node | None:
    """Create a single synthetic node from a trust parse result.

    Returns None if the principal type doesn't need a synthetic node
    (e.g., IAMRole/IAMUser that will be collected directly).
    """
    node_type = tr.resolved_node_type
    provider_id = tr.principal_value
    properties: dict[str, Any] = {"is_synthetic": True}

    if node_type == NODE_TYPE_WILDCARD_PRINCIPAL:
        properties["description"] = "Any AWS principal (Principal: *)"
        properties["org_member"] = False
        return Node(
            provider=PROVIDER_AWS,
            node_type=NODE_TYPE_WILDCARD_PRINCIPAL,
            provider_id="*",
            region=REGION_GLOBAL,
            properties=properties,
        )

    if node_type == NODE_TYPE_ACCOUNT_ROOT:
        account_id = _extract_account_from_arn(provider_id)
        is_org_member = account_id in known_account_ids if account_id else False
        properties["account_id"] = account_id or ""
        properties["is_external"] = not is_org_member
        properties["org_member"] = is_org_member
        return Node(
            provider=PROVIDER_AWS,
            node_type=NODE_TYPE_ACCOUNT_ROOT,
            provider_id=provider_id,
            region=REGION_GLOBAL,
            properties=properties,
        )

    if node_type == NODE_TYPE_AWS_SERVICE:
        properties["service_name"] = provider_id
        return Node(
            provider=PROVIDER_AWS,
            node_type=NODE_TYPE_AWS_SERVICE,
            provider_id=provider_id,
            region=REGION_GLOBAL,
            properties=properties,
        )

    if node_type == NODE_TYPE_SAML_PROVIDER:
        properties["provider_arn"] = provider_id
        return Node(
            provider=PROVIDER_AWS,
            node_type=NODE_TYPE_SAML_PROVIDER,
            provider_id=provider_id,
            region=REGION_GLOBAL,
            properties=properties,
        )

    if node_type == NODE_TYPE_OIDC_PROVIDER:
        properties["provider_url"] = provider_id
        return Node(
            provider=PROVIDER_AWS,
            node_type=NODE_TYPE_OIDC_PROVIDER,
            provider_id=provider_id,
            region=REGION_GLOBAL,
            properties=properties,
        )

    if node_type == NODE_TYPE_EXTERNAL_ACCOUNT:
        properties["raw_principal"] = provider_id
        properties["org_member"] = False
        return Node(
            provider=PROVIDER_AWS,
            node_type=NODE_TYPE_EXTERNAL_ACCOUNT,
            provider_id=provider_id,
            region=REGION_GLOBAL,
            properties=properties,
        )

    # IAMRole and IAMUser are collected directly — create synthetic only
    # if the principal is cross-account (won't be in our collection)
    if node_type in (NODE_TYPE_IAM_ROLE, NODE_TYPE_IAM_USER):
        if tr.cross_account:
            account_id = _extract_account_from_arn(provider_id)
            is_org_member = account_id in known_account_ids if account_id else False
            properties["account_id"] = account_id or ""
            properties["is_external"] = not is_org_member
            properties["org_member"] = is_org_member
            return Node(
                provider=PROVIDER_AWS,
                node_type=node_type,
                provider_id=provider_id,
                region=REGION_GLOBAL,
                properties=properties,
            )
        # Same-account IAMRole/User — will be collected, no synthetic needed
        return None

    return None


def build_trust_edges(
    trust_results: list[TrustParseResult],
    role_node: Node,
    noise_filter_fn: Any | None = None,
) -> list[Edge]:
    """Build _trust edges from parsed trust policy results.

    Each TrustParseResult produces one Edge with:
    - src: the trusting principal (account root, wildcard, service, etc.)
    - dst: the role being trusted (role_node)
    - edge_type: "{action}_{EDGE_LAYER_TRUST}" (e.g., "sts:AssumeRole_trust")
    - features: naked trust classification and condition flags

    Args:
        trust_results: Parsed trust results for a single role.
        role_node: The Node object for the role being trusted.
        noise_filter_fn: Optional callable (src_account, dst_account, is_self) → bool.
                        If provided, edges failing the filter are excluded.

    Returns:
        List of Edge objects, ordered by input order (deterministic if
        trust_results are ordered).
    """
    edges: list[Edge] = []
    role_account = role_node.properties.get("account_id", "")

    for tr in trust_results:
        # Build source NodeRef
        src_ref = NodeRef(
            provider=PROVIDER_AWS,
            node_type=tr.resolved_node_type,
            provider_id=tr.principal_value,
            region=REGION_GLOBAL,
        )

        # Build edge type
        edge_type = f"{tr.action}_{EDGE_LAYER_TRUST}"

        # Classify naked trust
        naked_class = classify_naked_trust(tr)

        # Check noise filter
        if noise_filter_fn is not None:
            src_account = _extract_account_from_arn(tr.principal_value) or ""
            is_self = src_ref.provider_id == role_node.provider_id
            if not noise_filter_fn(src_account, role_account, is_self):
                continue

        # Build features dict — provenance for investigation
        features: dict[str, Any] = {
            # DIG-1 (S05): ControlRef evidence attribution. Single-item list
            # because one trust edge comes from one statement. A reasoner can
            # cite `allow_controls[0]["digest"]` as proof the finding references
            # an auditable policy statement the client can verify themselves.
            "allow_controls": [
                ControlRef(
                    control_type="TRUST",
                    policy_arn=role_node.provider_id,
                    statement_index=tr.statement_index,
                    digest=tr.statement_digest,
                    summary=f"trust policy for {role_node.provider_id}",
                ).to_dict()
            ],
            "cross_account": tr.cross_account,
            "effect": tr.effect,
            "has_conditions": bool(tr.raw_conditions),
            "has_external_id": tr.has_external_id,
            "has_mfa_condition": tr.has_mfa_condition,
            "has_org_id_condition": tr.has_org_id_condition,
            "has_source_account_condition": tr.has_source_account_condition,
            "has_source_ip_condition": tr.has_source_ip_condition,
            "has_source_vpc_condition": tr.has_source_vpc_condition,
            "is_wildcard_principal": tr.principal_value == "*",
            "layer": EDGE_LAYER_TRUST,
            "naked_trust": naked_class,
            "oidc_subject_pattern": tr.oidc_subject_pattern,
            "principal_type": tr.principal_type,
            "raw_conditions": tr.raw_conditions,
            "source_policy": "TrustPolicy",
            "statement_index": tr.statement_index,
            "trust_scope": tr.trust_scope,
        }

        edge = Edge(
            edge_type=edge_type,
            src=src_ref,
            dst=role_node.to_ref(),
            region=REGION_GLOBAL,
            features=features,
        )
        edges.append(edge)

    return edges


def _extract_account_from_arn(arn: str) -> str | None:
    """Extract 12-digit account ID from an ARN.

    Returns None if the ARN doesn't contain an account ID.
    """
    if not arn or arn == "*":
        return None
    parts = arn.split(":")
    if len(parts) >= 5 and len(parts[4]) == 12 and parts[4].isdigit():
        return parts[4]
    return None
