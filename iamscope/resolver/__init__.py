"""IAMScope resolvers — synthetic nodes, cross-account, naked trust, SCP binding, permission boundaries."""

from iamscope.resolver.cross_account import build_trust_edges, resolve_synthetic_nodes
from iamscope.resolver.identity_deny_binder import (
    bind_all_identity_denies,
    bind_identity_deny_to_edge,
    build_identity_deny_constraints,
)
from iamscope.resolver.naked_trust import classify_naked_trust
from iamscope.resolver.permission_boundary import (
    bind_permission_boundaries,
    build_permission_boundary_constraints,
)
from iamscope.resolver.scp_binder import bind_all_scps, bind_scp_to_edge

__all__ = [
    "bind_all_identity_denies",
    "bind_all_scps",
    "bind_permission_boundaries",
    "bind_identity_deny_to_edge",
    "bind_scp_to_edge",
    "build_identity_deny_constraints",
    "build_permission_boundary_constraints",
    "build_trust_edges",
    "classify_naked_trust",
    "resolve_synthetic_nodes",
]
