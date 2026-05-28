"""Expansion controller — graph explosion controls with hard limits.

Implements architecture doc Decision 5:
- Global --expansion-mode {warn, skip, expand} applies to all edge types
- Type-specific overrides (--passrole-mode, --lambda-mode, --ec2-mode)
  take precedence over the global setting
- Hard limits (non-overridable):
  - MAX_EDGES_PER_EXPANSION = 500: if a single expansion would produce
    >500 edges, force warn mode regardless of setting
  - MAX_TOTAL_EDGES = 100,000: abort with error if total exceeds this

All decisions are deterministic: same config + same counts → same result.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field

from iamscope.constants import (
    EXPANSION_MODE_EXPAND,
    EXPANSION_MODE_SKIP,
    EXPANSION_MODE_WARN,
    MAX_EDGES_PER_EXPANSION,
    MAX_TOTAL_EDGES,
)

logger = logging.getLogger(__name__)


class TotalEdgeLimitError(Exception):
    """Raised when the total edge count exceeds MAX_TOTAL_EDGES."""

    def __init__(self, current_count: int, limit: int = MAX_TOTAL_EDGES) -> None:
        self.current_count = current_count
        self.limit = limit
        super().__init__(
            f"Total edge count ({current_count}) exceeds hard limit ({limit}). Aborting to prevent graph explosion."
        )


@dataclass
class ExpansionController:
    """Controls graph expansion behavior for cross-service edge types.

    Attributes:
        global_mode: Default expansion mode for all edge types.
        passrole_mode: Override for iam:PassRole edges (None = use global).
        lambda_mode: Override for lambda:InvokeFunction edges (None = use global).
        ec2_mode: Override for ec2:InstanceProfile edges (None = use global).
    """

    global_mode: str = EXPANSION_MODE_WARN
    passrole_mode: str | None = None
    lambda_mode: str | None = None
    ec2_mode: str | None = None

    # Internal edge counter for total limit enforcement
    _total_edges: int = field(default=0, repr=False, compare=False)

    def __post_init__(self) -> None:
        """Validate mode values."""
        valid = {EXPANSION_MODE_WARN, EXPANSION_MODE_SKIP, EXPANSION_MODE_EXPAND}
        if self.global_mode not in valid:
            raise ValueError(f"Invalid global_mode: {self.global_mode!r}. Must be one of {valid}")
        for name, mode in [
            ("passrole_mode", self.passrole_mode),
            ("lambda_mode", self.lambda_mode),
            ("ec2_mode", self.ec2_mode),
        ]:
            if mode is not None and mode not in valid:
                raise ValueError(f"Invalid {name}: {mode!r}. Must be one of {valid}")

    def get_mode(self, edge_type: str) -> str:
        """Get the effective expansion mode for an edge type.

        Type-specific overrides take precedence over the global mode.

        Args:
            edge_type: The edge type string (e.g., "iam:PassRole_permission").

        Returns:
            The effective mode: "warn", "skip", or "expand".
        """
        # Check type-specific overrides
        edge_lower = edge_type.lower()

        if "passrole" in edge_lower and self.passrole_mode is not None:
            return self.passrole_mode

        if "lambda" in edge_lower and self.lambda_mode is not None:
            return self.lambda_mode

        if ("ec2" in edge_lower or "instanceprofile" in edge_lower) and self.ec2_mode is not None:
            return self.ec2_mode

        return self.global_mode

    def check_expansion(self, expansion_count: int, edge_type: str) -> tuple[str, list[str]]:
        """Determine the effective mode for an expansion, applying hard limits.

        If the configured mode is "expand" but expansion_count > MAX_EDGES_PER_EXPANSION,
        the mode is forced to "warn" regardless of configuration.

        Args:
            expansion_count: Number of edges this expansion would produce.
            edge_type: The edge type being expanded.

        Returns:
            Tuple of (effective_mode, warnings).
            - effective_mode: The mode to use ("warn", "skip", or "expand").
            - warnings: List of warning strings (e.g., hard limit forced warn).
        """
        warnings: list[str] = []
        configured_mode = self.get_mode(edge_type)

        # Hard limit: >500 per expansion forces warn
        if configured_mode == EXPANSION_MODE_EXPAND and expansion_count > MAX_EDGES_PER_EXPANSION:
            warnings.append(
                f"Expansion of {edge_type} would produce {expansion_count} edges "
                f"(> hard limit {MAX_EDGES_PER_EXPANSION}). Forcing warn mode."
            )
            logger.warning(warnings[-1])
            return EXPANSION_MODE_WARN, warnings

        return configured_mode, warnings

    def register_edges(self, count: int) -> None:
        """Register edges being added to the graph and check total limit.

        Must be called every time edges are added. Raises TotalEdgeLimitError
        if the cumulative total exceeds MAX_TOTAL_EDGES.

        Args:
            count: Number of edges being added.

        Raises:
            TotalEdgeLimitError: If total edges exceed MAX_TOTAL_EDGES.
        """
        self._total_edges += count
        if self._total_edges > MAX_TOTAL_EDGES:
            raise TotalEdgeLimitError(self._total_edges)

    @property
    def total_edges(self) -> int:
        """Current total edge count."""
        return self._total_edges

    def reset_count(self) -> None:
        """Reset the edge counter (for testing or re-collection)."""
        self._total_edges = 0

    def to_config_dict(self) -> dict[str, object]:
        """Serialize expansion config for metadata output."""
        return {
            "ec2_mode": self.ec2_mode or self.global_mode,
            "expansion_mode": self.global_mode,
            "lambda_mode": self.lambda_mode or self.global_mode,
            "passrole_mode": self.passrole_mode or self.global_mode,
        }
