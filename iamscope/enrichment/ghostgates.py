"""GhostGates enrichment — annotates OIDC trust edges with CI/CD bypass data.

Post-pipeline enrichment that reads a GhostGates report JSON and matches
OIDC trust edges by repository/branch pattern from the subject claim.

How it works:
1. Load scenario.json and GhostGates report
2. Find OIDC trust edges (src node_type == OIDCProvider)
3. Extract subject claim patterns from edge raw_conditions
4. Match patterns against GhostGates repo/branch bypass data
5. Annotate binding_metadata with governance confidence

New vocabulary (post-GC-1, S07):
- enrichment_confidence="compromised": gate bypassed, treat as naked trust
- enrichment_confidence="externally_validated": gate solid, stronger DENY prior

These values are written to binding_metadata.json under their own
`enrichment_confidence` key, alongside (not overwriting) the
`governance_confidence` key written by the SCP and boundary binders.

ARF-RT prior mapping:
- compromised → alpha=1, beta=1 (naked trust — no governance assurance)
- externally_validated → alpha=1, beta=4 (governance-backed DENY prior)

Wildcard handling:
- Subject claim "repo:MyOrg/*" matches ALL repos in the org
- If ANY matched repo has a bypass, the entire edge is compromised
- Conservative: one weak link breaks the chain

Self-contained module — no IAMScope core changes needed.
"""

from __future__ import annotations

import fnmatch
import json
import logging
import re
from dataclasses import dataclass, field
from typing import Any

from iamscope.constants import (
    ENRICHMENT_CONFIDENCE_COMPROMISED,
    ENRICHMENT_CONFIDENCE_EXTERNALLY_VALIDATED,
)

logger = logging.getLogger(__name__)

# GitHub OIDC provider identifiers
GITHUB_OIDC_PROVIDERS = {
    "token.actions.githubusercontent.com",
}

# Condition keys that carry subject claims
SUBJECT_CONDITION_KEYS = {
    "token.actions.githubusercontent.com:sub",
    "accounts.google.com:sub",
}

# ARF-RT prior parameters
PRIOR_COMPROMISED = {"alpha": 1, "beta": 1}  # Naked trust
PRIOR_EXTERNALLY_VALIDATED = {"alpha": 1, "beta": 4}  # Strong governance


@dataclass
class RepoBypassInfo:
    """Bypass status for a single repo/branch combination."""

    repo: str
    branch: str
    bypassed: bool
    bypass_reasons: list[str] = field(default_factory=list)
    gates_checked: int = 0
    gates_bypassed: int = 0


@dataclass
class EnrichmentResult:
    """Result of enriching a single OIDC trust edge."""

    edge_id: str
    enrichment_confidence: str  # "compromised" or "externally_validated"
    matched_repos: list[str]
    bypass_details: list[dict[str, Any]]
    subject_claim: str
    prior: dict[str, int]


def load_ghostgates_report(path: str) -> dict[str, Any]:
    """Load a GhostGates report JSON file.

    Expected format:
    {
        "org": "MyOrg",
        "repositories": [
            {
                "repo": "MyOrg/backend-api",
                "branch_protections": [
                    {
                        "branch": "main",
                        "bypassed": true,
                        "bypass_reason": "dismiss_stale_reviews disabled",
                        "gates_checked": 5,
                        "gates_bypassed": 2
                    }
                ]
            }
        ]
    }
    """
    with open(path) as f:
        result: dict[str, Any] = json.load(f)
        return result


def parse_ghostgates_report(report: dict[str, Any]) -> dict[str, list[RepoBypassInfo]]:
    """Parse a GhostGates report into a repo→bypass lookup.

    Returns:
        Dict mapping "org/repo" to list of RepoBypassInfo per branch.
    """
    result: dict[str, list[RepoBypassInfo]] = {}

    for repo_entry in report.get("repositories", []):
        repo_name = repo_entry.get("repo", "")
        if not repo_name:
            continue

        bypasses: list[RepoBypassInfo] = []
        for bp in repo_entry.get("branch_protections", []):
            info = RepoBypassInfo(
                repo=repo_name,
                branch=bp.get("branch", ""),
                bypassed=bp.get("bypassed", False),
                bypass_reasons=bp.get("bypass_reasons", []),
                gates_checked=bp.get("gates_checked", 0),
                gates_bypassed=bp.get("gates_bypassed", 0),
            )
            # Handle singular bypass_reason → list
            if not info.bypass_reasons and bp.get("bypass_reason"):
                info.bypass_reasons = [bp["bypass_reason"]]
            bypasses.append(info)

        result[repo_name] = bypasses

    return result


def enrich_scenario(
    scenario: dict[str, Any],
    ghostgates_report: dict[str, Any],
) -> list[EnrichmentResult]:
    """Enrich OIDC trust edges with GhostGates bypass data.

    Args:
        scenario: Parsed scenario.json dict.
        ghostgates_report: Parsed GhostGates report dict.

    Returns:
        List of EnrichmentResult for each matched OIDC edge.
    """
    bypass_lookup = parse_ghostgates_report(ghostgates_report)
    results: list[EnrichmentResult] = []

    for edge in scenario.get("edges", []):
        # Only process OIDC trust edges
        src = edge.get("src", {})
        if src.get("node_type") != "OIDCProvider":
            continue

        provider_id = src.get("provider_id", "")
        if not _is_github_oidc(provider_id):
            continue

        features = edge.get("features", {})
        raw_conditions = features.get("raw_conditions", {})

        # Extract subject claim patterns
        subject_patterns = _extract_subject_claims(raw_conditions)
        if not subject_patterns:
            continue

        edge_id = edge.get("edge_id", "")

        for pattern in subject_patterns:
            enrichment = _match_pattern(edge_id, pattern, bypass_lookup)
            if enrichment:
                results.append(enrichment)

    logger.info(
        "GhostGates enrichment: %d OIDC edges enriched (%d compromised, %d validated)",
        len(results),
        sum(1 for r in results if r.enrichment_confidence == ENRICHMENT_CONFIDENCE_COMPROMISED),
        sum(1 for r in results if r.enrichment_confidence == ENRICHMENT_CONFIDENCE_EXTERNALLY_VALIDATED),
    )
    return results


def enrichment_to_binding_metadata(results: list[EnrichmentResult]) -> list[dict[str, Any]]:
    """Convert enrichment results to binding_metadata sidecar entries.

    Returns:
        List of dicts suitable for appending to binding_metadata.json.
    """
    entries: list[dict[str, Any]] = []
    for r in results:
        entry = {
            "edge_id": r.edge_id,
            "enrichment_source": "ghostgates",
            "binding_metadata": {
                # GC-1 (S07): write to a separate `enrichment_confidence` key
                # rather than overwriting `governance_confidence` (which is
                # owned by the SCP/boundary binders).
                "enrichment_confidence": r.enrichment_confidence,
                "subject_claim": r.subject_claim,
                "matched_repos": sorted(r.matched_repos),
                "bypass_details": r.bypass_details,
                "arf_rt_prior": r.prior,
            },
        }
        entries.append(entry)
    return entries


def _is_github_oidc(provider_id: str) -> bool:
    """Check if a provider_id is a GitHub OIDC provider."""
    return any(gh in provider_id for gh in GITHUB_OIDC_PROVIDERS)


def _extract_subject_claims(raw_conditions: dict[str, Any]) -> list[str]:
    """Extract subject claim patterns from IAM trust policy conditions.

    Looks for StringEquals/StringLike conditions on known subject keys.

    Returns:
        List of subject claim pattern strings.
    """
    patterns: list[str] = []

    for operator in ["StringEquals", "StringLike", "ForAnyValue:StringLike"]:
        condition_block = raw_conditions.get(operator, {})
        for key in SUBJECT_CONDITION_KEYS:
            values = condition_block.get(key, [])
            if isinstance(values, str):
                values = [values]
            patterns.extend(values)

    return patterns


def _match_pattern(
    edge_id: str,
    subject_pattern: str,
    bypass_lookup: dict[str, list[RepoBypassInfo]],
) -> EnrichmentResult | None:
    """Match a subject claim pattern against GhostGates bypass data.

    Subject claim format: "repo:ORG/REPO:ref:refs/heads/BRANCH"
    or wildcard: "repo:ORG/*"

    Returns:
        EnrichmentResult if any repos match, None otherwise.
    """
    repo_pattern, branch_pattern = _parse_subject_claim(subject_pattern)
    if not repo_pattern:
        return None

    # Find matching repos
    matched_repos: list[str] = []
    bypass_details: list[dict[str, Any]] = []
    any_bypassed = False

    for repo_name, bypasses in sorted(bypass_lookup.items()):
        if not _repo_matches(repo_name, repo_pattern):
            continue

        matched_repos.append(repo_name)

        for bp in bypasses:
            if branch_pattern and not _branch_matches(bp.branch, branch_pattern):
                continue

            if bp.bypassed:
                any_bypassed = True
                bypass_details.append(
                    {
                        "repo": bp.repo,
                        "branch": bp.branch,
                        "bypass_reasons": bp.bypass_reasons,
                        "gates_checked": bp.gates_checked,
                        "gates_bypassed": bp.gates_bypassed,
                    }
                )

    if not matched_repos:
        return None

    # Conservative: any bypass → compromised
    if any_bypassed:
        confidence = ENRICHMENT_CONFIDENCE_COMPROMISED
        prior = dict(PRIOR_COMPROMISED)
    else:
        confidence = ENRICHMENT_CONFIDENCE_EXTERNALLY_VALIDATED
        prior = dict(PRIOR_EXTERNALLY_VALIDATED)

    return EnrichmentResult(
        edge_id=edge_id,
        enrichment_confidence=confidence,
        matched_repos=matched_repos,
        bypass_details=bypass_details,
        subject_claim=subject_pattern,
        prior=prior,
    )


def _parse_subject_claim(pattern: str) -> tuple[str, str]:
    """Parse a GitHub OIDC subject claim into (repo_pattern, branch_pattern).

    Formats:
    - "repo:MyOrg/my-repo:ref:refs/heads/main" → ("MyOrg/my-repo", "main")
    - "repo:MyOrg/my-repo:*" → ("MyOrg/my-repo", "")
    - "repo:MyOrg/*" → ("MyOrg/*", "")
    - "repo:MyOrg/my-repo:environment:production" → ("MyOrg/my-repo", "")

    Returns:
        Tuple of (repo_pattern, branch_pattern). Empty string = any.
    """
    if not pattern.startswith("repo:"):
        return ("", "")

    rest = pattern[5:]  # Strip "repo:"

    # Split on first ":"
    parts = rest.split(":", 1)
    repo_pattern = parts[0]

    branch_pattern = ""
    if len(parts) > 1:
        qualifier = parts[1]
        # Extract branch from "ref:refs/heads/BRANCH"
        branch_match = re.match(r"ref:refs/heads/(.+)", qualifier)
        if branch_match:
            branch_pattern = branch_match.group(1)

    return (repo_pattern, branch_pattern)


def _repo_matches(repo_name: str, pattern: str) -> bool:
    """Check if a repo name matches a pattern (supports fnmatch wildcards)."""
    return fnmatch.fnmatch(repo_name.lower(), pattern.lower())


def _branch_matches(branch: str, pattern: str) -> bool:
    """Check if a branch name matches a pattern."""
    if not pattern or pattern == "*":
        return True
    return fnmatch.fnmatch(branch.lower(), pattern.lower())
