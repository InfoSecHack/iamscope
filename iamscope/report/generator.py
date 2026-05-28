"""Report generator — produces human-readable findings from scenario data.

Generates a structured Markdown report summarizing:
- Graph statistics
- Trust analysis (naked trust, cross-account, OIDC)
- Permission analysis (wildcard grants, lateral movement paths)
- SCP governance coverage
- Service edges (Lambda, EC2 instance profiles)
- GhostGates enrichment results (if present)

The report is designed for security teams to quickly identify:
1. High-risk trust relationships (naked trust)
2. Unscoped permissions (wildcard resources)
3. Governance gaps (SCP bypasses)
4. Lateral movement paths (PassRole + service edges)
"""

from __future__ import annotations

import json
import logging
from collections import Counter
from dataclasses import dataclass, field
from typing import Any

logger = logging.getLogger(__name__)


@dataclass
class ReportData:
    """Structured data extracted from scenario for report generation."""

    # Graph stats
    total_nodes: int = 0
    total_edges: int = 0
    total_constraints: int = 0
    total_edge_constraints: int = 0

    # Node breakdown
    node_types: Counter = field(default_factory=Counter)

    # Trust edge analysis
    trust_edges: int = 0
    cross_account_trust: int = 0
    oidc_trust: int = 0
    service_trust: int = 0  # AWS service principals
    naked_trust_counts: Counter = field(default_factory=Counter)

    # Permission edge analysis
    permission_edges: int = 0
    wildcard_permission_edges: int = 0
    passrole_edges: int = 0
    assume_role_perm_edges: int = 0
    lambda_perm_edges: int = 0
    ec2_perm_edges: int = 0

    # Service edges
    lambda_service_edges: int = 0
    ec2_service_edges: int = 0

    # Top findings
    naked_trust_edges: list[dict[str, Any]] = field(default_factory=list)
    wildcard_permission_details: list[dict[str, Any]] = field(default_factory=list)
    oidc_trust_details: list[dict[str, Any]] = field(default_factory=list)

    # Metadata
    org_id: str = ""
    accounts_collected: int = 0
    collection_timestamp: str = ""
    canonical_hash: str = ""

    # Enrichment
    enrichment_results: list[dict[str, Any]] = field(default_factory=list)

    # Constraint breakdown
    scp_constraints: int = 0
    permission_boundary_constraints: int = 0
    boundary_bound_edges: int = 0


def extract_report_data(
    scenario: dict[str, Any],
    binding_metadata: list[dict[str, Any]] | None = None,
    enrichment: list[dict[str, Any]] | None = None,
) -> ReportData:
    """Extract report data from a parsed scenario.json.

    Args:
        scenario: Parsed scenario.json dict.
        binding_metadata: Optional binding_metadata.json entries.
        enrichment: Optional GhostGates enrichment entries.

    Returns:
        ReportData with all metrics computed.
    """
    rd = ReportData()

    nodes = scenario.get("nodes", [])
    edges = scenario.get("edges", [])
    constraints = scenario.get("constraints", [])
    edge_constraints = scenario.get("edge_constraints", [])
    metadata = scenario.get("metadata", {})

    # Graph stats
    rd.total_nodes = len(nodes)
    rd.total_edges = len(edges)
    rd.total_constraints = len(constraints)
    rd.total_edge_constraints = len(edge_constraints)

    # Metadata
    rd.org_id = metadata.get("org_id", "")
    rd.accounts_collected = metadata.get("accounts_collected", 0)
    rd.collection_timestamp = metadata.get("collection_timestamp", "")
    rd.canonical_hash = metadata.get("canonical_hash", "")

    # Node type breakdown
    for node in nodes:
        rd.node_types[node.get("node_type", "unknown")] += 1

    # Edge analysis
    for edge in edges:
        edge_type = edge.get("edge_type", "")
        features = edge.get("features", {})
        src = edge.get("src", {})

        if edge_type.endswith("_trust"):
            rd.trust_edges += 1
            if features.get("cross_account"):
                rd.cross_account_trust += 1
            if src.get("node_type") == "OIDCProvider":
                rd.oidc_trust += 1
            if src.get("node_type") == "AWSService":
                rd.service_trust += 1

            naked = features.get("naked_trust", "")
            if naked:
                rd.naked_trust_counts[naked] += 1
            if naked in ("CRITICAL_NAKED", "BROAD_NAKED"):
                rd.naked_trust_edges.append(
                    {
                        "edge_id": edge.get("edge_id", ""),
                        "src": src.get("provider_id", ""),
                        "dst": edge.get("dst", {}).get("provider_id", ""),
                        "classification": naked,
                        "cross_account": features.get("cross_account", False),
                    }
                )

            # Collect OIDC trust details
            if src.get("node_type") == "OIDCProvider":
                rd.oidc_trust_details.append(
                    {
                        "provider": src.get("provider_id", ""),
                        "role": edge.get("dst", {}).get("provider_id", ""),
                        "oidc_subject_pattern": features.get("oidc_subject_pattern"),
                        "naked_trust": naked,
                        "condition_keys": features.get("raw_conditions", {}),
                    }
                )

        elif "_permission" in edge_type:
            rd.permission_edges += 1
            if features.get("is_wildcard_resource"):
                rd.wildcard_permission_edges += 1
                rd.wildcard_permission_details.append(
                    {
                        "edge_id": edge.get("edge_id", ""),
                        "action": features.get("action", edge_type.split("_")[0]),
                        "src": src.get("provider_id", ""),
                    }
                )

            action = features.get("action", edge_type.split("_")[0]).lower()
            if "passrole" in action:
                rd.passrole_edges += 1
            elif "assumerole" in action:
                rd.assume_role_perm_edges += 1
            elif "invokefunction" in action or "createfunction" in action:
                rd.lambda_perm_edges += 1
            elif "runinstances" in action:
                rd.ec2_perm_edges += 1

        elif "_service" in edge_type:
            if "lambda" in edge_type.lower():
                rd.lambda_service_edges += 1
            elif "ec2" in edge_type.lower() or "instanceprofile" in edge_type.lower():
                rd.ec2_service_edges += 1

    # Enrichment
    if enrichment:
        rd.enrichment_results = enrichment

    # Constraint type breakdown
    for c in constraints:
        ctype = c.get("constraint_type", "")
        if ctype == "SCP":
            rd.scp_constraints += 1
        elif ctype == "PERMISSION_BOUNDARY":
            rd.permission_boundary_constraints += 1

    # Count edge-constraint bindings for permission boundaries
    boundary_constraint_ids = {
        c.get("constraint_id") for c in constraints if c.get("constraint_type") == "PERMISSION_BOUNDARY"
    }
    for ec in edge_constraints:
        if ec.get("constraint_id") in boundary_constraint_ids:
            rd.boundary_bound_edges += 1

    return rd


def generate_report(rd: ReportData) -> str:
    """Generate a Markdown report from extracted report data.

    Args:
        rd: ReportData with all metrics.

    Returns:
        Markdown string.
    """
    sections: list[str] = []

    # Header
    sections.append("# IAMScope Security Assessment Report\n")
    if rd.org_id:
        sections.append(f"**Organization:** {rd.org_id}  ")
    if rd.accounts_collected:
        sections.append(f"**Accounts collected:** {rd.accounts_collected}  ")
    if rd.collection_timestamp:
        sections.append(f"**Collection time:** {rd.collection_timestamp}  ")
    if rd.canonical_hash:
        sections.append(f"**Scenario hash:** `{rd.canonical_hash[:16]}...`  ")
    sections.append("")

    # Executive Summary
    sections.append("## Executive Summary\n")
    high_risk = len(rd.naked_trust_edges)
    medium_risk = rd.wildcard_permission_edges
    # GC-1 (S07): ghostgates writes its values under `enrichment_confidence`,
    # not `governance_confidence` (which is owned by SCP/boundary binders).
    compromised = sum(
        1 for e in rd.enrichment_results if e.get("binding_metadata", {}).get("enrichment_confidence") == "compromised"
    )

    if high_risk == 0 and medium_risk == 0 and compromised == 0:
        sections.append("No critical trust or permission risks identified in this collection.")
    else:
        findings: list[str] = []
        if high_risk:
            findings.append(f"{high_risk} naked trust relationship(s)")
        if medium_risk:
            findings.append(f"{medium_risk} wildcard permission grant(s)")
        if compromised:
            findings.append(f"{compromised} CI/CD gate bypass(es) (GhostGates)")
        sections.append("Key findings: " + ", ".join(findings) + ".")
    sections.append("")

    # Graph Overview
    sections.append("## Graph Overview\n")
    sections.append("| Metric | Count |")
    sections.append("|--------|-------|")
    sections.append(f"| Nodes | {rd.total_nodes} |")
    sections.append(f"| Edges | {rd.total_edges} |")
    sections.append(f"| SCP Constraints | {rd.scp_constraints} |")
    if rd.permission_boundary_constraints:
        sections.append(f"| Permission Boundary Constraints | {rd.permission_boundary_constraints} |")
    sections.append(f"| Edge-Constraint Bindings | {rd.total_edge_constraints} |")
    sections.append("")

    # Node types
    if rd.node_types:
        sections.append("### Node Types\n")
        sections.append("| Type | Count |")
        sections.append("|------|-------|")
        for ntype, count in rd.node_types.most_common():
            sections.append(f"| {ntype} | {count} |")
        sections.append("")

    # Trust Analysis
    sections.append("## Trust Analysis\n")
    sections.append("| Category | Count |")
    sections.append("|----------|-------|")
    sections.append(f"| Total trust edges | {rd.trust_edges} |")
    sections.append(f"| Cross-account | {rd.cross_account_trust} |")
    sections.append(f"| OIDC federation | {rd.oidc_trust} |")
    sections.append(f"| AWS service | {rd.service_trust} |")
    sections.append("")

    if rd.naked_trust_counts:
        sections.append("### Naked Trust Classification\n")
        sections.append("| Classification | Count |")
        sections.append("|---------------|-------|")
        for cls, count in rd.naked_trust_counts.most_common():
            sections.append(f"| {cls} | {count} |")
        sections.append("")

    if rd.naked_trust_edges:
        sections.append("### High-Risk: Naked Trust Edges\n")
        for nte in rd.naked_trust_edges[:20]:  # Cap at 20
            xacct = " (cross-account)" if nte["cross_account"] else ""
            sections.append(
                f"- **{nte['classification']}**: `{_shorten(nte['src'])}` → `{_shorten(nte['dst'])}`{xacct}"
            )
        if len(rd.naked_trust_edges) > 20:
            sections.append(f"- ... and {len(rd.naked_trust_edges) - 20} more")
        sections.append("")

    # OIDC Federation Details
    if rd.oidc_trust_details:
        sections.append("### OIDC Federation Details\n")

        # Split into restricted (CONDITIONED) and unrestricted (BROAD_NAKED)
        unrestricted = [d for d in rd.oidc_trust_details if d["naked_trust"] in ("BROAD_NAKED", "CRITICAL_NAKED")]
        restricted = [d for d in rd.oidc_trust_details if d["naked_trust"] not in ("BROAD_NAKED", "CRITICAL_NAKED")]

        if unrestricted:
            sections.append(
                f"**{len(unrestricted)} OIDC trust(s) WITHOUT `:sub` restriction** "
                f"— any identity from the provider can assume these roles:\n"
            )
            for d in unrestricted[:15]:
                sections.append(f"- `{_shorten(d['provider'])}` → `{_shorten(d['role'])}`")
            if len(unrestricted) > 15:
                sections.append(f"- ... and {len(unrestricted) - 15} more")
            sections.append("")

        if restricted:
            sections.append(f"**{len(restricted)} OIDC trust(s) with `:sub` restriction:**\n")
            for d in restricted[:15]:
                sub = d.get("oidc_subject_pattern") or "—"
                sections.append(f"- `{_shorten(d['role'])}` ← `{_shorten(d['provider'])}` sub=`{sub}`")
            if len(restricted) > 15:
                sections.append(f"- ... and {len(restricted) - 15} more")
            sections.append("")

    # Permission Analysis
    sections.append("## Permission Analysis\n")
    sections.append("| Category | Count |")
    sections.append("|----------|-------|")
    sections.append(f"| Total permission edges | {rd.permission_edges} |")
    sections.append(f"| sts:AssumeRole | {rd.assume_role_perm_edges} |")
    sections.append(f"| iam:PassRole | {rd.passrole_edges} |")
    sections.append(f"| Lambda (Invoke/Create) | {rd.lambda_perm_edges} |")
    sections.append(f"| EC2 (RunInstances) | {rd.ec2_perm_edges} |")
    sections.append(f"| Wildcard resource | {rd.wildcard_permission_edges} |")
    sections.append("")

    # Service Edges
    if rd.lambda_service_edges or rd.ec2_service_edges:
        sections.append("## Service Edges (Lateral Movement)\n")
        sections.append("| Service | Edges |")
        sections.append("|---------|-------|")
        if rd.lambda_service_edges:
            sections.append(f"| Lambda → Execution Role | {rd.lambda_service_edges} |")
        if rd.ec2_service_edges:
            sections.append(f"| EC2 Instance Profile → Role | {rd.ec2_service_edges} |")
        sections.append("")

    # Permission Boundaries
    if rd.permission_boundary_constraints:
        sections.append("## Permission Boundaries\n")
        sections.append(
            f"**{rd.permission_boundary_constraints}** permission boundary "
            f"policies detected, bound to **{rd.boundary_bound_edges}** edges."
        )
        sections.append(
            "Permission boundaries cap effective permissions — edges bound by "
            "a boundary may be less permissive than the identity policy alone."
        )
        sections.append("")

    # GhostGates Enrichment
    if rd.enrichment_results:
        sections.append("## GhostGates CI/CD Gate Analysis\n")
        # GC-1 (S07): see executive summary above for the field rename rationale.
        compromised_list = [
            e
            for e in rd.enrichment_results
            if e.get("binding_metadata", {}).get("enrichment_confidence") == "compromised"
        ]
        validated_list = [
            e
            for e in rd.enrichment_results
            if e.get("binding_metadata", {}).get("enrichment_confidence") == "externally_validated"
        ]

        sections.append("| Status | Count |")
        sections.append("|--------|-------|")
        sections.append(f"| Compromised (gate bypassed) | {len(compromised_list)} |")
        sections.append(f"| Externally validated | {len(validated_list)} |")
        sections.append("")

        if compromised_list:
            sections.append("### Compromised OIDC Trust Edges\n")
            for entry in compromised_list[:10]:
                bm = entry.get("binding_metadata", {})
                repos = bm.get("matched_repos", [])
                claim = bm.get("subject_claim", "")
                sections.append(f"- Edge `{entry.get('edge_id', '')[:16]}...`: claim=`{claim}`, repos={repos}")
                for detail in bm.get("bypass_details", []):
                    reasons = ", ".join(detail.get("bypass_reasons", []))
                    sections.append(f"  - {detail['repo']}:{detail.get('branch', '*')} — {reasons}")
            sections.append("")

    # SCP Coverage
    if rd.total_constraints:
        sections.append("## SCP Governance Coverage\n")
        sections.append(
            f"**{rd.total_constraints}** SCP constraint(s) collected, "
            f"producing **{rd.total_edge_constraints}** edge-constraint binding(s)."
        )
        if rd.total_edge_constraints == 0 and rd.trust_edges > 0:
            sections.append(
                "\n> **Warning:** No SCP bindings found despite active trust edges. "
                "This may indicate SCPs are not scoped to restrict trust actions."
            )
        sections.append("")

    return "\n".join(sections)


def generate_report_from_files(
    scenario_path: str,
    binding_metadata_path: str | None = None,
    enrichment_path: str | None = None,
    findings_path: str | None = None,
) -> str:
    """Generate a report from file paths.

    Convenience wrapper that loads files and generates the report.

    When `findings_path` is provided and the file exists, a findings-first
    section is prepended to the report. This is the priority-2 design: the
    top of the report is pattern-reasoner output (validated / inconclusive
    / precondition_only / blocked), and the traditional graph statistics
    follow as supporting context.

    When `findings_path` is None (or the file is absent), the report
    degrades gracefully to the pre-priority-2 graph-only format. This
    keeps the report working against old scenarios collected before
    findings.json existed, and against `--no-findings` collection runs.
    """
    with open(scenario_path) as f:
        scenario = json.load(f)

    binding_metadata = None
    if binding_metadata_path:
        with open(binding_metadata_path) as f:
            binding_metadata = json.load(f)

    enrichment = None
    if enrichment_path:
        with open(enrichment_path) as f:
            enrichment = json.load(f)

    # Load findings.json if provided. Import here to avoid a hard
    # dependency on findings_renderer at module-import time — the
    # graph-only report path doesn't need it.
    findings_data = None
    if findings_path:
        with open(findings_path) as f:
            findings_data = json.load(f)

    rd = extract_report_data(scenario, binding_metadata, enrichment)
    graph_report = generate_report(rd)

    if findings_data is not None:
        from iamscope.report.findings_renderer import render_findings_section

        findings_section = render_findings_section(findings_data, scenario)
        # The findings section leads; the graph report follows as
        # context for drill-downs.
        return findings_section + "\n\n---\n\n" + graph_report

    return graph_report


def _shorten(arn: str, max_len: int = 60) -> str:
    """Shorten an ARN for display."""
    if len(arn) <= max_len:
        return arn
    return arn[: max_len - 3] + "..."
