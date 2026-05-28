"""Tests for GhostGates enrichment — CI/CD gate bypass annotation.

Tests cover:
- parse_ghostgates_report extracts repo/bypass data
- Subject claim pattern parsing (repo, branch, wildcard)
- OIDC edge matching (GitHub OIDC provider detection)
- Bypass → compromised classification
- No bypass → externally_validated classification
- Wildcard subject claim matches all repos
- Conservative: one bypass → entire edge compromised
- enrichment_to_binding_metadata sidecar format
- Non-OIDC edges are skipped
- ARF-RT prior parameters correct
"""

import json

from iamscope.enrichment.ghostgates import (
    PRIOR_COMPROMISED,
    PRIOR_EXTERNALLY_VALIDATED,
    EnrichmentResult,
    _branch_matches,
    _extract_subject_claims,
    _is_github_oidc,
    _match_pattern,
    _parse_subject_claim,
    _repo_matches,
    enrich_scenario,
    enrichment_to_binding_metadata,
    load_ghostgates_report,
    parse_ghostgates_report,
)

SAMPLE_GHOSTGATES_REPORT = {
    "org": "MyOrg",
    "repositories": [
        {
            "repo": "MyOrg/backend-api",
            "branch_protections": [
                {
                    "branch": "main",
                    "bypassed": True,
                    "bypass_reasons": ["dismiss_stale_reviews disabled"],
                    "gates_checked": 5,
                    "gates_bypassed": 1,
                },
                {
                    "branch": "develop",
                    "bypassed": False,
                    "gates_checked": 5,
                    "gates_bypassed": 0,
                },
            ],
        },
        {
            "repo": "MyOrg/frontend-app",
            "branch_protections": [
                {
                    "branch": "main",
                    "bypassed": False,
                    "gates_checked": 5,
                    "gates_bypassed": 0,
                },
            ],
        },
    ],
}


def _make_oidc_edge(edge_id, subject_claim, provider_id="token.actions.githubusercontent.com"):
    """Build an OIDC trust edge for testing."""
    return {
        "edge_id": edge_id,
        "edge_type": "sts:AssumeRoleWithWebIdentity_trust",
        "src": {
            "node_type": "OIDCProvider",
            "provider_id": f"arn:aws:iam::123:oidc-provider/{provider_id}",
        },
        "dst": {"node_type": "IAMRole", "provider_id": "arn:aws:iam::123:role/Deploy"},
        "features": {
            "raw_conditions": {
                "StringEquals": {
                    "token.actions.githubusercontent.com:sub": subject_claim,
                },
            },
        },
    }


class TestParseGhostGatesReport:
    """Tests for parse_ghostgates_report."""

    def test_basic_parse(self) -> None:
        """Parses repos and bypass status."""
        result = parse_ghostgates_report(SAMPLE_GHOSTGATES_REPORT)
        assert "MyOrg/backend-api" in result
        assert "MyOrg/frontend-app" in result
        assert len(result["MyOrg/backend-api"]) == 2

    def test_bypass_fields(self) -> None:
        """Bypass details populated correctly."""
        result = parse_ghostgates_report(SAMPLE_GHOSTGATES_REPORT)
        backend_main = [b for b in result["MyOrg/backend-api"] if b.branch == "main"][0]
        assert backend_main.bypassed is True
        assert "dismiss_stale_reviews" in backend_main.bypass_reasons[0]
        assert backend_main.gates_checked == 5
        assert backend_main.gates_bypassed == 1

    def test_no_bypass(self) -> None:
        """Non-bypassed branches have bypassed=False."""
        result = parse_ghostgates_report(SAMPLE_GHOSTGATES_REPORT)
        frontend = result["MyOrg/frontend-app"][0]
        assert frontend.bypassed is False

    def test_empty_report(self) -> None:
        """Empty report produces empty dict."""
        result = parse_ghostgates_report({"repositories": []})
        assert result == {}

    def test_singular_bypass_reason(self) -> None:
        """Single bypass_reason string converted to list."""
        report = {
            "repositories": [
                {
                    "repo": "Org/repo",
                    "branch_protections": [
                        {
                            "branch": "main",
                            "bypassed": True,
                            "bypass_reason": "no approvals required",
                        }
                    ],
                }
            ],
        }
        result = parse_ghostgates_report(report)
        assert result["Org/repo"][0].bypass_reasons == ["no approvals required"]


class TestSubjectClaimParsing:
    """Tests for _parse_subject_claim."""

    def test_full_claim(self) -> None:
        """repo:Org/repo:ref:refs/heads/main → (Org/repo, main)."""
        repo, branch = _parse_subject_claim("repo:MyOrg/app:ref:refs/heads/main")
        assert repo == "MyOrg/app"
        assert branch == "main"

    def test_wildcard_claim(self) -> None:
        """repo:Org/* → (Org/*, '')."""
        repo, branch = _parse_subject_claim("repo:MyOrg/*")
        assert repo == "MyOrg/*"
        assert branch == ""

    def test_environment_claim(self) -> None:
        """repo:Org/repo:environment:prod → (Org/repo, '')."""
        repo, branch = _parse_subject_claim("repo:MyOrg/app:environment:production")
        assert repo == "MyOrg/app"
        assert branch == ""

    def test_star_suffix(self) -> None:
        """repo:Org/repo:* → (Org/repo, '')."""
        repo, branch = _parse_subject_claim("repo:MyOrg/app:*")
        assert repo == "MyOrg/app"
        assert branch == ""

    def test_non_repo_pattern(self) -> None:
        """Non-repo patterns return empty."""
        repo, branch = _parse_subject_claim("arn:aws:sts::123:assumed-role/x")
        assert repo == ""
        assert branch == ""


class TestHelpers:
    """Tests for helper functions."""

    def test_is_github_oidc(self) -> None:
        """GitHub OIDC providers detected."""
        assert _is_github_oidc("arn:aws:iam::123:oidc-provider/token.actions.githubusercontent.com")
        assert not _is_github_oidc("arn:aws:iam::123:oidc-provider/accounts.google.com")

    def test_repo_matches_exact(self) -> None:
        """Exact repo matching."""
        assert _repo_matches("MyOrg/app", "MyOrg/app")
        assert not _repo_matches("MyOrg/other", "MyOrg/app")

    def test_repo_matches_wildcard(self) -> None:
        """Wildcard repo matching."""
        assert _repo_matches("MyOrg/app", "MyOrg/*")
        assert _repo_matches("MyOrg/backend-api", "MyOrg/*")
        assert not _repo_matches("OtherOrg/app", "MyOrg/*")

    def test_branch_matches(self) -> None:
        """Branch matching with wildcards."""
        assert _branch_matches("main", "main")
        assert _branch_matches("main", "")  # Empty = any
        assert _branch_matches("main", "*")
        assert not _branch_matches("develop", "main")

    def test_extract_subject_claims_string_equals(self) -> None:
        """Extracts from StringEquals condition."""
        conditions = {
            "StringEquals": {
                "token.actions.githubusercontent.com:sub": "repo:Org/app:ref:refs/heads/main",
            },
        }
        claims = _extract_subject_claims(conditions)
        assert len(claims) == 1
        assert "Org/app" in claims[0]

    def test_extract_subject_claims_string_like(self) -> None:
        """Extracts from StringLike condition."""
        conditions = {
            "StringLike": {
                "token.actions.githubusercontent.com:sub": "repo:Org/*",
            },
        }
        claims = _extract_subject_claims(conditions)
        assert len(claims) == 1

    def test_extract_subject_claims_list(self) -> None:
        """Handles list of claim values."""
        conditions = {
            "StringEquals": {
                "token.actions.githubusercontent.com:sub": [
                    "repo:Org/app1:ref:refs/heads/main",
                    "repo:Org/app2:ref:refs/heads/main",
                ],
            },
        }
        claims = _extract_subject_claims(conditions)
        assert len(claims) == 2


class TestMatchPattern:
    """Tests for _match_pattern — the core matching logic."""

    def test_bypass_produces_compromised(self) -> None:
        """Matching a bypassed repo → compromised."""
        bypass_lookup = parse_ghostgates_report(SAMPLE_GHOSTGATES_REPORT)
        result = _match_pattern(
            "edge1",
            "repo:MyOrg/backend-api:ref:refs/heads/main",
            bypass_lookup,
        )
        assert result is not None
        assert result.enrichment_confidence == "compromised"
        assert result.prior == PRIOR_COMPROMISED

    def test_no_bypass_produces_validated(self) -> None:
        """Matching a clean repo → externally_validated."""
        bypass_lookup = parse_ghostgates_report(SAMPLE_GHOSTGATES_REPORT)
        result = _match_pattern(
            "edge2",
            "repo:MyOrg/frontend-app:ref:refs/heads/main",
            bypass_lookup,
        )
        assert result is not None
        assert result.enrichment_confidence == "externally_validated"
        assert result.prior == PRIOR_EXTERNALLY_VALIDATED

    def test_wildcard_any_bypass_compromises(self) -> None:
        """Wildcard matching: one bypassed repo → compromised."""
        bypass_lookup = parse_ghostgates_report(SAMPLE_GHOSTGATES_REPORT)
        result = _match_pattern(
            "edge3",
            "repo:MyOrg/*",
            bypass_lookup,
        )
        assert result is not None
        assert result.enrichment_confidence == "compromised"
        assert len(result.matched_repos) == 2

    def test_no_match_returns_none(self) -> None:
        """No matching repos → None."""
        bypass_lookup = parse_ghostgates_report(SAMPLE_GHOSTGATES_REPORT)
        result = _match_pattern(
            "edge4",
            "repo:OtherOrg/app:ref:refs/heads/main",
            bypass_lookup,
        )
        assert result is None


class TestEnrichScenario:
    """Tests for enrich_scenario — full pipeline."""

    def test_enriches_oidc_edge(self) -> None:
        """Enriches a matching OIDC edge."""
        scenario = {
            "edges": [
                _make_oidc_edge("e1", "repo:MyOrg/backend-api:ref:refs/heads/main"),
            ],
        }
        results = enrich_scenario(scenario, SAMPLE_GHOSTGATES_REPORT)
        assert len(results) == 1
        assert results[0].enrichment_confidence == "compromised"

    def test_skips_non_oidc_edges(self) -> None:
        """Non-OIDC edges are not enriched."""
        scenario = {
            "edges": [
                {
                    "edge_id": "e_role",
                    "edge_type": "sts:AssumeRole_trust",
                    "src": {"node_type": "IAMRole", "provider_id": "arn:aws:iam::123:role/X"},
                    "dst": {"node_type": "IAMRole", "provider_id": "arn:aws:iam::123:role/Y"},
                    "features": {},
                }
            ],
        }
        results = enrich_scenario(scenario, SAMPLE_GHOSTGATES_REPORT)
        assert len(results) == 0

    def test_skips_non_github_oidc(self) -> None:
        """Non-GitHub OIDC providers are skipped."""
        scenario = {
            "edges": [
                _make_oidc_edge("e2", "repo:MyOrg/app:ref:refs/heads/main", provider_id="accounts.google.com"),
            ],
        }
        results = enrich_scenario(scenario, SAMPLE_GHOSTGATES_REPORT)
        assert len(results) == 0

    def test_empty_scenario(self) -> None:
        """Empty scenario produces no enrichment."""
        results = enrich_scenario({"edges": []}, SAMPLE_GHOSTGATES_REPORT)
        assert results == []

    def test_multiple_edges(self) -> None:
        """Multiple OIDC edges enriched independently."""
        scenario = {
            "edges": [
                _make_oidc_edge("e1", "repo:MyOrg/backend-api:ref:refs/heads/main"),
                _make_oidc_edge("e2", "repo:MyOrg/frontend-app:ref:refs/heads/main"),
            ],
        }
        results = enrich_scenario(scenario, SAMPLE_GHOSTGATES_REPORT)
        assert len(results) == 2
        confidences = {r.enrichment_confidence for r in results}
        assert "compromised" in confidences
        assert "externally_validated" in confidences


class TestEnrichmentToBindingMetadata:
    """Tests for sidecar format conversion."""

    def test_sidecar_format(self) -> None:
        """Enrichment results convert to binding_metadata entries."""
        results = [
            EnrichmentResult(
                edge_id="e1",
                enrichment_confidence="compromised",
                matched_repos=["MyOrg/app"],
                bypass_details=[{"repo": "MyOrg/app", "branch": "main"}],
                subject_claim="repo:MyOrg/app:ref:refs/heads/main",
                prior={"alpha": 1, "beta": 1},
            ),
        ]
        entries = enrichment_to_binding_metadata(results)
        assert len(entries) == 1
        entry = entries[0]
        assert entry["edge_id"] == "e1"
        assert entry["enrichment_source"] == "ghostgates"
        bm = entry["binding_metadata"]
        assert bm["enrichment_confidence"] == "compromised"
        assert bm["arf_rt_prior"] == {"alpha": 1, "beta": 1}

    def test_empty_results(self) -> None:
        """Empty enrichment → empty sidecar."""
        assert enrichment_to_binding_metadata([]) == []


class TestLoadGhostGatesReport:
    """Tests for file loading."""

    def test_load_from_file(self, tmp_path) -> None:
        """Load and parse a GhostGates report JSON file."""
        report_path = str(tmp_path / "ghostgates.json")
        with open(report_path, "w") as f:
            json.dump(SAMPLE_GHOSTGATES_REPORT, f)

        report = load_ghostgates_report(report_path)
        assert report["org"] == "MyOrg"
        assert len(report["repositories"]) == 2
