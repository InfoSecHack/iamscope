"""Tests for noise filter — role and edge include/exclude decisions.

Tests cover architecture doc §3.5 and §10.6:
- Service-linked roles excluded by default
- SSO roles included by default (even though under /aws-reserved/)
- AWS-managed roles excluded by default
- Override: --include-service-linked
- Override: --include-aws-managed (also includes SSO toggle)
- Self-trust edges excluded by default
- Override: --include-self-trust
- --exclude-accounts skips specified accounts
- --include-accounts collects only specified
- Default path (/) always included
- max_role_path_depth filter
- Service principal toggle
- Account filter priority (include over exclude)
"""

from iamscope.controls.noise_filter import NoiseFilter


class TestServiceLinkedRoles:
    """Tests for /aws-service-role/* filtering."""

    def test_service_linked_excluded_by_default(self) -> None:
        """Service-linked roles are excluded with default config."""
        nf = NoiseFilter()
        assert nf.should_include_role("/aws-service-role/lambda.amazonaws.com/AWSLambdaRole") is False

    def test_service_linked_included_with_override(self) -> None:
        """Service-linked roles are included when exclude_service_linked=False."""
        nf = NoiseFilter(exclude_service_linked=False)
        assert nf.should_include_role("/aws-service-role/lambda.amazonaws.com/AWSLambdaRole") is True


class TestSSOeRoles:
    """Tests for /aws-reserved/sso.amazonaws.com/* filtering."""

    def test_sso_roles_included_by_default(self) -> None:
        """SSO roles are INCLUDED by default — real attack surface."""
        nf = NoiseFilter()
        assert nf.should_include_role("/aws-reserved/sso.amazonaws.com/AWSReservedSSO_AdminAccess_abc123") is True

    def test_sso_roles_excluded_with_override(self) -> None:
        """SSO roles excluded when include_sso_roles=False."""
        nf = NoiseFilter(include_sso_roles=False)
        assert nf.should_include_role("/aws-reserved/sso.amazonaws.com/AWSReservedSSO_AdminAccess_abc123") is False

    def test_sso_takes_priority_over_aws_managed(self) -> None:
        """SSO check runs BEFORE aws-managed check.

        Even with exclude_aws_managed=True, SSO roles under /aws-reserved/
        are still included because the SSO check fires first.
        """
        nf = NoiseFilter(exclude_aws_managed=True, include_sso_roles=True)
        assert nf.should_include_role("/aws-reserved/sso.amazonaws.com/SomeSSO") is True


class TestAWSManagedRoles:
    """Tests for /aws-reserved/* (non-SSO) filtering."""

    def test_aws_managed_excluded_by_default(self) -> None:
        """Non-SSO aws-reserved roles are excluded by default."""
        nf = NoiseFilter()
        assert nf.should_include_role("/aws-reserved/other-service/SomeRole") is False

    def test_aws_managed_included_with_override(self) -> None:
        """AWS-managed roles included when exclude_aws_managed=False."""
        nf = NoiseFilter(exclude_aws_managed=False)
        assert nf.should_include_role("/aws-reserved/other-service/SomeRole") is True


class TestSelfTrust:
    """Tests for self-trust edge filtering."""

    def test_self_trust_excluded_by_default(self) -> None:
        """Self-trust edges (role trusts itself) excluded by default."""
        nf = NoiseFilter()
        assert nf.should_include_edge("111", "111", is_self_trust=True) is False

    def test_self_trust_included_with_override(self) -> None:
        """Self-trust edges included when exclude_self_trust=False."""
        nf = NoiseFilter(exclude_self_trust=False)
        assert nf.should_include_edge("111", "111", is_self_trust=True) is True

    def test_non_self_trust_always_included(self) -> None:
        """Normal edges (not self-trust) always included regardless of filter."""
        nf = NoiseFilter()
        assert nf.should_include_edge("111", "222", is_self_trust=False) is True


class TestAccountFilters:
    """Tests for --exclude-accounts and --include-accounts."""

    def test_exclude_accounts(self) -> None:
        """Roles in excluded accounts are filtered out."""
        nf = NoiseFilter(exclude_accounts=frozenset({"999999\u003999999"}))
        assert nf.should_include_role("/", account_id="999999\u003999999") is False
        assert nf.should_include_role("/", account_id="111111\u003111111") is True

    def test_include_accounts(self) -> None:
        """Only roles in included accounts pass the filter."""
        nf = NoiseFilter(include_accounts=frozenset({"111111\u003111111", "222222\u003222222"}))
        assert nf.should_include_role("/", account_id="111111\u003111111") is True
        assert nf.should_include_role("/", account_id="333333\u003333333") is False

    def test_include_accounts_on_edges(self) -> None:
        """Edge account filtering works for both src and dst."""
        nf = NoiseFilter(include_accounts=frozenset({"111", "222"}))
        assert nf.should_include_edge("111", "222") is True
        assert nf.should_include_edge("111", "333") is False
        assert nf.should_include_edge("333", "111") is False

    def test_exclude_accounts_on_edges(self) -> None:
        """Excluded accounts block edges involving those accounts."""
        nf = NoiseFilter(exclude_accounts=frozenset({"999"}))
        assert nf.should_include_edge("999", "111") is False
        assert nf.should_include_edge("111", "999") is False
        assert nf.should_include_edge("111", "222") is True

    def test_include_takes_priority_over_exclude(self) -> None:
        """[ASSUMPTION] include_accounts checked first, then exclude_accounts."""
        nf = NoiseFilter(
            include_accounts=frozenset({"111", "222"}),
            exclude_accounts=frozenset({"222"}),
        )
        # 111 is in include and not in exclude → included
        assert nf.should_include_role("/", account_id="111") is True
        # 222 is in include BUT also in exclude → excluded
        assert nf.should_include_role("/", account_id="222") is False
        # 333 is not in include → excluded
        assert nf.should_include_role("/", account_id="333") is False


class TestPathDepth:
    """Tests for max_role_path_depth filter."""

    def test_root_path_always_included(self) -> None:
        """Root path (/) has depth 0, always passes depth filter."""
        nf = NoiseFilter(max_role_path_depth=1)
        assert nf.should_include_role("/") is True

    def test_path_depth_within_limit(self) -> None:
        """Path within depth limit is included."""
        nf = NoiseFilter(max_role_path_depth=2)
        assert nf.should_include_role("/app/") is True
        assert nf.should_include_role("/app/team/") is True

    def test_path_depth_exceeds_limit(self) -> None:
        """Path exceeding depth limit is excluded."""
        nf = NoiseFilter(max_role_path_depth=1)
        assert nf.should_include_role("/app/team/") is False

    def test_no_depth_limit(self) -> None:
        """None depth limit means no filtering."""
        nf = NoiseFilter(max_role_path_depth=None)
        assert nf.should_include_role("/very/deep/nested/path/") is True


class TestServicePrincipalToggle:
    """Tests for service principal include/exclude."""

    def test_service_principals_included_by_default(self) -> None:
        """Service principals included by default."""
        nf = NoiseFilter()
        assert nf.should_include_service_principal() is True

    def test_service_principals_excluded_with_flag(self) -> None:
        """Service principals excluded when flag set."""
        nf = NoiseFilter(exclude_service_principals=True)
        assert nf.should_include_service_principal() is False


class TestConfigSerialization:
    """Tests for config dict serialization."""

    def test_to_config_dict_deterministic(self) -> None:
        """Config dict has sorted keys and stable output."""
        nf = NoiseFilter(exclude_accounts=frozenset({"222", "111"}))
        d = nf.to_config_dict()
        assert list(d.keys()) == sorted(d.keys())
        # Accounts sorted in list form
        assert d["exclude_accounts"] == ["111", "222"]

    def test_default_config_dict(self) -> None:
        """Default config dict matches expected defaults."""
        nf = NoiseFilter()
        d = nf.to_config_dict()
        assert d["exclude_service_linked"] is True
        assert d["exclude_aws_managed"] is True
        assert d["include_sso_roles"] is True
        assert d["exclude_self_trust"] is True
        assert d["exclude_service_principals"] is False
        assert d["max_role_path_depth"] is None


class TestNoiseFilterToFilterFn:
    """NF-1 wiring: to_filter_fn returns a callable usable by build_trust_edges.

    The resolver's `noise_filter_fn` parameter expects a callable with
    signature `(src_account, dst_account, is_self) -> bool` where True means
    "keep this edge." `NoiseFilter.should_include_edge` matches that contract
    positionally, and `to_filter_fn` exposes it explicitly for the pipeline
    to consume.
    """

    def test_to_filter_fn_returns_callable(self) -> None:
        """to_filter_fn returns a callable that accepts the expected signature."""
        nf = NoiseFilter()
        fn = nf.to_filter_fn()
        assert callable(fn)
        # Must accept three positional args and return a bool.
        result = fn("111111\u003111111", "222222\u003222222", False)
        assert isinstance(result, bool)

    def test_to_filter_fn_semantics_match_should_include_edge(self) -> None:
        """The returned callable produces identical results to should_include_edge.

        Probes every combination of (matching accounts, self_trust flag,
        exclude_self_trust config) to ensure the wrapper does not swallow or
        flip any parameter.
        """
        nf_default = NoiseFilter()  # exclude_self_trust=True
        nf_permissive = NoiseFilter(exclude_self_trust=False)

        cases = [
            ("111111\u003111111", "222222\u003222222", False),
            ("111111\u003111111", "111111\u003111111", True),  # same account, self trust
            ("111111\u003111111", "111111\u003111111", False),  # same account, not self
            ("", "222222\u003222222", False),  # unknown src account
        ]

        for nf in [nf_default, nf_permissive]:
            fn = nf.to_filter_fn()
            for src, dst, is_self in cases:
                assert fn(src, dst, is_self) == nf.should_include_edge(
                    src,
                    dst,
                    is_self_trust=is_self,
                ), f"to_filter_fn diverged from should_include_edge for {(src, dst, is_self)}"

    def test_self_trust_excluded_via_filter_fn(self) -> None:
        """Default filter_fn excludes self-trust edges.

        This is the precise contract the pipeline relies on post-S06: the
        filter_fn returned by `to_filter_fn()` must say False for self-trust
        edges under the default config, so build_trust_edges drops them.
        """
        fn = NoiseFilter().to_filter_fn()
        # Same account, is_self=True → excluded (False return).
        assert fn("111111\u003111111", "111111\u003111111", True) is False
        # Same account, is_self=False → included.
        assert fn("111111\u003111111", "111111\u003111111", False) is True
        # Different accounts (cross-account trust) → included.
        assert fn("222222\u003222222", "111111\u003111111", False) is True
