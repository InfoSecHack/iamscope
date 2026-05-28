"""Golden fixture regression tests.

These tests pin specific output hashes to catch any accidental
changes to ID generation, serialization, or sorting logic.

If a golden test fails, it means the output format has changed.
This is a BREAKING CHANGE for ARF-RT integration and must be
reviewed before updating the golden fixture.
"""

import hashlib
import json
from pathlib import Path

import pytest

GOLDEN_DIR = Path(__file__).parent / "fixtures" / "expected_output"


@pytest.mark.golden
class TestGoldenMinimalScenario:
    """Golden tests for the minimal scenario fixture."""

    def test_golden_file_exists(self) -> None:
        """Golden fixture file must exist."""
        golden_path = GOLDEN_DIR / "minimal_scenario.json"
        assert golden_path.exists(), f"Golden fixture missing: {golden_path}"

    def test_golden_valid_json(self) -> None:
        """Golden fixture must be valid JSON."""
        golden_path = GOLDEN_DIR / "minimal_scenario.json"
        data = golden_path.read_bytes()
        scenario = json.loads(data)
        assert "nodes" in scenario
        assert "edges" in scenario

    def test_golden_canonical_hash_pinned(self) -> None:
        """Canonical hash from golden fixture must match pinned value.

        PINNED HASH: 1ef3da8327d13ea21c80923c79076db819b0cea74320b18671bc4a8c06f81150

        Re-pinned in v0.2.37 (Session 2 edge_id v1→v2): edge_id formula
        now includes features_digest, so every edge_id in this fixture
        changed, which cascaded into a new canonical_hash. Structural
        content is unchanged — same 2 edges, same features, same
        constraint binding. See `iamscope.identity.deterministic_ids`
        module docstring for the v1→v2 migration rationale.

        Re-pinned in S05 (DIG-1 + D1 absorption): fixture now contains a trust
        edge with populated allow_controls ControlRef AND a new permission edge
        (Alice → TestRole via iam:PassRole) with raw_conditions + allow_controls.

        If this hash changes, either:
        1. The ID algorithm changed (BREAKING — update all downstream refs)
        2. The serialization format changed (BREAKING — update ARF-RT contract)
        3. The golden fixture was regenerated (review and re-pin)
        """
        golden_path = GOLDEN_DIR / "minimal_scenario.json"
        scenario = json.loads(golden_path.read_bytes())
        stored_hash = scenario["metadata"]["canonical_hash"]

        pinned_hash = "1ef3da8327d13ea21c80923c79076db819b0cea74320b18671bc4a8c06f81150"
        assert stored_hash == pinned_hash, (
            f"Golden canonical hash changed!\n"
            f"  Expected: {pinned_hash}\n"
            f"  Got:      {stored_hash}\n"
            f"This is a BREAKING CHANGE. Review before updating."
        )

    def test_golden_file_hash_stable(self) -> None:
        """Raw file bytes hash must be stable (pinned).

        This catches any change to the file, including metadata changes.
        """
        golden_path = GOLDEN_DIR / "minimal_scenario.json"
        file_bytes = golden_path.read_bytes()
        file_hash = hashlib.sha256(file_bytes).hexdigest()

        # Pin the raw file hash (re-pinned in S05, re-pinned again in
        # v0.2.29 after BUG-013 added `collection_failures` to
        # ScenarioMetadata. canonical_hash unchanged — metadata is
        # excluded from the canonical hash — but the raw file bytes
        # now include the new empty-list field. Re-pinned again in
        # v0.2.37 (Session 2 edge_id v1→v2) — both the canonical_hash
        # and the raw file bytes changed because edge_ids shifted.)
        pinned_file_hash = "8d5de2dca34cfb4d04ab348b5985836c570ab8504c52fbae71ff0771be78a0e7"

        # Note: raw file hash includes metadata (timestamps etc).
        # If only metadata changed, canonical_hash test above still passes.
        # This test catches ALL changes including metadata field additions.
        assert file_hash == pinned_file_hash, (
            f"Golden file hash changed!\n"
            f"  Expected: {pinned_file_hash}\n"
            f"  Got:      {file_hash}\n"
            f"If only metadata changed, update this pin. "
            f"If canonical_hash also changed, this is a BREAKING CHANGE."
        )

    def test_golden_no_trailing_newline(self) -> None:
        """Golden fixture must not end with trailing newline."""
        golden_path = GOLDEN_DIR / "minimal_scenario.json"
        data = golden_path.read_bytes()
        assert not data.endswith(b"\n")

    def test_golden_reproduces_from_code(self) -> None:
        """Regenerating the golden fixture from code must produce identical bytes.

        This is the ultimate determinism test: code → bytes → match golden file.

        Post-S05: the fixture now exercises both a trust edge and a permission
        edge with populated `allow_controls` ControlRef evidence attribution.
        The digests are computed inline from hand-constructed statement dicts
        so the test catches any change to the digest function without needing
        a separate fixture source file.
        """
        from iamscope.constants import (
            CONSTRAINT_TYPE_SCP,
            NODE_TYPE_ACCOUNT_ROOT,
            NODE_TYPE_IAM_ROLE,
            NODE_TYPE_IAM_USER,
            PROVIDER_AWS,
            REGION_GLOBAL,
        )
        from iamscope.identity.statement_digest import statement_digest
        from iamscope.models import (
            Constraint,
            ControlRef,
            Edge,
            EdgeConstraint,
            Node,
            ScenarioMetadata,
        )
        from iamscope.output.scenario_json import emit_scenario

        role = Node(
            provider=PROVIDER_AWS,
            node_type=NODE_TYPE_IAM_ROLE,
            provider_id="arn:aws:iam::111111111111:role/TestRole",
            region=REGION_GLOBAL,
            properties={"account_id": "111111111111", "is_synthetic": False, "path": "/"},
        )
        acct_root = Node(
            provider=PROVIDER_AWS,
            node_type=NODE_TYPE_ACCOUNT_ROOT,
            provider_id="arn:aws:iam::222222222222:root",
            region=REGION_GLOBAL,
            properties={"account_id": "222222222222", "is_synthetic": True, "principal_count": 50},
        )
        # S05 + D1 absorption: add a real user principal as the source of a
        # permission edge, so the fixture exercises the post-S01 raw_conditions
        # + post-S05 allow_controls shape on a permission edge end-to-end.
        alice = Node(
            provider=PROVIDER_AWS,
            node_type=NODE_TYPE_IAM_USER,
            provider_id="arn:aws:iam::111111111111:user/Alice",
            region=REGION_GLOBAL,
            properties={"account_id": "111111111111", "is_synthetic": False, "path": "/"},
        )

        # Trust statement → digest → ControlRef dict.
        trust_statement = {
            "Effect": "Allow",
            "Principal": {"AWS": "arn:aws:iam::222222222222:root"},
            "Action": "sts:AssumeRole",
        }
        trust_digest = statement_digest(trust_statement)
        trust_control_ref = ControlRef(
            control_type="TRUST",
            policy_arn=role.provider_id,
            statement_index=0,
            digest=trust_digest,
            summary=f"trust policy for {role.provider_id}",
        ).to_dict()

        trust_edge = Edge(
            edge_type="sts:AssumeRole_trust",
            src=acct_root.to_ref(),
            dst=role.to_ref(),
            region=REGION_GLOBAL,
            features={
                "allow_controls": [trust_control_ref],
                "cross_account": True,
                "has_external_id": False,
                "layer": "trust",
                "naked_trust": True,
                "trust_scope": "account_root",
            },
        )

        # Permission statement → digest → ControlRef dict.
        perm_statement = {
            "Effect": "Allow",
            "Action": "iam:PassRole",
            "Resource": role.provider_id,
        }
        perm_digest = statement_digest(perm_statement)
        perm_control_ref = ControlRef(
            control_type="IDENTITY_POLICY",
            policy_arn=None,  # inline policy
            statement_index=0,
            digest=perm_digest,
            summary="inline:AliceAdmin",
        ).to_dict()

        permission_edge = Edge(
            edge_type="iam:PassRole_permission",
            src=alice.to_ref(),
            dst=role.to_ref(),
            region=REGION_GLOBAL,
            features={
                "action_matched_via": "exact",
                "allow_controls": [perm_control_ref],
                "effect": "Allow",
                "has_conditions": False,
                "is_wildcard_resource": False,
                "layer": "permission",
                "permission_source": "inline",
                "policy_arn": "",
                "policy_name": "AliceAdmin",
                "raw_conditions": {},
                "resource_pattern": role.provider_id,
                "statement_index": 0,
            },
        )

        scp = Constraint(
            provider=PROVIDER_AWS,
            constraint_type=CONSTRAINT_TYPE_SCP,
            scope_type="OU",
            scope_id="ou-abc123-prodou",
            policy_id="p-1234567890",
            statement_id="DenyAssumeRole",
            region=REGION_GLOBAL,
            properties={
                "deny_actions": ["sts:AssumeRole"],
                "deny_not_actions": [],
                "exception_principal_patterns": [],
                "parse_status": "complete",
                "policy_name": "DenyAssumeRoleProd",
                "resource_patterns": ["*"],
            },
            status="ACTIVE",
            validation_status="UNVALIDATED",
            confidence_q=800,
        )
        ec = EdgeConstraint(
            edge_id=trust_edge.edge_id,
            constraint_id=scp.constraint_id,
            governance_confidence="complete",
            likely_blocking=True,
            binding_reason="edge action sts:AssumeRole in SCP deny_actions",
        )
        meta = ScenarioMetadata(
            collector="iamscope",
            collector_version="0.2.0",
            id_algorithm="sha256_null_separated_v2",
            org_id="o-golden",
            accounts_collected=2,
            collection_timestamp="2026-01-01T00:00:00Z",
            collection_duration_seconds=1.0,
            noise_filter={"exclude_service_linked": True, "expansion_mode": "warn"},
            graph_stats={"total_edges": 2, "total_nodes": 3},
        )

        scenario_bytes, canonical_hash = emit_scenario(
            nodes=[role, acct_root, alice],
            edges=[trust_edge, permission_edge],
            constraints=[scp],
            edge_constraints=[ec],
            metadata=meta,
        )

        golden_path = GOLDEN_DIR / "minimal_scenario.json"
        golden_bytes = golden_path.read_bytes()

        assert scenario_bytes == golden_bytes, "Regenerated scenario does not match golden fixture byte-for-byte!"
