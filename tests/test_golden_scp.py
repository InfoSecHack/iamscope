"""Golden fixture test for SCP binding scenario.

Pins the canonical hash and file hash for the SCP binding scenario.
Any change to serialization, binding logic, or constraint format
will cause these tests to fail — forcing explicit review.
"""

import hashlib
import json
from pathlib import Path

from iamscope.constants import (
    CONSTRAINT_TYPE_SCP,
    NODE_TYPE_ACCOUNT_ROOT,
    NODE_TYPE_IAM_ROLE,
    NODE_TYPE_IAM_USER,
    PROVIDER_AWS,
)
from iamscope.identity.statement_digest import statement_digest
from iamscope.models import (
    Constraint,
    ControlRef,
    Edge,
    Node,
    ScenarioMetadata,
)
from iamscope.output.scenario_json import emit_scenario
from iamscope.resolver.scp_binder import bind_scp_to_edge

GOLDEN_PATH = Path(__file__).parent / "fixtures" / "expected_output" / "scp_binding_scenario.json"

PINNED_CANONICAL_HASH = "c2c40451ac7ef118f5c06c4581baff29a58306c9d6fefb8ab6fae6feed0fbdf0"
# Re-pinned in v0.2.29 after BUG-013 added `collection_failures` to
# ScenarioMetadata. canonical_hash unchanged — metadata is excluded
# from the canonical hash — but the raw file bytes now include the
# new empty-list field. Re-pinned again in v0.2.37 (Session 2 edge_id
# v1→v2) — edge_ids in the fixture changed when features became part
# of the hash, cascading into a new canonical_hash AND a new raw file
# hash. Structural content is unchanged — same 2 edges, same features,
# same SCP bindings.
PINNED_FILE_HASH = "68469b9dbbcacfab4033f5320b1ce18275a34a69e1e0e43af9f5bb5a4d0a7220"


class TestSCPBindingGolden:
    """Golden fixture tests for the SCP binding scenario."""

    def test_golden_file_exists(self) -> None:
        assert GOLDEN_PATH.exists()

    def test_golden_valid_json(self) -> None:
        data = GOLDEN_PATH.read_bytes()
        doc = json.loads(data)
        assert "nodes" in doc
        assert "edges" in doc
        assert "constraints" in doc
        assert "edge_constraints" in doc

    def test_canonical_hash_pinned(self) -> None:
        data = GOLDEN_PATH.read_bytes()
        doc = json.loads(data)
        assert doc["metadata"]["canonical_hash"] == PINNED_CANONICAL_HASH

    def test_file_hash_pinned(self) -> None:
        data = GOLDEN_PATH.read_bytes()
        assert hashlib.sha256(data).hexdigest() == PINNED_FILE_HASH

    def test_no_trailing_newline(self) -> None:
        data = GOLDEN_PATH.read_bytes()
        assert not data.endswith(b"\n")

    def test_two_edge_constraints(self) -> None:
        """Fixture must contain exactly 2 SCP bindings."""
        data = GOLDEN_PATH.read_bytes()
        doc = json.loads(data)
        assert len(doc["edge_constraints"]) == 2

    def test_no_binding_metadata_in_scenario(self) -> None:
        """edge_constraints must NOT contain binding_metadata (ARF-RT extra=forbid).

        Governance data (likely_blocking, governance_confidence) is computed
        internally but emitted in a separate sidecar file, not in scenario.json.
        """
        data = GOLDEN_PATH.read_bytes()
        doc = json.loads(data)
        for ec in doc["edge_constraints"]:
            assert "binding_metadata" not in ec
            # Only edge_id and constraint_id
            assert set(ec.keys()) == {"edge_id", "constraint_id"}

    def test_code_reproduces_golden_bytes(self) -> None:
        """Code produces byte-identical output to the golden fixture.

        Post-S05: the reproducer now exercises both a trust edge and a
        permission edge with populated allow_controls ControlRef attribution.
        """
        role = Node(
            provider=PROVIDER_AWS,
            node_type=NODE_TYPE_IAM_ROLE,
            provider_id="arn:aws:iam::111111\u003111111:role/ProdDeploy",
            properties={"account_id": "111111\u003111111", "is_synthetic": False, "path": "/"},
        )
        acct_root = Node(
            provider=PROVIDER_AWS,
            node_type=NODE_TYPE_ACCOUNT_ROOT,
            provider_id="arn:aws:iam::222222\u003222222:root",
            properties={"account_id": "222222\u003222222", "is_synthetic": True, "principal_count": 50},
        )
        # S05 + D1 absorption: add Alice as a real user principal so the
        # permission edge exercises the post-S01 raw_conditions + post-S05
        # allow_controls shape end-to-end.
        alice = Node(
            provider=PROVIDER_AWS,
            node_type=NODE_TYPE_IAM_USER,
            provider_id="arn:aws:iam::111111\u003111111:user/Alice",
            properties={"account_id": "111111\u003111111", "is_synthetic": False, "path": "/"},
        )

        # Trust statement → digest → ControlRef dict.
        trust_statement = {
            "Effect": "Allow",
            "Principal": {"AWS": "arn:aws:iam::222222\u003222222:root"},
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
            features={
                "allow_controls": [trust_control_ref],
                "cross_account": True,
                "has_external_id": False,
                "layer": "trust",
                "naked_trust": "BROAD_NAKED",
                "trust_scope": "account_root",
            },
        )

        # Permission statement → digest → ControlRef dict.
        perm_statement = {
            "Effect": "Allow",
            "Action": "sts:AssumeRole",
            "Resource": role.provider_id,
        }
        perm_digest = statement_digest(perm_statement)
        perm_control_ref = ControlRef(
            control_type="IDENTITY_POLICY",
            policy_arn=None,  # inline
            statement_index=0,
            digest=perm_digest,
            summary="inline:AliceAssume",
        ).to_dict()

        permission_edge = Edge(
            edge_type="sts:AssumeRole_permission",
            src=alice.to_ref(),
            dst=role.to_ref(),
            features={
                "action_matched_via": "exact",
                "allow_controls": [perm_control_ref],
                "effect": "Allow",
                "has_conditions": False,
                "is_wildcard_resource": False,
                "layer": "permission",
                "permission_source": "inline",
                "policy_arn": "",
                "policy_name": "AliceAssume",
                "raw_conditions": {},
                "resource_pattern": role.provider_id,
                "statement_index": 0,
            },
        )

        scp_blocking = Constraint(
            provider=PROVIDER_AWS,
            constraint_type=CONSTRAINT_TYPE_SCP,
            scope_type="OU",
            scope_id="ou-prod",
            policy_id="p-block",
            statement_id="DenyAssumeRole",
            properties={
                "deny_actions": ["sts:AssumeRole"],
                "deny_not_actions": [],
                "exception_principal_patterns": [],
                "parse_status": "complete",
                "resource_patterns": ["*"],
            },
            status="ACTIVE",
            validation_status="UNVALIDATED",
            confidence_q=800,
        )
        scp_exception = Constraint(
            provider=PROVIDER_AWS,
            constraint_type=CONSTRAINT_TYPE_SCP,
            scope_type="OU",
            scope_id="ou-prod",
            policy_id="p-except",
            statement_id="DenyAllStsExceptBreakGlass",
            properties={
                "deny_actions": ["sts:*"],
                "deny_not_actions": [],
                "exception_principal_patterns": ["arn:aws:iam::*:role/BreakGlass*"],
                "parse_status": "complete",
                "resource_patterns": ["*"],
            },
            status="ACTIVE",
            validation_status="UNVALIDATED",
            confidence_q=500,
        )
        ec1 = bind_scp_to_edge(trust_edge, scp_blocking)
        ec2 = bind_scp_to_edge(trust_edge, scp_exception)
        edge_constraints = [ec for ec in [ec1, ec2] if ec is not None]

        meta = ScenarioMetadata(
            collector="iamscope",
            collector_version="0.2.0",
            id_algorithm="sha256_null_separated_v2",
            org_id="o-golden-scp",
            accounts_collected=2,
            collection_timestamp="2026-01-01T00:00:00Z",
            collection_duration_seconds=2.0,
            noise_filter={"exclude_service_linked": True, "expansion_mode": "warn"},
            graph_stats={"total_edges": 2, "total_nodes": 3},
        )

        scenario_bytes, canonical_hash = emit_scenario(
            nodes=[role, acct_root, alice],
            edges=[trust_edge, permission_edge],
            constraints=[scp_blocking, scp_exception],
            edge_constraints=edge_constraints,
            metadata=meta,
        )

        golden_bytes = GOLDEN_PATH.read_bytes()
        assert json.loads(scenario_bytes) == json.loads(golden_bytes)
        assert canonical_hash == PINNED_CANONICAL_HASH
