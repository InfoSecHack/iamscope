"""Fix A regression tests — validate.py hash recomputation and
referential integrity for edge src/dst. v0.2.36."""

from __future__ import annotations

import json

from iamscope.models import (
    Edge,
    Node,
    NodeRef,
    ScenarioMetadata,
)
from iamscope.output.scenario_json import emit_scenario
from iamscope.pipeline import _materialize_dangling_endpoints
from iamscope.validate import validate_scenario


def _build_clean_scenario() -> dict:
    a = Node(provider="aws", node_type="IAMRole", provider_id="arn:aws:iam::111:role/A", region="-")
    b = Node(provider="aws", node_type="IAMRole", provider_id="arn:aws:iam::111:role/B", region="-")
    e = Edge(
        edge_type="sts:AssumeRole_trust",
        src=NodeRef(provider="aws", node_type="IAMRole", provider_id="arn:aws:iam::111:role/A", region="-"),
        dst=NodeRef(provider="aws", node_type="IAMRole", provider_id="arn:aws:iam::111:role/B", region="-"),
        region="-",
        features={"layer": "trust"},
    )
    md = ScenarioMetadata(
        collector="iamscope",
        collector_version="0.2.0",
        id_algorithm="sha256_null_separated_v2",
    )
    scenario_bytes, _ = emit_scenario(
        nodes=[a, b],
        edges=[e],
        constraints=[],
        edge_constraints=[],
        metadata=md,
    )
    return json.loads(scenario_bytes.decode("utf-8"))


class TestFixAValidate:
    def test_clean_scenario_validates(self) -> None:
        errors = validate_scenario(_build_clean_scenario())
        assert errors == [], f"clean scenario had errors: {errors}"

    def test_rejects_dst_missing_node(self) -> None:
        s = _build_clean_scenario()
        s["edges"][0]["dst"]["provider_id"] = "arn:aws:iam::111:role/DOES_NOT_EXIST"
        errors = validate_scenario(s)
        assert any("non-existent node" in e for e in errors), errors

    def test_rejects_fabricated_hash(self) -> None:
        s = _build_clean_scenario()
        s["metadata"]["canonical_hash"] = "a" * 64  # valid hex, wrong
        errors = validate_scenario(s)
        assert any("canonical_hash mismatch" in e for e in errors), errors

    def test_rejects_stale_hash_with_modified_content(self) -> None:
        """Realistic tamper: edit content but leave old hash in place."""
        s = _build_clean_scenario()
        # Mutate a node property without touching the hash.
        s["nodes"][0]["region"] = "us-west-2"
        errors = validate_scenario(s)
        assert any("canonical_hash mismatch" in e for e in errors), errors


class TestDanglingSrcMaterialization:
    """Fix A pipeline extension: _materialize_dangling_endpoints must
    symmetrically materialize src placeholders for trust edges whose
    trusting principal is a same-account IAM role/user not returned
    by the IAM collector (deleted, renamed, mid-Terraform-apply,
    org/IAM consistency drift).

    Pre-Fix-A the validator only checked dst, so such edges passed
    silently. Post-Fix-A rule 8b would reject them — the pipeline
    has to materialize the missing src before emission or it would
    regress v0.2.35 scans that used to work.

    These tests exercise `_materialize_dangling_endpoints` directly
    (white-box) because the full pipeline entry point would require
    constructing OrgData / AccountInfo / collector output, which is
    out of scope for a validator-layer regression test.
    """

    _ROLE_ACCOUNT = "111111111111"
    _TRUSTEE_ARN = f"arn:aws:iam::{_ROLE_ACCOUNT}:role/Trustee"
    _DELETED_ARN = f"arn:aws:iam::{_ROLE_ACCOUNT}:role/DeletedTrustor"

    def _build_stale_trust_edge(self) -> tuple[Node, Edge]:
        trustee = Node(
            provider="aws",
            node_type="IAMRole",
            provider_id=self._TRUSTEE_ARN,
            region="-",
            properties={"account_id": self._ROLE_ACCOUNT},
        )
        edge = Edge(
            edge_type="sts:AssumeRole_trust",
            src=NodeRef(
                provider="aws",
                node_type="IAMRole",
                provider_id=self._DELETED_ARN,
                region="-",
            ),
            dst=NodeRef(
                provider="aws",
                node_type="IAMRole",
                provider_id=self._TRUSTEE_ARN,
                region="-",
            ),
            region="-",
            features={"layer": "trust"},
        )
        return trustee, edge

    def test_materializes_synthetic_for_dangling_src(self) -> None:
        trustee, edge = self._build_stale_trust_edge()
        synthetic = _materialize_dangling_endpoints(
            nodes=[trustee],
            edges=[edge],
        )

        # Exactly one synthetic: the DeletedTrustor src. The dst
        # (Trustee) is already in the known set and must NOT be
        # re-materialized.
        assert len(synthetic) == 1
        s = synthetic[0]
        assert s.provider_id == self._DELETED_ARN
        assert s.node_type == "IAMRole"
        assert s.properties["is_synthetic"] is True
        assert s.properties["is_dangling_reference"] is True
        assert s.properties["collection_status"] == "not_collected"
        assert s.properties["account_id"] == self._ROLE_ACCOUNT

    def test_src_dangling_reason_mentions_trust_case(self) -> None:
        """Reviewer-facing: operators running a scan need to be able
        to tell a dangling-src synthetic apart from a dangling-dst
        synthetic. The dst reason mentions 'rds!' / 'unscanned region';
        the src reason mentions the trust-policy drift cases. Assert
        the src reason is present so the two codepaths are not mixed
        up by a future refactor."""
        trustee, edge = self._build_stale_trust_edge()
        synthetic = _materialize_dangling_endpoints(
            nodes=[trustee],
            edges=[edge],
        )
        reason = synthetic[0].properties["dangling_reason"]
        assert "trust" in reason or "same-account" in reason, reason

    def test_emitted_scenario_validates_clean(self) -> None:
        """End-to-end: materialize, emit, validate. Must return [].
        This is the regression guard — if the pipeline stops
        materializing src placeholders, emit_scenario will still
        produce bytes but validate_scenario (with rule 8b) will
        reject them. Any error here means Fix A regressed."""
        trustee, edge = self._build_stale_trust_edge()
        synthetic = _materialize_dangling_endpoints(
            nodes=[trustee],
            edges=[edge],
        )
        all_nodes = [trustee, *synthetic]

        md = ScenarioMetadata(
            collector="iamscope",
            collector_version="0.2.0",
            id_algorithm="sha256_null_separated_v2",
        )
        scenario_bytes, _ = emit_scenario(
            nodes=all_nodes,
            edges=[edge],
            constraints=[],
            edge_constraints=[],
            metadata=md,
        )
        scenario = json.loads(scenario_bytes.decode("utf-8"))

        errors = validate_scenario(scenario)
        assert errors == [], f"stale-trust scenario failed validation after materialization: {errors}"


class TestValidatorErrorMessageConventions:
    """Fix A convention: rule 5 and rule 8b error messages must
    carry the offending `edge_id`, not a bare list index. Operators
    triaging a failed scan need to grep the emitted scenario.json
    for the exact identifier, and list indices shift whenever the
    edge order changes.

    Also: the validator must never raise on malformed input. A
    tampered or hand-edited scenario.json may have `src`/`dst` as a
    non-dict; the validator's job is to report it as an error and
    keep going, not crash the caller."""

    def test_malformed_non_dict_src_returns_errors_not_raises(self) -> None:
        s = _build_clean_scenario()
        s["edges"][0]["src"] = "not-a-dict"
        # Must not raise AttributeError from `.get` on a string.
        errors = validate_scenario(s)
        assert errors, "validator silently accepted non-dict src"
        assert any("src is not a dict" in e for e in errors), f"expected non-dict src error, got: {errors}"

    def test_rule_8b_error_message_includes_edge_id(self) -> None:
        """Point a dst at a node that doesn't exist, then assert the
        rule 8b error string carries the real edge_id (not 'index N')."""
        s = _build_clean_scenario()
        real_edge_id = s["edges"][0]["edge_id"]
        assert real_edge_id, "test precondition: edge_id must be set"
        s["edges"][0]["dst"]["provider_id"] = "arn:aws:iam::111:role/NOPE"
        errors = validate_scenario(s)
        rule_8b_errors = [e for e in errors if "non-existent node" in e]
        assert rule_8b_errors, f"rule 8b did not fire: {errors}"
        assert any(real_edge_id in e for e in rule_8b_errors), (
            f"edge_id {real_edge_id} not in rule 8b errors: {rule_8b_errors}"
        )
        # And the old "Edge at index N" wording must be gone.
        assert not any("at index" in e for e in rule_8b_errors), f"rule 8b still using list index: {rule_8b_errors}"
