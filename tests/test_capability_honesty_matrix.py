from pathlib import Path

from iamscope import cli
from iamscope.parser import permission_policy

MATRIX = Path("docs/reference/capability-honesty-matrix.md")


def _matrix_text() -> str:
    return MATRIX.read_text(encoding="utf-8")


def test_matrix_documents_all_parser_relevant_actions() -> None:
    text = _matrix_text()

    expected_actions = {permission_policy._canonicalize_action(action) for action in permission_policy.RELEVANT_ACTIONS}

    for action in sorted(expected_actions):
        assert f"`{action}`" in text


def test_matrix_documents_all_shipped_reasoner_pattern_ids() -> None:
    text = _matrix_text()

    for pattern_id in sorted(cli._AVAILABLE_REASONER_FACTORIES):
        assert f"`{pattern_id}`" in text


def test_matrix_documents_required_explicit_noncoverage_examples() -> None:
    text = _matrix_text()

    for action in (
        "iam:CreateAccessKey",
        "iam:PutRolePolicy",
        "iam:UpdateAssumeRolePolicy",
        "sts:GetFederationToken",
    ):
        assert f"`{action}`" in text


def test_matrix_contains_required_honesty_language() -> None:
    text = _matrix_text()
    lower_text = text.lower()

    assert "No findings" in text
    assert "does not mean the account is safe" in text
    assert "not exploitability proof" in lower_text
    assert "collection_context" in text
    assert "org_membership_status" in text
    assert "resource-policy" in lower_text
    assert "no composite score" in lower_text
    assert "no pass/fail benchmark label" in lower_text
