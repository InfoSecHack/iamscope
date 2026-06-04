"""Regression evidence for case-sensitive ARN deterministic ID collisions."""

from iamscope.constants import ID_ALGORITHM
from iamscope.identity.deterministic_ids import edge_id, node_id

_EMPTY_FEATURES_DIGEST = "{}"


def test_case_distinct_iam_role_provider_ids_do_not_collide_under_node_id() -> None:
    upper_role = node_id(
        "aws",
        "IAMRole",
        "arn:aws:iam::000000000000:role/CaseRole",
    )
    lower_role = node_id(
        "aws",
        "IAMRole",
        "arn:aws:iam::000000000000:role/caserole",
    )

    assert upper_role != lower_role


def test_case_distinct_iam_user_provider_ids_do_not_collide_under_node_id() -> None:
    upper_user = node_id(
        "aws",
        "IAMUser",
        "arn:aws:iam::000000000000:user/CaseUser",
    )
    lower_user = node_id(
        "aws",
        "IAMUser",
        "arn:aws:iam::000000000000:user/caseuser",
    )

    assert upper_user != lower_user


def test_case_distinct_source_provider_ids_do_not_collide_under_edge_id() -> None:
    upper_source = edge_id(
        "sts:AssumeRole_permission",
        "arn:aws:iam::000000000000:user/CaseUser",
        "arn:aws:iam::000000000000:role/TargetRole",
        "-",
        _EMPTY_FEATURES_DIGEST,
    )
    lower_source = edge_id(
        "sts:AssumeRole_permission",
        "arn:aws:iam::000000000000:user/caseuser",
        "arn:aws:iam::000000000000:role/TargetRole",
        "-",
        _EMPTY_FEATURES_DIGEST,
    )

    assert upper_source != lower_source


def test_case_distinct_destination_provider_ids_do_not_collide_under_edge_id() -> None:
    upper_destination = edge_id(
        "sts:AssumeRole_permission",
        "arn:aws:iam::000000000000:user/SourceUser",
        "arn:aws:iam::000000000000:role/CaseRole",
        "-",
        _EMPTY_FEATURES_DIGEST,
    )
    lower_destination = edge_id(
        "sts:AssumeRole_permission",
        "arn:aws:iam::000000000000:user/SourceUser",
        "arn:aws:iam::000000000000:role/caserole",
        "-",
        _EMPTY_FEATURES_DIGEST,
    )

    assert upper_destination != lower_destination


def test_exact_repeated_inputs_remain_deterministic() -> None:
    first_node_id = node_id(
        "aws",
        "IAMRole",
        "arn:aws:iam::000000000000:role/CaseRole",
    )
    second_node_id = node_id(
        "aws",
        "IAMRole",
        "arn:aws:iam::000000000000:role/CaseRole",
    )
    first_edge_id = edge_id(
        "sts:AssumeRole_permission",
        "arn:aws:iam::000000000000:user/CaseUser",
        "arn:aws:iam::000000000000:role/CaseRole",
        "-",
        _EMPTY_FEATURES_DIGEST,
    )
    second_edge_id = edge_id(
        "sts:AssumeRole_permission",
        "arn:aws:iam::000000000000:user/CaseUser",
        "arn:aws:iam::000000000000:role/CaseRole",
        "-",
        _EMPTY_FEATURES_DIGEST,
    )

    assert first_node_id == second_node_id
    assert first_edge_id == second_edge_id


def test_id_algorithm_exposes_v3_case_sensitive_provider_id_value() -> None:
    assert ID_ALGORITHM == "sha256_null_separated_v3_case_sensitive_provider_ids"
