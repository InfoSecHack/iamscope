"""Tests for resource policy parsing."""

from __future__ import annotations

from iamscope.models import ResourcePolicyDocument
from iamscope.parser.resource_policy import parse_resource_policy_document


def test_parse_simple_s3_bucket_policy_allow() -> None:
    policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Sid": "AllowPartnerRead",
                "Effect": "Allow",
                "Principal": {"AWS": "arn:aws:iam::222222\u003222222:role/Partner"},
                "Action": "s3:GetObject",
                "Resource": "arn:aws:s3:::demo-bucket/*",
            }
        ],
    }
    doc = ResourcePolicyDocument(
        target_arn="arn:aws:s3:::demo-bucket",
        policy_document=policy,
        policy_source="s3_bucket_policy",
        account_id="111111\u003111111",
        region="-",
        resource_type="S3Bucket",
        policy_name="bucket-policy:demo-bucket",
    )

    results = parse_resource_policy_document(doc)

    assert len(results) == 1
    result = results[0]
    assert result.target_arn == "arn:aws:s3:::demo-bucket"
    assert result.principal_value == "arn:aws:iam::222222\u003222222:role/Partner"
    assert result.resolved_node_type == "IAMRole"
    assert result.action == "s3:GetObject"
    assert result.resource_pattern == "arn:aws:s3:::demo-bucket/*"
    assert result.statement_sid == "AllowPartnerRead"
    assert result.has_conditions is False
    assert len(result.statement_digest) == 64


def test_parse_condition_bearing_resource_policy() -> None:
    policy = {
        "Statement": [
            {
                "Effect": "Allow",
                "Principal": {"AWS": "222222\u003222222"},
                "Action": ["kms:Decrypt", "kms:DescribeKey"],
                "Resource": "*",
                "Condition": {
                    "StringEquals": {"kms:ViaService": "secretsmanager.us-east-1.amazonaws.com"},
                },
            }
        ],
    }
    doc = ResourcePolicyDocument(
        target_arn="arn:aws:kms:us-east-1:111111\u003111111:key/abc",
        policy_document=policy,
        policy_source="kms_key_policy",
        account_id="111111\u003111111",
        region="us-east-1",
        resource_type="KMSKey",
    )

    results = parse_resource_policy_document(doc)

    assert len(results) == 2
    assert {r.action for r in results} == {"kms:Decrypt", "kms:DescribeKey"}
    assert all(r.has_conditions for r in results)
    assert all(r.resolved_node_type == "AccountPrincipalSet" for r in results)
    assert results[0].raw_conditions == {
        "StringEquals": {"kms:ViaService": "secretsmanager.us-east-1.amazonaws.com"},
    }


def test_resource_policy_deny_does_not_create_allow_rows() -> None:
    doc = ResourcePolicyDocument(
        target_arn="arn:aws:s3:::demo-bucket",
        policy_document={
            "Statement": [
                {
                    "Effect": "Deny",
                    "Principal": "*",
                    "Action": "s3:GetObject",
                    "Resource": "arn:aws:s3:::demo-bucket/*",
                }
            ],
        },
        policy_source="s3_bucket_policy",
        account_id="111111\u003111111",
        region="-",
        resource_type="S3Bucket",
    )

    assert parse_resource_policy_document(doc) == []


def test_mixed_allow_and_deny_policy_only_returns_allow_rows() -> None:
    doc = ResourcePolicyDocument(
        target_arn="arn:aws:s3:::demo-bucket",
        policy_document={
            "Statement": [
                {
                    "Sid": "DenyPartnerRead",
                    "Effect": "Deny",
                    "Principal": {"AWS": "arn:aws:iam::222222\u003222222:role/Partner"},
                    "Action": "s3:GetObject",
                    "Resource": "arn:aws:s3:::demo-bucket/*",
                },
                {
                    "Sid": "AllowPartnerList",
                    "Effect": "Allow",
                    "Principal": {"AWS": "arn:aws:iam::222222\u003222222:role/Partner"},
                    "Action": "s3:ListBucket",
                    "Resource": "arn:aws:s3:::demo-bucket",
                },
            ],
        },
        policy_source="s3_bucket_policy",
        account_id="111111\u003111111",
        region="-",
        resource_type="S3Bucket",
    )

    results = parse_resource_policy_document(doc)

    assert len(results) == 1
    assert results[0].effect == "Allow"
    assert results[0].action == "s3:ListBucket"
    assert results[0].statement_sid == "AllowPartnerList"
