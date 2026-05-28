"""IAMScope collector module."""

from iamscope.collector.account import AccountData, collect_account
from iamscope.collector.ec2_collector import collect_instance_profiles
from iamscope.collector.kms_collector import collect_kms_keys
from iamscope.collector.lambda_collector import collect_lambda_functions
from iamscope.collector.organization import collect_organization
from iamscope.collector.passrole import build_permission_edges
from iamscope.collector.s3_collector import collect_s3_buckets
from iamscope.collector.secrets_collector import collect_secrets

__all__ = [
    "AccountData",
    "build_permission_edges",
    "collect_account",
    "collect_instance_profiles",
    "collect_kms_keys",
    "collect_lambda_functions",
    "collect_organization",
    "collect_s3_buckets",
    "collect_secrets",
]
