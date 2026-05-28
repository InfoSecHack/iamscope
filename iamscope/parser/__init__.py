"""IAMScope parsers — trust policies, permission policies, SCPs, conditions."""

from iamscope.parser.condition_extractor import ConditionSet, extract_conditions
from iamscope.parser.permission_policy import parse_permission_denies, parse_permission_policy
from iamscope.parser.scp_policy import parse_scp_document
from iamscope.parser.trust_policy import parse_trust_policy

__all__ = [
    "ConditionSet",
    "extract_conditions",
    "parse_permission_denies",
    "parse_permission_policy",
    "parse_scp_document",
    "parse_trust_policy",
]
