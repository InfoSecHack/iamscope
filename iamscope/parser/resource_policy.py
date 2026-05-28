"""Resource policy parser for non-role resource-based allow edges."""

from __future__ import annotations

import json
from typing import Any, cast

from iamscope.constants import (
    NODE_TYPE_ACCOUNT_ROOT,
    NODE_TYPE_AWS_SERVICE,
    NODE_TYPE_EXTERNAL_ACCOUNT,
    NODE_TYPE_IAM_ROLE,
    NODE_TYPE_IAM_USER,
    NODE_TYPE_KMS_KEY,
    NODE_TYPE_LAMBDA_FUNCTION,
    NODE_TYPE_S3_BUCKET,
    NODE_TYPE_SECRETS_MANAGER_SECRET,
    NODE_TYPE_WILDCARD_PRINCIPAL,
)
from iamscope.identity.statement_digest import statement_digest
from iamscope.models import ResourcePolicyDocument, ResourcePolicyParseResult
from iamscope.parser.parse_failures import PolicyParseFailure, make_parse_failure


def parse_resource_policy_document(
    resource_policy: ResourcePolicyDocument,
    failures: list[PolicyParseFailure] | None = None,
) -> list[ResourcePolicyParseResult]:
    """Parse Allow statements from a collected resource policy document."""
    doc, failure_kind, exception = _parse_document(resource_policy.policy_document)
    if doc is None:
        if failures is not None:
            failures.append(
                make_parse_failure(
                    parser="resource_policy",
                    source_arn=resource_policy.target_arn,
                    policy_source=resource_policy.policy_source,
                    failure_kind=failure_kind,
                    exception=exception,
                )
            )
        return []

    statements = doc.get("Statement")
    if not statements:
        return []
    if isinstance(statements, dict):
        statements = [statements]
    if not isinstance(statements, list):
        if failures is not None:
            failures.append(
                make_parse_failure(
                    parser="resource_policy",
                    source_arn=resource_policy.target_arn,
                    policy_source=resource_policy.policy_source,
                    failure_kind="invalid_statement_type",
                )
            )
        return []

    results: list[ResourcePolicyParseResult] = []
    for statement_index, statement in enumerate(statements):
        if not isinstance(statement, dict):
            continue
        if statement.get("Effect") != "Allow":
            continue
        principals = _resolve_principals(statement.get("Principal"))
        if not principals:
            continue
        actions = _string_list(statement.get("Action", "*"))
        resources = _string_list(statement.get("Resource", resource_policy.target_arn))
        raw_conditions = _canonical_conditions(statement.get("Condition"))
        has_conditions = bool(raw_conditions)
        digest = statement_digest(statement)
        statement_sid_raw = statement.get("Sid")
        statement_sid = str(statement_sid_raw) if statement_sid_raw is not None else None

        for principal_type, principal_value, node_type in principals:
            for action in actions:
                for resource_pattern in resources:
                    results.append(
                        ResourcePolicyParseResult(
                            target_arn=resource_policy.target_arn,
                            target_node_type=_infer_target_node_type(resource_policy.target_arn),
                            policy_source=resource_policy.policy_source,
                            policy_name=resource_policy.policy_name,
                            account_id=resource_policy.account_id,
                            region=resource_policy.region,
                            statement_index=statement_index,
                            statement_sid=statement_sid,
                            effect="Allow",
                            principal_type=principal_type,
                            principal_value=principal_value,
                            resolved_node_type=node_type,
                            action=str(action),
                            resource_pattern=str(resource_pattern),
                            has_conditions=has_conditions,
                            raw_conditions=raw_conditions,
                            parse_status="complete",
                            statement_digest=digest,
                        )
                    )
    return results


def parse_resource_policy_documents(
    resource_policies: list[ResourcePolicyDocument],
    failures: list[PolicyParseFailure] | None = None,
) -> list[ResourcePolicyParseResult]:
    """Parse multiple resource policy documents deterministically."""
    results: list[ResourcePolicyParseResult] = []
    for resource_policy in sorted(resource_policies, key=lambda p: (p.target_arn, p.policy_source)):
        results.extend(parse_resource_policy_document(resource_policy, failures=failures))
    return results


def _parse_document(
    policy_document: str | dict[str, Any],
) -> tuple[dict[str, Any] | None, str, BaseException | None]:
    if isinstance(policy_document, dict):
        return policy_document, "", None
    try:
        parsed = json.loads(policy_document)
    except (json.JSONDecodeError, TypeError) as exc:
        return None, "json_decode_error", exc
    if not isinstance(parsed, dict):
        return None, "non_dict_policy", None
    return parsed, "", None


def _resolve_principals(principal: Any) -> list[tuple[str, str, str]]:
    if principal is None:
        return []
    if principal == "*":
        return [("AWS", "*", NODE_TYPE_WILDCARD_PRINCIPAL)]
    if isinstance(principal, str):
        return [("AWS", principal, _node_type_for_aws_principal(principal))]
    if not isinstance(principal, dict):
        return []

    results: list[tuple[str, str, str]] = []
    for key, value in principal.items():
        values = _string_list(value)
        for item in values:
            if key == "AWS":
                results.append(("AWS", item, _node_type_for_aws_principal(item)))
            elif key == "Service":
                results.append(("Service", item, NODE_TYPE_AWS_SERVICE))
            elif key == "Federated":
                results.append(("Federated", item, NODE_TYPE_EXTERNAL_ACCOUNT))
            elif key == "CanonicalUser":
                results.append(("CanonicalUser", item, NODE_TYPE_EXTERNAL_ACCOUNT))
    return results


def _node_type_for_aws_principal(value: str) -> str:
    if value == "*":
        return NODE_TYPE_WILDCARD_PRINCIPAL
    if value.isdigit() and len(value) == 12:
        return NODE_TYPE_ACCOUNT_ROOT
    if value.endswith(":root"):
        return NODE_TYPE_ACCOUNT_ROOT
    if ":role/" in value:
        return NODE_TYPE_IAM_ROLE
    if ":user/" in value:
        return NODE_TYPE_IAM_USER
    return NODE_TYPE_EXTERNAL_ACCOUNT


def _infer_target_node_type(arn: str) -> str:
    if ":s3:::" in arn:
        return NODE_TYPE_S3_BUCKET
    if ":key/" in arn:
        return NODE_TYPE_KMS_KEY
    if ":secret:" in arn:
        return NODE_TYPE_SECRETS_MANAGER_SECRET
    if ":function:" in arn or ":function/" in arn:
        return NODE_TYPE_LAMBDA_FUNCTION
    return NODE_TYPE_EXTERNAL_ACCOUNT


def _string_list(value: Any) -> list[str]:
    if value is None:
        return []
    if isinstance(value, list):
        return [str(v) for v in value]
    return [str(value)]


def _canonical_conditions(value: Any) -> dict[str, Any]:
    if not value:
        return {}
    if not isinstance(value, dict):
        return {"_unsupported_condition": value}
    canonical = json.loads(json.dumps(value, sort_keys=True, separators=(",", ":")))
    return cast(dict[str, Any], canonical)
