"""SCP policy parser — parses Service Control Policy documents into SCPParseResult objects.

Handles all real-world SCP patterns per architecture doc §5.5, Decision 3:
- Standard Deny + Action list + Resource *  → parse_status="complete"
- NotAction (inverted deny semantics)       → parse_status="partial"
- Non-wildcard resources                    → parse_status="partial"
- Unrecognized condition keys               → parse_status="partial"
- Complex patterns we can't evaluate        → parse_status="unsupported"

Exception extraction from Condition blocks:
- ArnNotLike / StringNotLike on aws:PrincipalArn → exception_principal_patterns
- StringNotEquals on aws:PrincipalOrgID           → exception_org_ids
- StringNotEquals on aws:SourceAccount            → exception_account_ids

Applicability extraction from Condition blocks:
- ArnLike / StringLike / ArnEquals / StringEquals on aws:PrincipalArn
  → applicable_principal_patterns

Allow statements in SCPs are skipped (they're the default SCP; we only
care about explicit Deny statements for governance modeling).

CRITICAL correctness rule (NotAction inversion):
  When an SCP uses NotAction, everything NOT in the list IS denied.
  deny_not_actions stores the exception list (actions NOT denied).
  The binder checks: if edge action NOT in deny_not_actions → it IS denied.
  Getting this backwards silently misclassifies SCP governance.

All parsing is deterministic: same SCP document → same results.
"""

from __future__ import annotations

import json
import logging
from typing import Any

from iamscope.constants import (
    PARSE_STATUS_COMPLETE,
    PARSE_STATUS_PARTIAL,
    PARSE_STATUS_UNSUPPORTED,
)
from iamscope.models import SCPParseResult

logger = logging.getLogger(__name__)

# Condition operators that extract exception patterns for aws:PrincipalArn
_PRINCIPAL_EXCEPTION_OPERATORS: frozenset[str] = frozenset(
    {
        "ArnNotLike",
        "StringNotLike",
    }
)

# Positive PrincipalArn filters that narrow which principals a Deny applies to.
_PRINCIPAL_APPLICABILITY_OPERATORS: frozenset[str] = frozenset(
    {
        "ArnLike",
        "StringLike",
        "ArnEquals",
        "StringEquals",
    }
)

# Condition key → SCPParseResult field for exception extraction
_EXCEPTION_KEY_FIELD_MAP: dict[str, str] = {
    "aws:PrincipalArn": "exception_principal_patterns",
    "aws:PrincipalOrgID": "exception_org_ids",
    "aws:SourceAccount": "exception_account_ids",
}

# Operators that trigger exception extraction for org/account IDs
_NEGATION_OPERATORS: frozenset[str] = frozenset(
    {
        "ArnNotLike",
        "StringNotLike",
        "StringNotEquals",
    }
)


def parse_scp_document(
    policy_document: str | dict[str, Any],
    policy_id: str = "",
    policy_name: str = "",
) -> list[SCPParseResult]:
    """Parse an SCP policy document into structured SCPParseResult objects.

    Each Deny statement produces one SCPParseResult. Allow statements
    are skipped. Multiple statements → multiple results.

    Args:
        policy_document: SCP policy as a JSON string or parsed dict.
        policy_id: SCP policy ID (e.g., "p-1234567890").
        policy_name: SCP policy name (informational).

    Returns:
        List of SCPParseResult objects, ordered by statement index.
        Empty list if the policy is malformed or has no Deny statements.
    """
    doc = _parse_document(policy_document)
    if doc is None:
        logger.warning("Malformed SCP document for policy %s: could not parse", policy_id)
        return []

    statements = doc.get("Statement")
    if not statements:
        logger.debug("No statements in SCP %s", policy_id)
        return []

    # Normalize single statement to list
    if isinstance(statements, dict):
        statements = [statements]

    if not isinstance(statements, list):
        logger.warning("Invalid Statement field in SCP %s", policy_id)
        return []

    results: list[SCPParseResult] = []

    for stmt_index, statement in enumerate(statements):
        if not isinstance(statement, dict):
            logger.warning(
                "Statement %d in SCP %s is not a dict, skipping",
                stmt_index,
                policy_id,
            )
            continue

        result = _parse_scp_statement(statement, policy_id, stmt_index)
        if result is not None:
            results.append(result)

    return results


def _parse_scp_statement(
    statement: dict[str, Any],
    policy_id: str,
    stmt_index: int,
) -> SCPParseResult | None:
    """Parse a single SCP statement into an SCPParseResult.

    Only processes Deny statements. Returns None for Allow or
    unrecognized Effect values.

    Args:
        statement: A single statement dict from the SCP.
        policy_id: Parent policy ID for logging.
        stmt_index: Index of this statement (0-based).

    Returns:
        SCPParseResult or None if the statement should be skipped.
    """
    effect = statement.get("Effect", "")

    # Only process Deny statements
    if effect != "Deny":
        logger.debug(
            "Skipping %s statement %d in SCP %s",
            effect,
            stmt_index,
            policy_id,
        )
        return None

    # Extract statement ID
    statement_id = statement.get("Sid", f"stmt_{stmt_index}")

    # Initialize tracking
    parse_status = PARSE_STATUS_COMPLETE
    parse_warnings: list[str] = []

    # --- Action / NotAction ---
    deny_actions: list[str] = []
    deny_not_actions: list[str] = []

    if "Action" in statement:
        deny_actions = _normalize_to_list(statement["Action"])
    elif "NotAction" in statement:
        deny_not_actions = _normalize_to_list(statement["NotAction"])
        # NotAction inverts semantics — everything NOT listed IS denied
        # This is complex enough to warrant partial status
        parse_status = PARSE_STATUS_PARTIAL
        parse_warnings.append("Uses NotAction — inverted deny semantics")
    else:
        # No Action or NotAction — unusual, can't evaluate
        parse_status = PARSE_STATUS_UNSUPPORTED
        parse_warnings.append("No Action or NotAction field in Deny statement")

    # --- Resource ---
    resource_field = statement.get("Resource", "*")
    resource_patterns = _normalize_to_list(resource_field)

    # Non-wildcard resources reduce parse confidence
    if resource_patterns != ["*"]:
        if parse_status == PARSE_STATUS_COMPLETE:
            parse_status = PARSE_STATUS_PARTIAL
        parse_warnings.append(f"Non-wildcard resource patterns: {resource_patterns}")

    # --- Condition (exception extraction) ---
    condition_block = statement.get("Condition")
    (
        exception_principal_patterns,
        exception_org_ids,
        exception_account_ids,
        applicable_principal_patterns,
        unhandled_keys,
        raw_conditions,
    ) = _extract_scp_exceptions(condition_block)

    # Unhandled condition keys reduce parse confidence
    if unhandled_keys:
        if parse_status == PARSE_STATUS_COMPLETE:
            parse_status = PARSE_STATUS_PARTIAL
        parse_warnings.append(f"Unhandled condition keys: {sorted(unhandled_keys)}")

    return SCPParseResult(
        statement_id=statement_id,
        effect="Deny",
        deny_actions=deny_actions,
        deny_not_actions=deny_not_actions,
        resource_patterns=resource_patterns,
        exception_principal_patterns=exception_principal_patterns,
        exception_org_ids=exception_org_ids,
        exception_account_ids=exception_account_ids,
        applicable_principal_patterns=applicable_principal_patterns,
        raw_conditions=raw_conditions,
        parse_status=parse_status,
        parse_warnings=parse_warnings,
    )


def _extract_scp_exceptions(
    condition_block: dict[str, Any] | None,
) -> tuple[list[str], list[str], list[str], list[str], list[str], dict[str, Any]]:
    """Extract exception patterns from an SCP Condition block.

    Recognized exception patterns:
    - ArnNotLike/StringNotLike on aws:PrincipalArn → principal exception patterns
    - StringNotEquals on aws:PrincipalOrgID → org ID exceptions
    - StringNotEquals on aws:SourceAccount → account ID exceptions
    - ArnLike/StringLike/ArnEquals/StringEquals on aws:PrincipalArn
      → principal applicability patterns

    Any other condition keys are returned as unhandled_keys.

    Args:
        condition_block: The Condition dict, or None.

    Returns:
        Tuple of:
        - exception_principal_patterns: list[str]
        - exception_org_ids: list[str]
        - exception_account_ids: list[str]
        - applicable_principal_patterns: list[str]
        - unhandled_keys: list[str] (condition keys we don't recognize)
        - raw_conditions: dict (canonicalized condition block)
    """
    exception_principal_patterns: list[str] = []
    exception_org_ids: list[str] = []
    exception_account_ids: list[str] = []
    applicable_principal_patterns: list[str] = []
    unhandled_keys: list[str] = []

    if not condition_block or not isinstance(condition_block, dict):
        return (
            exception_principal_patterns,
            exception_org_ids,
            exception_account_ids,
            applicable_principal_patterns,
            unhandled_keys,
            {},
        )

    # Canonicalize raw conditions for deterministic storage
    raw_conditions = _canonicalize_dict(condition_block)

    for operator, key_value_map in condition_block.items():
        if not isinstance(key_value_map, dict):
            continue

        is_negation_operator = operator in _NEGATION_OPERATORS
        is_principal_exception_operator = operator in _PRINCIPAL_EXCEPTION_OPERATORS
        is_principal_applicability_operator = operator in _PRINCIPAL_APPLICABILITY_OPERATORS

        for condition_key, values in key_value_map.items():
            values_list = _normalize_to_list(values)

            handled = False

            # aws:PrincipalArn with ArnNotLike or StringNotLike
            if condition_key == "aws:PrincipalArn" and is_principal_exception_operator:
                exception_principal_patterns.extend(values_list)
                handled = True

            # aws:PrincipalArn with positive matching operators narrows
            # which principals the Deny statement applies to.
            elif condition_key == "aws:PrincipalArn" and is_principal_applicability_operator:
                applicable_principal_patterns.extend(values_list)
                handled = True

            # aws:PrincipalOrgID with StringNotEquals
            elif condition_key == "aws:PrincipalOrgID" and is_negation_operator:
                exception_org_ids.extend(values_list)
                handled = True

            # aws:SourceAccount with StringNotEquals
            elif condition_key == "aws:SourceAccount" and is_negation_operator:
                exception_account_ids.extend(values_list)
                handled = True

            if not handled:
                unhandled_keys.append(condition_key)

    return (
        exception_principal_patterns,
        exception_org_ids,
        exception_account_ids,
        applicable_principal_patterns,
        unhandled_keys,
        raw_conditions,
    )


def _normalize_to_list(value: Any) -> list[str]:
    """Normalize a string-or-list field to a list of strings.

    Handles the AWS policy convention where a field can be either
    a single string or a list of strings.
    """
    if isinstance(value, str):
        return [value]
    if isinstance(value, list):
        return [str(v) for v in value]
    return [str(value)]


def _parse_document(policy_document: str | dict[str, Any]) -> dict[str, Any] | None:
    """Parse policy document from string or dict. Returns None if malformed."""
    if isinstance(policy_document, dict):
        return policy_document
    if isinstance(policy_document, str):
        try:
            parsed = json.loads(policy_document)
            if isinstance(parsed, dict):
                return parsed
            return None
        except (json.JSONDecodeError, TypeError):
            return None
    return None


def _canonicalize_dict(d: dict[str, Any]) -> dict[str, Any]:
    """Canonicalize a dict via JSON round-trip for deterministic storage."""
    canonical_str = json.dumps(d, sort_keys=True, separators=(",", ":"), ensure_ascii=True)
    result: dict[str, Any] = json.loads(canonical_str)
    return result
