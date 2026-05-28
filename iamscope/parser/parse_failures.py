"""Structured policy parse failure records.

BUG-021 fix: the parser layer (`permission_policy.py`, `trust_policy.py`)
and the collector layer (`account.py`) collectively had at least six
sites where a malformed IAM policy JSON document was caught with a
bare `except json.JSONDecodeError` and either silently `continue`d
past the policy or returned an empty result list. The combined effect
was a false-negative cascade in the deepest layer of the tool:

  malformed policy
    → silent drop in parse_permission_policy or inline parse in account.py
    → no PermissionParseResult / TrustParseResult emitted
    → no permission edge / trust edge built in the resolver
    → reasoners never see the path
    → finding silently missing from findings.json

This is the worst class of bug for a security tool, because the
operator has no signal that anything went wrong — the scan just
quietly produces a smaller report.

This module defines the structured record that the parser layer
appends to an optional `failures` list passed in by the collector.
The collector aggregates per-account failures into `AccountData`,
the pipeline aggregates per-account lists into a single bundle list,
and the bundle list is surfaced in two places:

1. `PipelineResult.policy_parse_failures` — so CLI callers can
   fail loud or render a visible summary.
2. `ScenarioMetadata.policy_parse_failures` — embedded in
   scenario.json so downstream consumers (reasoners, reports,
   diffs) can see that the fact graph was built from a partially
   parseable input. Safe to embed because metadata is excluded
   from `canonical_hash`.

Scope of the v0.2.31 fix:

- `permission_policy.parse_permission_policy` JSON-decode failures
- `permission_policy.parse_permission_policy` non-dict-root failures
- `trust_policy.parse_trust_policy` JSON-decode + invalid-root failures
- `trust_policy.parse_trust_policy` invalid Statement field failures
- The redundant inline `try/except json.JSONDecodeError: continue`
  patterns in `account.py` are deleted entirely — the parser layer
  now handles string→dict + failure tracking, so the collector
  can pass the raw policy document straight through.

Explicitly NOT covered (tracked as followups for the parser-layer
review session):

- Per-statement failures inside policies (e.g., one statement has an
  invalid Action type but other statements are fine). The current
  parsers log these as warnings and continue, which loses individual
  statements but not the whole policy. Surfacing per-statement
  failures requires a different shape (either many records or a
  nested structure) and should be its own focused fix.
- `scp_policy.py` and `condition_extractor.py` parse failures — out
  of scope for the BUG-021 fix; will be examined in the parser-layer
  review session.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any


@dataclass(frozen=True)
class PolicyParseFailure:
    """A single failed policy parse attempt.

    Immutable so callers can't accidentally mutate records after
    appending to the shared list.

    Attributes:
        parser: Which parser raised
            ("permission_policy", "trust_policy").
        source_arn: The principal or role ARN whose policy failed
            to parse. For permission policies this is the user/role/
            group ARN; for trust policies this is the role ARN.
        policy_source: How the policy was attached (
            "inline", "managed", "group_inline", "group_managed",
            "trust"). Lets operators distinguish "this principal had
            an inline policy that's malformed" from "this managed
            policy is malformed and used by N principals".
        policy_name: The customer-supplied policy name, if known.
        policy_arn: The managed policy ARN, if applicable. Empty
            for inline policies.
        failure_kind: A short tag describing what went wrong:
            "json_decode_error" — string isn't valid JSON
            "not_a_dict" — JSON parsed but root is not an object
            "invalid_statement_type" — Statement field is wrong type
            "type_error" — input is None or wrong type entirely
        error_class: `type(e).__name__` of the caught exception, if
            any. Empty for non-exception failures (like "not_a_dict").
        error_message: `str(e)` truncated to `_MESSAGE_MAX_LEN` chars.
            Empty for non-exception failures.
    """

    parser: str
    source_arn: str
    policy_source: str
    policy_name: str
    policy_arn: str
    failure_kind: str
    error_class: str
    error_message: str

    def to_dict(self) -> dict[str, Any]:
        """Serialize to a sorted-key dict for deterministic JSON output."""
        return {
            "error_class": self.error_class,
            "error_message": self.error_message,
            "failure_kind": self.failure_kind,
            "parser": self.parser,
            "policy_arn": self.policy_arn,
            "policy_name": self.policy_name,
            "policy_source": self.policy_source,
            "source_arn": self.source_arn,
        }


# Cap error message length so a pathological traceback can't blow up
# scenario.json size. 500 chars matches CollectionFailure (BUG-013).
_MESSAGE_MAX_LEN = 500


def make_parse_failure(
    *,
    parser: str,
    source_arn: str,
    policy_source: str = "",
    policy_name: str = "",
    policy_arn: str = "",
    failure_kind: str,
    exception: BaseException | None = None,
) -> PolicyParseFailure:
    """Construct a `PolicyParseFailure` from a parse-time failure.

    Centralized so all parsers truncate error messages the same way
    and use `type(e).__name__` consistently. The exception is
    optional because some failure kinds (like "not_a_dict") are
    detected by isinstance checks rather than caught exceptions.
    """
    error_class = ""
    error_message = ""
    if exception is not None:
        error_class = type(exception).__name__
        error_message = str(exception)
        if len(error_message) > _MESSAGE_MAX_LEN:
            error_message = error_message[: _MESSAGE_MAX_LEN - 3] + "..."
    return PolicyParseFailure(
        parser=parser,
        source_arn=source_arn,
        policy_source=policy_source,
        policy_name=policy_name,
        policy_arn=policy_arn,
        failure_kind=failure_kind,
        error_class=error_class,
        error_message=error_message,
    )
