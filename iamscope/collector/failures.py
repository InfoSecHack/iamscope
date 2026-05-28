"""Structured collection failure records.

BUG-013 fix: collectors previously swallowed per-region exceptions with
nothing but a `logger.warning` call, leaving downstream consumers
(scenario.json, reasoners, reports) unable to distinguish "no resources
exist" from "the API call failed and we silently moved on". That's the
worst failure mode for a security tool — reasoners run against an
incomplete fact graph and produce fewer findings than they should, with
no indication anything was missed.

This module defines the structured record that collectors now append to
an optional `failures` list passed in by the pipeline. The pipeline
surfaces the accumulated list in two places:

1. `PipelineResult.collection_failures` — so CLI callers can fail loud
   or render a visible summary.
2. `ScenarioMetadata.collection_failures` — embedded in scenario.json
   so downstream consumers (reasoners, reports, diffs) can see that
   the fact graph they're reading is partial. Safe to embed because
   metadata is excluded from `canonical_hash` (see models.py).

Scope of the v0.2.29 fix (region-level only):

- `collect_lambda_functions` per-region drops
- `collect_kms_keys` per-region drops
- `collect_secrets` per-region drops
- `collect_s3_buckets` global-call failure

Explicitly NOT covered here (tracked as BUG-013b for a future pass):

- KMS per-key `DescribeKey` / `GetKeyPolicy` degradation, which doesn't
  drop nodes — it produces KMSKey nodes with empty metadata/policy that
  the KMS reasoner currently treats as "no allow statements". Fixing
  that needs a reasoner-side change (a `policy_fetch_failed` marker the
  reasoner consults to emit INCONCLUSIVE instead of NOT_APPLICABLE),
  which is out of scope for this fix.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any


@dataclass(frozen=True)
class CollectionFailure:
    """A single failed collection call.

    Immutable so callers can't accidentally mutate records after
    appending to the shared list.

    Attributes:
        collector: Short name of the collector that raised
            ("lambda", "kms", "secrets", "s3").
        account_id: The AWS account being collected.
        region: The region the call was targeting, or `REGION_GLOBAL`
            (the iamscope sentinel `"-"`) for services with a global
            control plane (e.g. S3 `ListBuckets`).
        error_class: `type(e).__name__` of the caught exception.
        error_message: `str(e)` truncated to `_MESSAGE_MAX_LEN` chars
            to keep scenario.json bounded when the underlying error
            message is unreasonably long (moto tracebacks, for example).
    """

    collector: str
    account_id: str
    region: str
    error_class: str
    error_message: str

    def to_dict(self) -> dict[str, Any]:
        """Serialize to a sorted-key dict for deterministic JSON output.

        Key order matches other `to_dict` methods in models.py which
        also sort alphabetically for canonical output.
        """
        return {
            "account_id": self.account_id,
            "collector": self.collector,
            "error_class": self.error_class,
            "error_message": self.error_message,
            "region": self.region,
        }


# Cap error message length so a pathological traceback can't blow up
# scenario.json size. 500 chars is enough for the error class + typical
# boto ClientError message + a bit of context.
_MESSAGE_MAX_LEN = 500


def make_failure(
    collector: str,
    account_id: str,
    region: str,
    exception: BaseException,
) -> CollectionFailure:
    """Construct a `CollectionFailure` from a caught exception.

    Centralized so all collectors truncate error messages the same way
    and use `type(e).__name__` consistently. Callers pass in the string
    identifiers they already know; we don't reflect on the call stack.
    """
    message = str(exception)
    if len(message) > _MESSAGE_MAX_LEN:
        message = message[: _MESSAGE_MAX_LEN - 3] + "..."
    return CollectionFailure(
        collector=collector,
        account_id=account_id,
        region=region,
        error_class=type(exception).__name__,
        error_message=message,
    )
