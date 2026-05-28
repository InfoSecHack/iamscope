"""IAMScope — AWS Identity Attack Surface Collector.

Read-only IAM graph collector with two-layer edge semantics,
SCP governance binding, and ARF-RT native output.
"""

# Tool release version — consumed by the CLI `--version` flag
# and by tools that want to report the iamscope release they're
# running against. Independent from the scenario metadata's
# `collector_version` field (which is pinned at "0.2.0" as the
# scenario FORMAT version, baked into golden fixtures, and must
# NOT be bumped without re-pinning every scenario-bytes golden).
# The two concepts share a number today but will diverge as
# release versions advance and the scenario format stays stable.
__version__ = "0.3.0"
