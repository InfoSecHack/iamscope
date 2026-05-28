# Resource-Policy-Derived Edges

Phase 3 adds minimal graph coverage for non-role resource-based Allow policies.
IAM role trust policies remain handled by the existing trust-edge path. Generic
resource-policy Deny support remains explicitly out of scope unless and until
IAMScope parses, binds, emits, and consumes `RESOURCE_POLICY_DENY` constraints
end to end.

## Supported in Phase 3

IAMScope now collects and parses Allow statements from:

- S3 bucket policies
- KMS key policies
- Secrets Manager resource policies
- Lambda resource policies

Each parsed Allow statement can produce an ordinary graph edge with the
`_resource_policy` layer suffix, for example:

```text
arn:aws:iam::222222222222:role/Partner -> arn:aws:s3:::demo-bucket
edge_type = s3:GetObject_resource_policy
```

Condition-bearing statements also produce a `RESOURCE_POLICY_CONDITION`
constraint bound to the emitted edge with `governance_confidence=needs_review`.
IAMScope records the statement digest and `RESOURCE_POLICY` control reference in
edge features for attribution.

## Not Covered Yet

- Generic resource-policy Deny semantics are not parsed, bound, emitted as
  `RESOURCE_POLICY_DENY`, or consumed by reasoners in this phase. A deny-only
  resource policy should not create a supported deny constraint in
  `scenario.json`.
- Statement `Resource` expansion is not used to create extra target nodes; the
  edge target is the resource that owns the policy.
- Full runtime truth remains in the Phase 0-2 probe overlay sidecar, not in
  `scenario.json`.
- ARF overlay consumption is still future work.

## Narrow KMS Note

`SecretsBlastRadiusReasoner` contains a separate KMS key-policy evaluator for
its own decrypt check. That helper reads collected KMS key policy JSON from KMS
node properties and can treat relevant KMS `Deny` statements as blocking or
runtime-ambiguous. This is not generic resource-policy-deny support: it does not
emit `RESOURCE_POLICY_DENY` constraints and does not cover S3, Secrets Manager,
Lambda, or arbitrary resource-policy Deny semantics.

## Relation to Truth Contract

This is a graph-coverage phase. It preserves the Phase 0-2 truth contract:
`scenario.json` schema and edge ID formula are unchanged, and runtime truth stays
in sidecars.
