# Permission Boundary Intersection

IAMScope now treats permissions boundaries as an intersection control on identity-derived permission edges. Static identity-policy Allow remains only declared permission: the permission is effective only when the source principal's boundary also allows the same action on the same target resource.

## Covered

- Roles and users with `permission_boundary_arn` collected from IAM metadata.
- Managed permission-boundary policy documents already collected with the account data.
- Boundary Allow statements with `Action` and `Resource` are matched against permission edges using:
  - case-insensitive `Action` matching with IAM-style wildcards, and
  - resource/ARN wildcard matching against the edge target.
- Boundary explicit `Deny` statements that match action and resource are treated as complete blockers.
- Bound blocker evidence is exported through existing `PERMISSION_BOUNDARY` constraints and `edge_constraints`; `scenario.json` shape and `edge_id` formulas are unchanged.
- `assume_role_chain` and `admin_reachability` consume boundary blocker evidence on AssumeRole hops and admin-permission witness edges, so a declared path is blocked or inconclusive instead of overstated.

## Conservative Cases

The binder emits `governance_confidence="needs_review"` rather than a complete block when boundary evaluation depends on unsupported or runtime-specific policy features, including:

- boundary Allow/Deny statements with `Condition`,
- `NotAction`,
- `NotResource`, and
- malformed or partial boundary parse metadata.

These are not ignored. Reasoners that consume the binding surface them as inconclusive/unknown where the evidence affects a reachable path.

## Not Covered Yet

- Full IAM policy simulator parity for every condition key.
- Session-policy intersection.
- Permissions-boundary effects on resource-policy grants to role-session ARNs.
- CloudTrail/runtime validation.

Truth-aware replay and `diff-findings` remain the right way to compare declared-only findings against findings that include probe overlays or boundary evidence. Boundary evidence is static policy evidence, not live validation.
