# IAMScope Capability Honesty Matrix

This reference explains what IAMScope currently models, what it preserves as graph or metadata, and what it does not claim. It is intended for reviewers using IAMScope on real or prod-like AWS organizations where a quiet output can otherwise be misread as safety.

## 1. What IAMScope Currently Models

IAMScope emits findings for a bounded set of shipped reasoner pattern families:

- `cross_account_trust`
- `assume_role_chain`
- `admin_reachability`
- `passrole_lambda`
- `passrole_ecs`
- `secrets_blast_radius`
- `s3_bucket_takeover`
- `iam_group_membership_escalation`

The permission parser currently extracts a focused set of security-relevant actions for those modeled patterns:

- `sts:AssumeRole`
- `sts:AssumeRoleWithSAML`
- `sts:AssumeRoleWithWebIdentity`
- `iam:PassRole`
- `lambda:InvokeFunction`
- `lambda:CreateFunction`
- `ec2:RunInstances`
- `ecs:RegisterTaskDefinition`
- `ecs:RunTask`
- `secretsmanager:GetSecretValue`
- `iam:AddUserToGroup`
- `s3:PutBucketPolicy`

Modeled coverage means IAMScope has a reasoner that can evaluate a specific graph shape and produce a bounded verdict. It does not mean IAMScope evaluates the whole IAM attack surface.

## 2. What IAMScope Collects But Does Not Fully Reason Over

Some collected data is exported into the scenario graph or binding metadata but is not yet covered by broad reasoners:

- Resource-policy edges for S3, KMS, Secrets Manager, and Lambda may appear as graph data, but IAMScope does not claim broad resource-policy data-access or exfiltration reasoning.
- Resource-policy conditions may be emitted as constraints, but this is not full AWS authorization reasoning for every condition key and service behavior.
- SCPs, permission boundaries, session-policy context, and trust conditions may be represented as constraints or edge constraints for modeled checks, but representation is not the same thing as complete semantic coverage.
- Unsupported or static-only rows in evidence docs are preserved as boundaries, not silently converted into false positives or false negatives.

## 3. What IAMScope Explicitly Does Not Model Yet

The following examples are not currently covered as general attack-path reasoner families:

- `iam:CreateAccessKey`
- `iam:PutUserPolicy`
- `iam:PutRolePolicy`
- `iam:AttachUserPolicy`
- `iam:AttachRolePolicy`
- `iam:CreatePolicyVersion`
- `iam:SetDefaultPolicyVersion`
- `iam:UpdateAssumeRolePolicy`
- `iam:CreateLoginProfile`
- `iam:UpdateLoginProfile`
- `sts:GetFederationToken`
- broad resource-policy exfiltration paths
- full SCP semantics
- full permission-boundary semantics
- full session-policy visibility
- full service-specific downstream authorization
- exploit execution
- Lambda invocation behavior
- complete IAM privilege-escalation taxonomy

These gaps are explicit non-coverage, not evidence that the environment lacks those risks.

## 4. What “No Findings” Means

“No findings” means no modeled findings were emitted from the collected graph; it does not mean the account is safe.

A no-findings result can happen because the relevant path is absent, because the path is outside IAMScope’s modeled patterns, because collection was filtered or partial, or because a required context source was unavailable.

## 5. What “Validated” Means

“Validated” means IAMScope’s modeled preconditions passed for that pattern using the available graph; it is not exploitability proof and may carry `collection_context` caveats.

A validated finding is still scoped to the modeled pattern, the collected data, and the current reasoner semantics. It is not proof of downstream authorization, production impact, or successful exploit execution.

## 6. What “Inconclusive” Means

“Inconclusive” means IAMScope found a potentially relevant shape but refused to make a stronger claim because of missing/ambiguous context.

Common causes include partial collection, unknown organization membership, unresolved trust conditions, permission-boundary or SCP uncertainty, session-policy blind spots, dangling resource references, or wildcard evidence that is intentionally treated conservatively.

## 7. What “Blocked” Means

“Blocked” means IAMScope found a modeled blocker for the specific pattern/check; it is not proof the environment is safe.

A blocked verdict applies to the modeled path and blocker evidence. It does not rule out other paths, other principals, other regions, other services, or unmodeled privilege-escalation techniques.

## 8. What Users Should Manually Review

Reviewers should manually inspect:

- high-impact validated findings and the evidence edges behind them;
- inconclusive findings with shared missing evidence sources;
- environmental extras from non-sandbox or non-target principals;
- unsupported/static-only rows in benchmark or pilot outputs;
- collection failures and `policy_parse_failures` in scenario metadata;
- resource-policy, SCP, permission-boundary, and session-policy context when those controls matter to the reviewed path.

Manual review should treat IAMScope as an evidence organizer, not an automated safety certificate.

## 9. How `collection_context` Affects Interpretation

`collection_context` describes how complete or bounded the input graph is. A result from a filtered account, standalone account, partial organization view, or intentionally scoped pilot has narrower meaning than a complete organization-wide collection.

When `collection_context` indicates partial or filtered collection, findings should be read as statements about the collected graph only. Missing findings should not be generalized to uncollected principals, roles, resources, accounts, regions, or services.

## 10. How `org_membership_status` Affects Interpretation

`org_membership_status` distinguishes known organization members, confirmed non-members, and unknown membership:

- `member`: the source account is known to belong to the collected organization context.
- `non_member`: the source account is known to be outside that context.
- `unknown`: the source account could not be classified from the available collection context.

Unknown membership should not be worded or severity-treated as confirmed externality. It is a visibility boundary caused by partial, filtered, or standalone collection context.

## 11. Simulator/Verification Limitations

IAMScope does not run AWS IAM simulation or live AWS verification by default. Local tests, synthetic fixtures, and sanitized live checkpoints are evidence for specific modeled cases only.

The project does not use a composite score, no composite score is implied by a result set, and there is no pass/fail benchmark label. Evidence is layered by modeled support, observed comparison, environmental extras, unsupported/static-only rows, and not-currently-live-comparable rows.

## 12. Future Coverage Candidates

Future coverage candidates include broader IAM privilege-escalation primitives, deeper resource-policy authorization reasoning, richer SCP and permission-boundary semantics, session-policy visibility, more service-specific downstream authorization checks, and additional controlled live validation pairs.

Adding coverage should happen through narrow reasoners, bounded fixtures, explicit non-claims, and tests that keep “no findings” from being misread as account safety.
