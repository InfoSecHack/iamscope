# Prod-Like AWS Sandbox Terraform Design

## Purpose

This document designs the future Terraform sandbox for IAMScope's prod-like AWS
accuracy benchmark. It maps the already-frozen local oracle fixture to a
dedicated sandbox shape without writing Terraform files or running AWS.

This is design-only. It does not add live evidence, accuracy claims, benchmark
semantics, or implementation.

## Roadmap Alignment

This is Phase 3 of
`docs/specs/prod-like-aws-accuracy-benchmark-roadmap.md`: Terraform Sandbox
Design.

Inputs:

- Phase 2 fixture: `tests/fixtures/prod_like/aws_accuracy_oracle_v1/`.
- Future Phase 4: controlled sandbox deployment and collection.
- Future Phase 5: accuracy comparison report.

## Current Frozen Oracle

- Fixture id: `prod_like_aws_accuracy_oracle_v1`.
- Rows: 24.
- Breakdown: 6 `validated` / 5 `blocked` / 4 `precondition_only` / 5 `inconclusive` / 4 `unsupported`.
- Phase 3 must not expand oracle rows.

## Design Boundary

This PR is design-only:

- no Terraform files yet;
- no Terraform init, plan, apply, or destroy;
- no AWS calls;
- no production accounts;
- no live evidence;
- no accuracy claim yet.

## Dedicated Sandbox Account Policy

Future implementation must use a dedicated AWS sandbox only:

- never a work/prod account;
- require an expected account ID guard variable;
- require an `IAMSCOPE_LIVE_AWS_ACK` style explicit acknowledgement for any future live use;
- require explicit `AWS_PROFILE`;
- require explicit `AWS_REGION`;
- use resource names with a unique prefix such as `iamscope-prodlike-v1-`;
- sanitize all live outputs before commit;
- never commit raw account IDs or ARNs.

## Terraform Module Layout Design

Future path:

`tests/live/aws/prod_like_accuracy_sandbox/terraform/`

Future files:

- `main.tf`
- `variables.tf`
- `outputs.tf`
- `.gitignore`
- `README.md`

The future `.gitignore` must exclude:

- `.terraform/`
- `.terraform.lock.hcl`
- `terraform.tfstate`
- `terraform.tfstate.backup`
- `*.tfplan`
- `terraform-outputs.json`

## Resource Shape

The sandbox should map to the frozen oracle without expanding it.

Maximum v1:

- 2 accounts max, but implementation may use one account plus sanitized account aliases if cross-account is too risky for v1;
- 10 principals max;
- 12 roles max;
- 4 live probes max.

Planned resource families:

- IAM users or roles for source principals;
- target IAM roles;
- permission boundaries;
- inline policies or managed policies;
- trust policies;
- explicit Deny policy cases;
- SCP-like/account guardrail simulation if Organizations/SCPs are unsafe or unavailable;
- optional second account only if design can guard it safely.

## Oracle-Row-To-Resource Mapping

| Oracle row | Planned Terraform resource group | Expected live/sandbox representation | Live-representable in v1 | Reason if partial/no | Cleanup requirement | Risk note |
| --- | --- | --- | --- | --- | --- | --- |
| `oracle-v-001` | `passrole_lambda_allowed` | Source principal with Lambda create permission, `iam:PassRole` to scoped execution role, and Lambda trust | yes | N/A | Delete source policy, target role, and any test Lambda function if a later probe creates one | No Lambda invocation. |
| `oracle-v-002` | `passrole_ecs_allowed` | Source principal with ECS task/run permission, `iam:PassRole`, and ECS task role trust | partial | ECS live execution should not be run in v1; model static IAM shape only unless separately reviewed | Delete policies and roles | No service launch by default. |
| `oracle-v-003` | `assume_role_direct_allowed` | Source principal can assume target role through permission and trust | yes | N/A | Delete source policy and target role | Optional AssumeRole probe only if reviewed. |
| `oracle-v-004` | `assume_role_two_hop_allowed` | Source principal can assume intermediate role, then target role | partial | Two-hop live proof may require temporary credentials; keep collection static unless safe probe is approved | Delete policies and roles | Avoid long-lived credentials. |
| `oracle-v-005` | `cross_account_trust_condition_satisfied` | Cross-account-shaped trust using aliases or optional guarded second account | partial | Two-account setup may be deferred; one-account alias model may represent v1 safely | Delete trust roles and policies | Do not use unguarded second account. |
| `oracle-v-006` | `service_mediated_role_path` | Service-mediated role use shape with modeled trust and permission evidence | partial | Runtime service action is not required for v1 | Delete policies and roles | No downstream action. |
| `oracle-b-001` | `boundary_blocks_passrole_lambda` | Permission boundary prevents selected PassRole-to-Lambda path | yes | N/A | Delete boundary policy, source policy, and target role | Boundary must not affect operator identity. |
| `oracle-b-002` | `boundary_blocks_assume_chain` | Boundary blocks second-hop AssumeRole continuation | partial | Live two-hop probe may be deferred | Delete boundary policy and roles | Avoid credential chaining unless separately approved. |
| `oracle-b-003` | `scp_like_blocks_passrole` | SCP-like/account guardrail blocks PassRole using safe simulation if Organizations is unavailable | partial | Real SCPs may require Organizations permissions; simulation may be used | Delete guardrail policies and roles | Not generic SCP Deny support. |
| `oracle-b-004` | `identity_deny_suppresses_assume` | Identity Deny suppresses selected AssumeRole path | partial | Static/report evidence may remain primary | Delete deny policy and roles | Not generic Deny correctness. |
| `oracle-b-005` | `explicit_deny_service_permission` | Explicit Deny blocks service-mediated permission | partial | Service runtime action is not required | Delete deny policy and roles | No destructive service action. |
| `oracle-p-001` | `missing_passrole_precondition` | Source can create Lambda shape but lacks `iam:PassRole` to target | yes | N/A | Delete policies and roles | Candidate for denied CreateFunction probe. |
| `oracle-p-002` | `missing_target_service_trust` | Source has permissions but target role does not trust required service | partial | Some reasoners may emit no finding rather than precondition-only | Delete target role and policies | No service launch. |
| `oracle-p-003` | `missing_service_action` | Source has PassRole and trust path but lacks Lambda/service action | yes | N/A | Delete policies and roles | No live service action. |
| `oracle-p-004` | `missing_assume_role_permission` | Target trust exists but source lacks `sts:AssumeRole` permission | yes | N/A | Delete trust role and policies | Optional denied AssumeRole probe only if reviewed. |
| `oracle-i-001` | `wildcard_resource_scope_unknown` | Wildcard/resource-scope ambiguity is represented in policy shape | yes | N/A | Delete policies and roles | Must remain inconclusive unless resolved. |
| `oracle-i-002` | `unresolved_condition_key` | Permission/trust condition uses a context key unavailable to static collection | partial | Some conditions may not be safely probeable | Delete conditional policies and roles | Do not assume condition satisfaction. |
| `oracle-i-003` | `session_or_boundary_context_missing` | Runtime/session or boundary context is missing from collected evidence | partial | Session policy context may require special assume flow | Delete roles and policies | Do not claim downstream authorization. |
| `oracle-i-004` | `scp_like_scope_unknown` | Ambiguous account/OU guardrail scope is represented or simulated | partial | Real Organizations scope may be unavailable | Delete guardrail policies and roles | Not generic SCP support. |
| `oracle-i-005` | `cross_account_trust_condition_unknown` | Cross-account-shaped trust condition remains unresolved | partial | Optional second account may be deferred | Delete trust roles and policies | Use aliases if second account is too risky. |
| `oracle-u-001` | `unsupported_resource_policy_deny` | Static-only unsupported row, no live resource required | no | Generic resource-policy Deny outside v1 support | No live resource; retain fixture label only | Do not count as false positive or false negative. |
| `oracle-u-002` | `unsupported_service_condition_semantics` | Static-only unsupported row, no live resource required | no | Service-specific condition semantics outside v1 support | No live resource; retain fixture label only | Do not overclaim service semantics. |
| `oracle-u-003` | `unsupported_lambda_invocation_behavior` | Static-only unsupported row, no live invocation resource required | no | Downstream Lambda invocation behavior outside v1 support | No live resource; retain fixture label only | no Lambda invocation. |
| `oracle-u-004` | `unsupported_downstream_authorization` | Static-only unsupported row, no live resource required | no | Broad exploitability/downstream authorization outside v1 support | No live resource; retain fixture label only | No exploitability proof. |

## Live Probe Design

Maximum 4 live probes.

Future probe categories only:

- PassRole-to-Lambda allowed CreateFunction attempt without invoke.
- Missing-PassRole denied CreateFunction attempt.
- AssumeRole allowed or denied probe if safe.
- One boundary/SCP-like blocked probe if safe.

Probe boundaries:

- probes are optional and require separate implementation/review;
- no Lambda invocation;
- no destructive actions;
- no broad exploitability proof.

## Collection Design

Future Phase 4 collection should produce:

- sanitized collection manifest;
- sanitized IAMScope findings;
- sanitized cleanup proof;
- local comparison input for Phase 5.

Must not commit:

- raw AWS archives;
- raw account IDs;
- raw IAM ARNs;
- Terraform state/cache/lock/plan/output files;
- `result.json`;
- secrets.

## Cleanup Plan

Future implementation must require:

- Terraform destroy instructions;
- destroy trap or explicit cleanup runbook;
- verification that created roles, policies, and users are gone;
- cleanup status recorded in sanitized checkpoint only;
- no orphaned IAM resources.

## Cost And Blast-Radius Controls

- IAM-only by default.
- No compute unless separately approved.
- no Lambda invocation.
- No persistent data stores.
- No public networking.
- No external access.
- No production account.
- No cross-account unless explicitly guarded.

## Gates Before Implementation

- Do not write Terraform files until this design is merged.
- Do not run Terraform init/plan/apply in this PR.
- Do not apply Terraform until Terraform files have their own PR and review.
- Do not use live AWS until Phase 3 implementation is reviewed and Phase 4 is explicitly approved.
- Do not add new oracle rows.
- Do not expand beyond v1 maximums.

## Non-Claims

- not broad IAMScope correctness;
- not production readiness;
- not real production AWS;
- not exploitability proof;
- not downstream authorization proof;
- not Lambda invocation behavior;
- not generic Deny correctness;
- not resource-policy Deny support except unsupported/static-only row labeling;
- not SCP Deny support beyond selected benchmark behavior;
- no composite benchmark score;
- no pass/fail benchmark label.

## Exact Next Implementation Slice

Recommended next slice: implement Terraform sandbox files without applying them.
