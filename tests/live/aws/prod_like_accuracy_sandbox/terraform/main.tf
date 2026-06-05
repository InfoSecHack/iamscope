terraform {
  required_version = ">= 1.5.0"

  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = ">= 5.0"
    }
  }
}

provider "aws" {
  profile = var.aws_profile
  region  = var.aws_region

  default_tags {
    tags = local.common_tags
  }
}

data "aws_caller_identity" "current" {}

locals {
  required_live_ack = "I_UNDERSTAND_THIS_IS_A_DEDICATED_IAMSCOPE_SANDBOX"

  common_tags = {
    Project   = "IAMScope"
    Purpose   = "ProdLikeAccuracySandbox"
    Owner     = "TestOnly"
    ManagedBy = "Terraform"
  }

  source_principals = {
    ci_deployer                = "ci-deployer"
    ecs_deployer               = "ecs-deployer"
    helpdesk                   = "helpdesk"
    build                      = "build"
    audit                      = "audit"
    boundary_probe             = "boundary-probe"
    deny_probe                 = "deny-probe"
    uncertainty_resource_probe = "uncertainty-resource-probe"
    uncertainty_boundary_probe = "uncertainty-boundary-probe"
  }

  target_roles = {
    lambda_exec_scoped      = "lambda-exec-scoped"
    ecs_task_scoped         = "ecs-task-scoped"
    readonly_ops            = "readonly-ops"
    prod_observer           = "prod-observer"
    audit_b                 = "audit-b"
    service_mediated_target = "service-mediated-target"
    lambda_exec_boundary    = "lambda-exec-boundary"
    chain_target            = "chain-target"
    scp_passrole_target     = "scp-passrole-target"
    denied_assume           = "denied-assume"
  }

  permission_boundary_names = {
    passrole_lambda = "boundary-passrole-lambda"
    assume_chain    = "boundary-assume-chain"
    session_context = "boundary-session-context"
  }

  account_guardrail_policy_names = {
    passrole_guardrail = "guardrail-passrole"
    service_guardrail  = "guardrail-service"
    scope_guardrail    = "guardrail-scope"
  }

  target_role_trust_services = {
    lambda_exec_scoped      = ["lambda.amazonaws.com"]
    ecs_task_scoped         = ["ecs-tasks.amazonaws.com"]
    lambda_exec_boundary    = ["lambda.amazonaws.com"]
    service_mediated_target = ["lambda.amazonaws.com"]
  }

  source_permission_boundary_keys = {
    boundary_probe             = "passrole_lambda"
    uncertainty_boundary_probe = "session_context"
  }

  source_inline_policy_specs = {
    ci_deployer = {
      statements = [
        {
          sid       = "OracleV001LambdaCreateAndOracleP001ServiceAction"
          effect    = "Allow"
          actions   = ["lambda:CreateFunction"]
          resources = ["*"]
        },
        {
          sid       = "OracleV001PassRoleToScopedLambdaRole"
          effect    = "Allow"
          actions   = ["iam:PassRole"]
          resources = [aws_iam_role.target["lambda_exec_scoped"].arn]
        },
        {
          sid       = "OracleP002PassRoleToRoleWithoutServiceTrust"
          effect    = "Allow"
          actions   = ["iam:PassRole", "lambda:CreateFunction"]
          resources = [aws_iam_role.target["readonly_ops"].arn]
        },
        {
          sid       = "OracleV006ServiceMediatedPolicyShape"
          effect    = "Allow"
          actions   = ["lambda:CreateFunction", "iam:PassRole"]
          resources = [aws_iam_role.target["service_mediated_target"].arn]
        },
      ]
    }
    ecs_deployer = {
      statements = [
        {
          sid       = "OracleV002EcsTaskRunShape"
          effect    = "Allow"
          actions   = ["ecs:RegisterTaskDefinition", "ecs:RunTask", "iam:PassRole"]
          resources = [aws_iam_role.target["ecs_task_scoped"].arn]
        },
      ]
    }
    helpdesk = {
      statements = [
        {
          sid       = "OracleV003DirectAssumeRole"
          effect    = "Allow"
          actions   = ["sts:AssumeRole"]
          resources = [aws_iam_role.target["readonly_ops"].arn]
        },
        {
          sid       = "OracleP003PassRoleWithoutServiceAction"
          effect    = "Allow"
          actions   = ["iam:PassRole"]
          resources = [aws_iam_role.target["lambda_exec_scoped"].arn]
        },
      ]
    }
    build = {
      statements = [
        {
          sid       = "OracleV004FirstHopAssumeRole"
          effect    = "Allow"
          actions   = ["sts:AssumeRole"]
          resources = [aws_iam_role.target["prod_observer"].arn]
        },
      ]
    }
    audit = {
      statements = [
        {
          sid       = "OracleV005CrossAccountShapedConditionSatisfied"
          effect    = "Allow"
          actions   = ["sts:AssumeRole"]
          resources = [aws_iam_role.target["audit_b"].arn]
          condition = {
            test     = "StringEquals"
            variable = "aws:PrincipalTag/IAMScopeSyntheticAccount"
            values   = ["synthetic-account-a"]
          }
        },
        {
          sid       = "OracleI005CrossAccountTrustConditionUnknown"
          effect    = "Allow"
          actions   = ["sts:AssumeRole"]
          resources = [aws_iam_role.target["audit_b"].arn]
          condition = {
            test     = "StringEquals"
            variable = "aws:RequestTag/IAMScopeUnknownContext"
            values   = ["synthetic-account-b"]
          }
        },
      ]
    }
    boundary_probe = {
      statements = [
        {
          sid       = "OracleB001BoundaryBlockedPassRoleLambdaShape"
          effect    = "Allow"
          actions   = ["lambda:CreateFunction", "iam:PassRole"]
          resources = [aws_iam_role.target["lambda_exec_boundary"].arn]
        },
        {
          sid       = "OracleB002BoundaryBlockedChainContinuationShape"
          effect    = "Allow"
          actions   = ["sts:AssumeRole"]
          resources = [aws_iam_role.target["chain_target"].arn]
        },
      ]
    }
    deny_probe = {
      statements = [
        {
          sid       = "OracleB003ScpLikeGuardrailPassRoleShape"
          effect    = "Allow"
          actions   = ["iam:PassRole"]
          resources = [aws_iam_role.target["scp_passrole_target"].arn]
        },
        {
          sid       = "OracleB004IdentityDenyAssumeRoleShape"
          effect    = "Allow"
          actions   = ["sts:AssumeRole"]
          resources = [aws_iam_role.target["denied_assume"].arn]
        },
        {
          sid       = "OracleB005ExplicitDenyServiceMediatedShape"
          effect    = "Allow"
          actions   = ["lambda:CreateFunction", "iam:PassRole"]
          resources = [aws_iam_role.target["service_mediated_target"].arn]
        },
        {
          sid       = "OracleI004ScpLikeScopeUnknownShape"
          effect    = "Allow"
          actions   = ["iam:PassRole"]
          resources = [aws_iam_role.target["scp_passrole_target"].arn]
        },
      ]
    }
    uncertainty_resource_probe = {
      statements = [
        {
          sid       = "OracleI001WildcardResourceScopeUnknown"
          effect    = "Allow"
          actions   = ["iam:PassRole", "lambda:CreateFunction"]
          resources = ["*"]
        },
      ]
    }
    uncertainty_boundary_probe = {
      statements = [
        {
          sid       = "OracleI002UnresolvedConditionKey"
          effect    = "Allow"
          actions   = ["sts:AssumeRole"]
          resources = [aws_iam_role.target["readonly_ops"].arn]
          condition = {
            test     = "StringEquals"
            variable = "aws:RequestTag/IAMScopeUnknownContext"
            values   = ["required-but-not-collected"]
          }
        },
        {
          sid       = "OracleI003SessionBoundaryContextMissing"
          effect    = "Allow"
          actions   = ["sts:AssumeRole"]
          resources = [aws_iam_role.target["chain_target"].arn]
        },
      ]
    }
  }

  unsupported_static_only_rows = [
    "oracle-u-001",
    "oracle-u-002",
    "oracle-u-003",
    "oracle-u-004",
  ]

  oracle_row_mapping = {
    oracle-v-001 = {
      resource_group      = "passrole_lambda_allowed"
      source_principal    = "ci_deployer"
      target_role         = "lambda_exec_scoped"
      live_representable  = "yes"
      cleanup_requirement = "delete policies, source principal, target role, and any future test Lambda function"
      risk_note           = "no Lambda invocation"
    }
    oracle-v-002 = {
      resource_group      = "passrole_ecs_allowed"
      source_principal    = "ecs_deployer"
      target_role         = "ecs_task_scoped"
      live_representable  = "partial"
      cleanup_requirement = "delete policies, source principal, and target role"
      risk_note           = "no service launch by default"
    }
    oracle-v-003 = {
      resource_group      = "assume_role_direct_allowed"
      source_principal    = "helpdesk"
      target_role         = "readonly_ops"
      live_representable  = "yes"
      cleanup_requirement = "delete policies, source principal, and target role"
      risk_note           = "optional assume role probe only if reviewed"
    }
    oracle-v-004 = {
      resource_group      = "assume_role_two_hop_allowed"
      source_principal    = "build"
      target_role         = "prod_observer"
      live_representable  = "partial"
      cleanup_requirement = "delete policies and chain roles"
      risk_note           = "avoid credential chaining unless separately approved"
    }
    oracle-v-005 = {
      resource_group      = "cross_account_trust_condition_satisfied"
      source_principal    = "audit"
      target_role         = "audit_b"
      live_representable  = "partial"
      cleanup_requirement = "delete trust roles and policies"
      risk_note           = "use aliases if second account is too risky"
    }
    oracle-v-006 = {
      resource_group      = "service_mediated_role_path"
      source_principal    = "ci_deployer"
      target_role         = "service_mediated_target"
      live_representable  = "partial"
      cleanup_requirement = "delete policies and roles"
      risk_note           = "no downstream action"
    }
    oracle-b-001 = {
      resource_group      = "boundary_blocks_passrole_lambda"
      source_principal    = "boundary_probe"
      target_role         = "lambda_exec_boundary"
      live_representable  = "yes"
      cleanup_requirement = "delete boundary policy, source principal, and target role"
      risk_note           = "boundary must not affect operator identity"
    }
    oracle-b-002 = {
      resource_group      = "boundary_blocks_assume_chain"
      source_principal    = "boundary_probe"
      target_role         = "chain_target"
      live_representable  = "partial"
      cleanup_requirement = "delete boundary policy and roles"
      risk_note           = "avoid credential chaining unless separately approved"
    }
    oracle-b-003 = {
      resource_group      = "scp_like_blocks_passrole"
      source_principal    = "deny_probe"
      target_role         = "scp_passrole_target"
      live_representable  = "partial"
      cleanup_requirement = "delete guardrail policies and roles"
      risk_note           = "IAM-only guardrail simulation, not generic SCP support"
    }
    oracle-b-004 = {
      resource_group      = "identity_deny_suppresses_assume"
      source_principal    = "deny_probe"
      target_role         = "denied_assume"
      live_representable  = "partial"
      cleanup_requirement = "delete deny policy and roles"
      risk_note           = "not generic Deny correctness"
    }
    oracle-b-005 = {
      resource_group      = "explicit_deny_service_permission"
      source_principal    = "deny_probe"
      target_role         = "service_mediated_target"
      live_representable  = "partial"
      cleanup_requirement = "delete deny policy and roles"
      risk_note           = "no destructive service action"
    }
    oracle-p-001 = {
      resource_group      = "missing_passrole_precondition"
      source_principal    = "ci_deployer"
      target_role         = "lambda_exec_boundary"
      live_representable  = "yes"
      cleanup_requirement = "delete policies and roles"
      risk_note           = "candidate for denied CreateFunction probe"
    }
    oracle-p-002 = {
      resource_group      = "missing_target_service_trust"
      source_principal    = "ci_deployer"
      target_role         = "readonly_ops"
      live_representable  = "partial"
      cleanup_requirement = "delete target role and policies"
      risk_note           = "no service launch"
    }
    oracle-p-003 = {
      resource_group      = "missing_service_action"
      source_principal    = "helpdesk"
      target_role         = "lambda_exec_scoped"
      live_representable  = "yes"
      cleanup_requirement = "delete policies and roles"
      risk_note           = "no live service action"
    }
    oracle-p-004 = {
      resource_group      = "missing_assume_role_permission"
      source_principal    = "build"
      target_role         = "readonly_ops"
      live_representable  = "yes"
      cleanup_requirement = "delete trust role and policies"
      risk_note           = "optional denied AssumeRole probe only if reviewed"
    }
    oracle-i-001 = {
      resource_group      = "wildcard_resource_scope_unknown"
      source_principal    = "uncertainty_resource_probe"
      target_role         = "lambda_exec_scoped"
      live_representable  = "yes"
      cleanup_requirement = "delete policies and roles"
      risk_note           = "must remain inconclusive unless resolved"
    }
    oracle-i-002 = {
      resource_group      = "unresolved_condition_key"
      source_principal    = "uncertainty_boundary_probe"
      target_role         = "readonly_ops"
      live_representable  = "partial"
      cleanup_requirement = "delete conditional policies and roles"
      risk_note           = "do not assume condition satisfaction"
    }
    oracle-i-003 = {
      resource_group      = "session_or_boundary_context_missing"
      source_principal    = "uncertainty_boundary_probe"
      target_role         = "chain_target"
      live_representable  = "partial"
      cleanup_requirement = "delete roles and policies"
      risk_note           = "do not claim downstream authorization"
    }
    oracle-i-004 = {
      resource_group      = "scp_like_scope_unknown"
      source_principal    = "deny_probe"
      target_role         = "scp_passrole_target"
      live_representable  = "partial"
      cleanup_requirement = "delete guardrail policies and roles"
      risk_note           = "not generic SCP support"
    }
    oracle-i-005 = {
      resource_group      = "cross_account_trust_condition_unknown"
      source_principal    = "audit"
      target_role         = "audit_b"
      live_representable  = "partial"
      cleanup_requirement = "delete trust roles and policies"
      risk_note           = "use aliases if second account is too risky"
    }
    oracle-u-001 = {
      resource_group      = "unsupported_resource_policy_deny"
      source_principal    = null
      target_role         = null
      live_representable  = "static-only"
      cleanup_requirement = "no live resource"
      risk_note           = "unsupported static-only row, not false positive or false negative"
    }
    oracle-u-002 = {
      resource_group      = "unsupported_service_condition_semantics"
      source_principal    = null
      target_role         = null
      live_representable  = "static-only"
      cleanup_requirement = "no live resource"
      risk_note           = "unsupported static-only row, not false positive or false negative"
    }
    oracle-u-003 = {
      resource_group      = "unsupported_lambda_invocation_behavior"
      source_principal    = null
      target_role         = null
      live_representable  = "static-only"
      cleanup_requirement = "no live resource"
      risk_note           = "unsupported static-only row, no Lambda invocation"
    }
    oracle-u-004 = {
      resource_group      = "unsupported_downstream_authorization"
      source_principal    = null
      target_role         = null
      live_representable  = "static-only"
      cleanup_requirement = "no live resource"
      risk_note           = "unsupported static-only row, no exploitability proof"
    }
  }
}

resource "terraform_data" "safety_guards" {
  input = {
    account_id      = data.aws_caller_identity.current.account_id
    resource_prefix = var.resource_prefix
  }

  lifecycle {
    precondition {
      condition     = data.aws_caller_identity.current.account_id == var.expected_account_id
      error_message = "Caller account does not match expected_account_id."
    }

    precondition {
      condition     = var.live_ack == local.required_live_ack
      error_message = "live_ack does not match the required dedicated sandbox acknowledgement."
    }

    precondition {
      condition     = startswith(var.resource_prefix, "iamscope-prodlike-v1-")
      error_message = "resource_prefix must begin with iamscope-prodlike-v1-."
    }
  }
}

resource "aws_iam_user" "source" {
  for_each = local.source_principals

  name                 = "${var.resource_prefix}${each.value}"
  permissions_boundary = contains(keys(local.source_permission_boundary_keys), each.key) ? aws_iam_policy.permission_boundary[local.source_permission_boundary_keys[each.key]].arn : null

  tags = merge(local.common_tags, {
    OracleFixture = "prod_like_aws_accuracy_oracle_v1"
    SandboxRole   = "source-principal"
  })
}

resource "aws_iam_role" "target" {
  for_each = local.target_roles

  name = "${var.resource_prefix}${each.value}"
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = concat(
      [
        {
          Effect = "Allow"
          Action = "sts:AssumeRole"
          Principal = {
            AWS = "arn:aws:iam::${data.aws_caller_identity.current.account_id}:root"
          }
        }
      ],
      [
        for service in lookup(local.target_role_trust_services, each.key, []) : {
          Effect = "Allow"
          Action = "sts:AssumeRole"
          Principal = {
            Service = service
          }
        }
      ]
    )
  })

  tags = merge(local.common_tags, {
    OracleFixture = "prod_like_aws_accuracy_oracle_v1"
    SandboxRole   = "target-role"
  })
}

data "aws_iam_policy_document" "boundary" {
  for_each = local.permission_boundary_names

  statement {
    effect    = "Allow"
    actions   = ["iam:GetRole", "iam:ListRolePolicies", "iam:GetPolicy", "iam:GetPolicyVersion"]
    resources = ["*"]
  }
}

resource "aws_iam_policy" "permission_boundary" {
  for_each = local.permission_boundary_names

  name        = "${var.resource_prefix}${each.value}"
  description = "IAMScope prod-like v1 permission boundary fixture policy."
  policy      = data.aws_iam_policy_document.boundary[each.key].json

  tags = merge(local.common_tags, {
    OracleFixture = "prod_like_aws_accuracy_oracle_v1"
    SandboxRole   = "permission-boundary"
  })
}

data "aws_iam_policy_document" "guardrail_simulation" {
  for_each = local.account_guardrail_policy_names

  statement {
    sid       = "DenySelectedSandboxAction"
    effect    = "Deny"
    actions   = ["iam:PassRole"]
    resources = ["*"]
  }
}

resource "aws_iam_policy" "guardrail_simulation" {
  for_each = local.account_guardrail_policy_names

  name        = "${var.resource_prefix}${each.value}"
  description = "IAMScope prod-like v1 IAM-only guardrail simulation policy."
  policy      = data.aws_iam_policy_document.guardrail_simulation[each.key].json

  tags = merge(local.common_tags, {
    OracleFixture = "prod_like_aws_accuracy_oracle_v1"
    SandboxRole   = "guardrail-simulation"
  })
}

resource "aws_iam_user_policy" "source_relationships" {
  for_each = local.source_inline_policy_specs

  name = "${var.resource_prefix}${each.key}-oracle-relationships"
  user = aws_iam_user.source[each.key].name
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      for statement in each.value.statements : merge(
        {
          Sid      = statement.sid
          Effect   = statement.effect
          Action   = statement.actions
          Resource = statement.resources
        },
        try({
          Condition = {
            (statement.condition.test) = {
              (statement.condition.variable) = statement.condition.values
            }
          }
        }, {})
      )
    ]
  })
}

resource "aws_iam_role_policy" "assume_chain_continuation" {
  name = "${var.resource_prefix}prod-observer-chain-continuation"
  role = aws_iam_role.target["prod_observer"].id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid      = "OracleV004ContinuationAssumeRoleShape"
        Effect   = "Allow"
        Action   = ["sts:AssumeRole"]
        Resource = [aws_iam_role.target["chain_target"].arn]
      }
    ]
  })
}

data "aws_iam_policy_document" "identity_deny" {
  statement {
    sid       = "OracleB004DenyAssumeRole"
    effect    = "Deny"
    actions   = ["sts:AssumeRole"]
    resources = [aws_iam_role.target["denied_assume"].arn]
  }

  statement {
    sid       = "OracleB005DenyServiceMediatedPermission"
    effect    = "Deny"
    actions   = ["lambda:CreateFunction", "iam:PassRole"]
    resources = [aws_iam_role.target["service_mediated_target"].arn]
  }
}

resource "aws_iam_policy" "identity_deny" {
  name        = "${var.resource_prefix}identity-deny-selected-oracle-rows"
  description = "IAMScope prod-like v1 explicit deny policy for selected blocked oracle rows."
  policy      = data.aws_iam_policy_document.identity_deny.json

  tags = merge(local.common_tags, {
    OracleFixture = "prod_like_aws_accuracy_oracle_v1"
    SandboxRole   = "identity-deny"
  })
}

resource "aws_iam_user_policy_attachment" "identity_deny" {
  user       = aws_iam_user.source["deny_probe"].name
  policy_arn = aws_iam_policy.identity_deny.arn
}

resource "aws_iam_user_policy_attachment" "guardrail_simulation" {
  for_each = aws_iam_policy.guardrail_simulation

  user       = aws_iam_user.source["deny_probe"].name
  policy_arn = each.value.arn
}
