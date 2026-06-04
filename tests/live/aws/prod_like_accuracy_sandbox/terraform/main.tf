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
    ci_deployer       = "ci-deployer"
    ecs_deployer      = "ecs-deployer"
    helpdesk          = "helpdesk"
    build             = "build"
    audit             = "audit"
    boundary_probe    = "boundary-probe"
    deny_probe        = "deny-probe"
    uncertainty_probe = "uncertainty-probe"
  }

  target_roles = {
    lambda_exec_scoped       = "lambda-exec-scoped"
    ecs_task_scoped          = "ecs-task-scoped"
    readonly_ops             = "readonly-ops"
    prod_observer            = "prod-observer"
    audit_b                  = "audit-b"
    service_mediated_target  = "service-mediated-target"
    lambda_exec_boundary     = "lambda-exec-boundary"
    chain_target             = "chain-target"
    scp_passrole_target      = "scp-passrole-target"
    denied_assume            = "denied-assume"
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
      source_principal    = "uncertainty_probe"
      target_role         = "lambda_exec_scoped"
      live_representable  = "yes"
      cleanup_requirement = "delete policies and roles"
      risk_note           = "must remain inconclusive unless resolved"
    }
    oracle-i-002 = {
      resource_group      = "unresolved_condition_key"
      source_principal    = "uncertainty_probe"
      target_role         = "readonly_ops"
      live_representable  = "partial"
      cleanup_requirement = "delete conditional policies and roles"
      risk_note           = "do not assume condition satisfaction"
    }
    oracle-i-003 = {
      resource_group      = "session_or_boundary_context_missing"
      source_principal    = "uncertainty_probe"
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

data "aws_iam_policy_document" "target_role_trust" {
  for_each = local.target_roles

  statement {
    effect  = "Allow"
    actions = ["sts:AssumeRole"]

    principals {
      type = "AWS"
      identifiers = [
        "arn:aws:iam::${data.aws_caller_identity.current.account_id}:root",
      ]
    }
  }
}

resource "aws_iam_user" "source" {
  for_each = local.source_principals

  name = "${var.resource_prefix}${each.value}"

  tags = merge(local.common_tags, {
    OracleFixture = "prod_like_aws_accuracy_oracle_v1"
    SandboxRole   = "source-principal"
  })
}

resource "aws_iam_role" "target" {
  for_each = local.target_roles

  name               = "${var.resource_prefix}${each.value}"
  assume_role_policy = data.aws_iam_policy_document.target_role_trust[each.key].json

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
