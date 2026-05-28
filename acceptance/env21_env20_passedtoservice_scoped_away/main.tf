terraform {
  required_version = ">= 1.5.0"

  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
  }
}

provider "aws" {
  region = "us-east-1"

  default_tags {
    tags = {
      ManagedBy    = "terraform"
      Purpose      = "iamscope-env21-acceptance"
      iamscope-env = "env21"
    }
  }
}

data "aws_caller_identity" "current" {}

data "aws_region" "current" {}

locals {
  ecs_task_definition_arn = "arn:aws:ecs:${data.aws_region.current.name}:${data.aws_caller_identity.current.account_id}:task-definition/env21-passrole-probe:1"
}

resource "aws_iam_user" "alice" {
  name = "env21-alice"
  path = "/iamscope-test/"
}

data "aws_iam_policy_document" "ecs_admin_trust" {
  statement {
    sid     = "AllowEcsTasksService"
    effect  = "Allow"
    actions = ["sts:AssumeRole"]

    principals {
      type        = "Service"
      identifiers = ["ecs-tasks.amazonaws.com"]
    }
  }
}

resource "aws_iam_role" "ecs_admin_task" {
  name               = "env21-ecs-admin-task"
  path               = "/iamscope-test/"
  assume_role_policy = data.aws_iam_policy_document.ecs_admin_trust.json
}

resource "aws_iam_role_policy_attachment" "ecs_admin_administrator" {
  role       = aws_iam_role.ecs_admin_task.name
  policy_arn = "arn:aws:iam::aws:policy/AdministratorAccess"
}

data "aws_iam_policy_document" "alice_ecs_passrole" {
  statement {
    sid       = "AllowRegisterSpecificTaskDefinition"
    effect    = "Allow"
    actions   = ["ecs:RegisterTaskDefinition"]
    resources = [local.ecs_task_definition_arn]
  }

  statement {
    sid       = "AllowRunSpecificTaskDefinition"
    effect    = "Allow"
    actions   = ["ecs:RunTask"]
    resources = [local.ecs_task_definition_arn]
  }

  statement {
    sid       = "AllowPassEcsTaskRoleOnlyToEc2"
    effect    = "Allow"
    actions   = ["iam:PassRole"]
    resources = [aws_iam_role.ecs_admin_task.arn]

    condition {
      test     = "StringEquals"
      variable = "iam:PassedToService"
      values   = ["ec2.amazonaws.com"]
    }
  }
}

resource "aws_iam_user_policy" "alice_ecs_passrole" {
  name   = "env21-alice-ecs-passrole-scoped-away"
  user   = aws_iam_user.alice.name
  policy = data.aws_iam_policy_document.alice_ecs_passrole.json
}

output "account_id" {
  value = data.aws_caller_identity.current.account_id
}

output "alice_arn" {
  value = aws_iam_user.alice.arn
}

output "ecs_admin_role_arn" {
  value = aws_iam_role.ecs_admin_task.arn
}

output "ecs_task_definition_arn" {
  value = local.ecs_task_definition_arn
}
