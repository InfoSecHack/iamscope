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
      Purpose      = "iamscope-env19-acceptance"
      iamscope-env = "env19"
    }
  }
}

data "aws_caller_identity" "current" {}

data "aws_region" "current" {}

locals {
  lambda_function_arn = "arn:aws:lambda:${data.aws_region.current.name}:${data.aws_caller_identity.current.account_id}:function:env19-passrole-probe"
}

resource "aws_iam_user" "alice" {
  name = "env19-alice"
  path = "/iamscope-test/"
}

data "aws_iam_policy_document" "lambda_admin_trust" {
  statement {
    sid     = "AllowLambdaService"
    effect  = "Allow"
    actions = ["sts:AssumeRole"]

    principals {
      type        = "Service"
      identifiers = ["lambda.amazonaws.com"]
    }
  }
}

resource "aws_iam_role" "lambda_admin_exec" {
  name               = "env19-lambda-admin-exec"
  path               = "/iamscope-test/"
  assume_role_policy = data.aws_iam_policy_document.lambda_admin_trust.json
}

resource "aws_iam_role_policy_attachment" "lambda_admin_administrator" {
  role       = aws_iam_role.lambda_admin_exec.name
  policy_arn = "arn:aws:iam::aws:policy/AdministratorAccess"
}

data "aws_iam_policy_document" "alice_lambda_passrole" {
  statement {
    sid       = "AllowCreateSpecificProbeFunction"
    effect    = "Allow"
    actions   = ["lambda:CreateFunction"]
    resources = [local.lambda_function_arn]
  }

  statement {
    sid       = "AllowPassExecutionRoleOnlyToEc2"
    effect    = "Allow"
    actions   = ["iam:PassRole"]
    resources = [aws_iam_role.lambda_admin_exec.arn]

    condition {
      test     = "StringEquals"
      variable = "iam:PassedToService"
      values   = ["ec2.amazonaws.com"]
    }
  }
}

resource "aws_iam_user_policy" "alice_lambda_passrole" {
  name   = "env19-alice-passrole-scoped-away"
  user   = aws_iam_user.alice.name
  policy = data.aws_iam_policy_document.alice_lambda_passrole.json
}

output "account_id" {
  value = data.aws_caller_identity.current.account_id
}

output "alice_arn" {
  value = aws_iam_user.alice.arn
}

output "lambda_admin_role_arn" {
  value = aws_iam_role.lambda_admin_exec.arn
}

output "lambda_function_arn" {
  value = local.lambda_function_arn
}
