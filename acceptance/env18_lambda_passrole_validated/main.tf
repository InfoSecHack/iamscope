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
      Purpose      = "iamscope-env18-acceptance"
      iamscope-env = "env18"
    }
  }
}

data "aws_caller_identity" "current" {}

data "aws_region" "current" {}

locals {
  lambda_function_arn = "arn:aws:lambda:${data.aws_region.current.name}:${data.aws_caller_identity.current.account_id}:function:env18-passrole-probe"
}

resource "aws_iam_user" "alice" {
  name = "env18-alice"
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
  name               = "env18-lambda-admin-exec"
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
    sid       = "AllowPassLambdaAdminExecutionRole"
    effect    = "Allow"
    actions   = ["iam:PassRole"]
    resources = [aws_iam_role.lambda_admin_exec.arn]
  }
}

resource "aws_iam_user_policy" "alice_lambda_passrole" {
  name   = "env18-alice-lambda-passrole"
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
