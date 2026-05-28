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
      Purpose      = "iamscope-env08-acceptance"
      iamscope-env = "env08"
    }
  }
}

data "aws_caller_identity" "current" {}

data "aws_iam_policy_document" "conditioned_admin_trust" {
  statement {
    sid     = "AllowAliceWithMFA"
    effect  = "Allow"
    actions = ["sts:AssumeRole"]

    principals {
      type        = "AWS"
      identifiers = [aws_iam_user.alice.arn]
    }

    condition {
      test     = "Bool"
      variable = "aws:MultiFactorAuthPresent"
      values   = ["true"]
    }
  }
}

resource "aws_iam_role" "conditioned_admin" {
  name               = "env08-conditioned-admin"
  path               = "/iamscope-test/"
  assume_role_policy = data.aws_iam_policy_document.conditioned_admin_trust.json
}

resource "aws_iam_role_policy_attachment" "conditioned_admin_admin_access" {
  role       = aws_iam_role.conditioned_admin.name
  policy_arn = "arn:aws:iam::aws:policy/AdministratorAccess"
}

resource "aws_iam_user" "alice" {
  name = "env08-alice"
  path = "/iamscope-test/"
}

data "aws_iam_policy_document" "alice_assume_conditioned_admin" {
  statement {
    sid       = "AllowAssumeConditionedAdmin"
    effect    = "Allow"
    actions   = ["sts:AssumeRole"]
    resources = [aws_iam_role.conditioned_admin.arn]
  }
}

resource "aws_iam_user_policy" "alice_assume_conditioned_admin" {
  name   = "env08-alice-assume-conditioned-admin"
  user   = aws_iam_user.alice.name
  policy = data.aws_iam_policy_document.alice_assume_conditioned_admin.json
}

output "account_id" {
  value = data.aws_caller_identity.current.account_id
}

output "alice_arn" {
  value = aws_iam_user.alice.arn
}

output "conditioned_admin_arn" {
  value = aws_iam_role.conditioned_admin.arn
}
