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
      Purpose      = "iamscope-env17-acceptance"
      iamscope-env = "env17"
    }
  }
}

data "aws_caller_identity" "current" {}

resource "aws_iam_user" "alice" {
  name = "env17-alice"
  path = "/iamscope-test/"
}

data "aws_iam_policy_document" "admin_trust" {
  statement {
    sid     = "AllowAlice"
    effect  = "Allow"
    actions = ["sts:AssumeRole"]

    principals {
      type        = "AWS"
      identifiers = [aws_iam_user.alice.arn]
    }
  }
}

resource "aws_iam_role" "admin" {
  name               = "env17-admin"
  path               = "/iamscope-test/"
  assume_role_policy = data.aws_iam_policy_document.admin_trust.json
}

resource "aws_iam_role_policy_attachment" "admin_administrator" {
  role       = aws_iam_role.admin.name
  policy_arn = "arn:aws:iam::aws:policy/AdministratorAccess"
}

data "aws_iam_policy_document" "alice_assume_admin" {
  statement {
    sid       = "AllowAssumeAdmin"
    effect    = "Allow"
    actions   = ["sts:AssumeRole"]
    resources = [aws_iam_role.admin.arn]
  }
}

resource "aws_iam_user_policy" "alice_assume_admin" {
  name   = "env17-alice-assume-admin"
  user   = aws_iam_user.alice.name
  policy = data.aws_iam_policy_document.alice_assume_admin.json
}

output "account_id" {
  value = data.aws_caller_identity.current.account_id
}

output "alice_arn" {
  value = aws_iam_user.alice.arn
}

output "admin_arn" {
  value = aws_iam_role.admin.arn
}
