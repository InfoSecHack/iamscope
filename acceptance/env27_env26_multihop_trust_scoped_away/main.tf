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
      Purpose      = "iamscope-env27-acceptance"
      iamscope-env = "env27"
    }
  }
}

data "aws_caller_identity" "current" {}

resource "aws_iam_user" "alice" {
  name = "env27-alice"
  path = "/iamscope-test/"
}

resource "aws_iam_user" "decoy" {
  name = "env27-decoy"
  path = "/iamscope-test/"
}

data "aws_iam_policy_document" "hop1_trust" {
  statement {
    sid     = "AllowEnv27Alice"
    effect  = "Allow"
    actions = ["sts:AssumeRole"]

    principals {
      type        = "AWS"
      identifiers = [aws_iam_user.alice.arn]
    }
  }
}

resource "aws_iam_role" "hop1" {
  name               = "env27-hop1"
  path               = "/iamscope-test/"
  assume_role_policy = data.aws_iam_policy_document.hop1_trust.json
}

data "aws_iam_policy_document" "hop2_trust" {
  statement {
    sid     = "AllowEnv27Decoy"
    effect  = "Allow"
    actions = ["sts:AssumeRole"]

    principals {
      type        = "AWS"
      identifiers = [aws_iam_user.decoy.arn]
    }
  }
}

resource "aws_iam_role" "hop2" {
  name               = "env27-hop2"
  path               = "/iamscope-test/"
  assume_role_policy = data.aws_iam_policy_document.hop2_trust.json
}

data "aws_iam_policy_document" "admin_trust" {
  statement {
    sid     = "AllowEnv27Hop2"
    effect  = "Allow"
    actions = ["sts:AssumeRole"]

    principals {
      type        = "AWS"
      identifiers = [aws_iam_role.hop2.arn]
    }
  }
}

resource "aws_iam_role" "admin" {
  name               = "env27-admin"
  path               = "/iamscope-test/"
  assume_role_policy = data.aws_iam_policy_document.admin_trust.json
}

resource "aws_iam_role_policy_attachment" "admin_administrator" {
  role       = aws_iam_role.admin.name
  policy_arn = "arn:aws:iam::aws:policy/AdministratorAccess"
}

data "aws_iam_policy_document" "alice_assume_hop1" {
  statement {
    sid       = "AllowAssumeEnv27Hop1"
    effect    = "Allow"
    actions   = ["sts:AssumeRole"]
    resources = [aws_iam_role.hop1.arn]
  }
}

resource "aws_iam_user_policy" "alice_assume_hop1" {
  name   = "env27-alice-assume-hop1"
  user   = aws_iam_user.alice.name
  policy = data.aws_iam_policy_document.alice_assume_hop1.json
}

data "aws_iam_policy_document" "hop1_assume_hop2" {
  statement {
    sid       = "AllowAssumeEnv27Hop2"
    effect    = "Allow"
    actions   = ["sts:AssumeRole"]
    resources = [aws_iam_role.hop2.arn]
  }
}

resource "aws_iam_role_policy" "hop1_assume_hop2" {
  name   = "env27-hop1-assume-hop2"
  role   = aws_iam_role.hop1.id
  policy = data.aws_iam_policy_document.hop1_assume_hop2.json
}

data "aws_iam_policy_document" "hop2_assume_admin" {
  statement {
    sid       = "AllowAssumeEnv27Admin"
    effect    = "Allow"
    actions   = ["sts:AssumeRole"]
    resources = [aws_iam_role.admin.arn]
  }
}

resource "aws_iam_role_policy" "hop2_assume_admin" {
  name   = "env27-hop2-assume-admin"
  role   = aws_iam_role.hop2.id
  policy = data.aws_iam_policy_document.hop2_assume_admin.json
}

output "account_id" {
  value = data.aws_caller_identity.current.account_id
}

output "alice_arn" {
  value = aws_iam_user.alice.arn
}

output "decoy_arn" {
  value = aws_iam_user.decoy.arn
}

output "hop1_arn" {
  value = aws_iam_role.hop1.arn
}

output "hop2_arn" {
  value = aws_iam_role.hop2.arn
}

output "admin_arn" {
  value = aws_iam_role.admin.arn
}
