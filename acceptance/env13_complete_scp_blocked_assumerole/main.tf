# Env 13 - complete SCP blocks an otherwise IAM-allowed AssumeRole admin path.
#
# Scenario: env13-alice -> env13-admin
#   - alice has sts:AssumeRole permission on env13-admin
#   - env13-admin trusts alice
#   - env13-admin has AdministratorAccess
#   - run.sh attaches an Env13-specific SCP that denies sts:AssumeRole with Resource "*"
#   - the SCP has an ArnNotLike aws:PrincipalArn carveout for the collection caller
#
# Expected IAMScope output:
#   - scenario exports permission/trust structure and a complete SCP binding
#   - admin_reachability must be BLOCKED for alice -> admin
#
# Cost: $0 - IAM and Organizations policy resources only.
# Cleanup: run.sh detaches/deletes the SCP first, then terraform destroy.

terraform {
  required_version = ">= 1.5.0"

  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
  }
}

variable "aws_region" {
  type = string
}

variable "member_profile" {
  type = string
}

variable "management_account_id" {
  type = string
}

variable "collection_role_name" {
  type    = string
  default = "env13-iamscope-reader"
}

provider "aws" {
  region  = var.aws_region
  profile = var.member_profile

  default_tags {
    tags = {
      ManagedBy    = "terraform"
      Purpose      = "iamscope-env13-acceptance"
      iamscope-env = "env13"
    }
  }
}

data "aws_caller_identity" "current" {}

locals {
  account_id          = data.aws_caller_identity.current.account_id
  management_root_arn = "arn:aws:iam::${var.management_account_id}:root"
}

resource "aws_iam_user" "alice" {
  name = "env13-alice"
  path = "/iamscope-test/"
}

resource "aws_iam_role" "admin" {
  name = "env13-admin"
  path = "/iamscope-test/"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Sid       = "AllowEnv13Alice"
      Effect    = "Allow"
      Principal = { AWS = aws_iam_user.alice.arn }
      Action    = "sts:AssumeRole"
    }]
  })
}

resource "aws_iam_user_policy" "alice_assume_admin" {
  name = "env13-alice-assume-admin"
  user = aws_iam_user.alice.name

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Sid      = "AllowAssumeEnv13Admin"
      Effect   = "Allow"
      Action   = "sts:AssumeRole"
      Resource = aws_iam_role.admin.arn
    }]
  })
}

resource "aws_iam_role_policy_attachment" "admin_administrator" {
  role       = aws_iam_role.admin.name
  policy_arn = "arn:aws:iam::aws:policy/AdministratorAccess"
}

resource "aws_iam_role" "collection_reader" {
  name = var.collection_role_name
  path = "/iamscope-test/"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Sid       = "AllowManagementAccountCollection"
      Effect    = "Allow"
      Principal = { AWS = local.management_root_arn }
      Action    = "sts:AssumeRole"
    }]
  })
}

resource "aws_iam_role_policy_attachment" "collection_reader_readonly" {
  role       = aws_iam_role.collection_reader.name
  policy_arn = "arn:aws:iam::aws:policy/ReadOnlyAccess"
}

output "account_id" {
  value = local.account_id
}

output "alice_arn" {
  value = aws_iam_user.alice.arn
}

output "admin_arn" {
  value = aws_iam_role.admin.arn
}

output "collection_role_name" {
  value = aws_iam_role.collection_reader.name
}

output "collection_role_arn" {
  value = aws_iam_role.collection_reader.arn
}
