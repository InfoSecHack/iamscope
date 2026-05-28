# Env22 - validated cross-account AssumeRole admin path.
#
# Scenario:
#   caller account env22-alice -> sts:AssumeRole permission -> target account admin role
#   caller account env22-alice -> target role trust principal -> target account admin role
#
# Expected IAMScope output:
#   - scenario exports cross-account permission/trust structure
#   - admin_reachability is VALIDATED for alice -> admin
#   - cross_account_trust is VALIDATED for alice -> admin
#
# Cost: $0 - IAM resources only.
# Cleanup: run.sh calls terraform destroy.

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

variable "caller_profile" {
  type = string
}

variable "target_profile" {
  type = string
}

variable "caller_account_id" {
  type = string
}

variable "target_account_id" {
  type = string
}

variable "management_account_id" {
  type = string
}

variable "collection_role_name" {
  type    = string
  default = "env22-iamscope-reader"
}

provider "aws" {
  alias   = "caller"
  region  = var.aws_region
  profile = var.caller_profile

  default_tags {
    tags = {
      ManagedBy    = "terraform"
      Purpose      = "iamscope-env22-acceptance"
      iamscope-env = "env22"
    }
  }
}

provider "aws" {
  alias   = "target"
  region  = var.aws_region
  profile = var.target_profile

  default_tags {
    tags = {
      ManagedBy    = "terraform"
      Purpose      = "iamscope-env22-acceptance"
      iamscope-env = "env22"
    }
  }
}

data "aws_caller_identity" "caller" {
  provider = aws.caller
}

data "aws_caller_identity" "target" {
  provider = aws.target
}

locals {
  management_root_arn = "arn:aws:iam::${var.management_account_id}:root"
}

resource "aws_iam_user" "alice" {
  provider = aws.caller
  name     = "env22-alice"
  path     = "/iamscope-test/"
}

resource "aws_iam_role" "admin" {
  provider = aws.target
  name     = "env22-cross-account-admin"
  path     = "/iamscope-test/"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid       = "AllowEnv22Alice"
        Effect    = "Allow"
        Principal = { AWS = aws_iam_user.alice.arn }
        Action    = "sts:AssumeRole"
      }
    ]
  })
}

resource "aws_iam_user_policy" "alice_assume_admin" {
  provider = aws.caller
  name     = "env22-alice-assume-cross-account-admin"
  user     = aws_iam_user.alice.name

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid      = "AllowAssumeEnv22CrossAccountAdmin"
        Effect   = "Allow"
        Action   = "sts:AssumeRole"
        Resource = aws_iam_role.admin.arn
      }
    ]
  })
}

resource "aws_iam_role_policy_attachment" "admin_administrator" {
  provider   = aws.target
  role       = aws_iam_role.admin.name
  policy_arn = "arn:aws:iam::aws:policy/AdministratorAccess"
}

resource "aws_iam_role" "caller_collection_reader" {
  provider = aws.caller
  name     = var.collection_role_name

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid       = "AllowManagementAccountCollection"
        Effect    = "Allow"
        Principal = { AWS = local.management_root_arn }
        Action    = "sts:AssumeRole"
      }
    ]
  })
}

resource "aws_iam_role_policy_attachment" "caller_collection_reader_readonly" {
  provider   = aws.caller
  role       = aws_iam_role.caller_collection_reader.name
  policy_arn = "arn:aws:iam::aws:policy/ReadOnlyAccess"
}

resource "aws_iam_role" "target_collection_reader" {
  provider = aws.target
  name     = var.collection_role_name

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid       = "AllowManagementAccountCollection"
        Effect    = "Allow"
        Principal = { AWS = local.management_root_arn }
        Action    = "sts:AssumeRole"
      }
    ]
  })
}

resource "aws_iam_role_policy_attachment" "target_collection_reader_readonly" {
  provider   = aws.target
  role       = aws_iam_role.target_collection_reader.name
  policy_arn = "arn:aws:iam::aws:policy/ReadOnlyAccess"
}

output "caller_account_id" {
  value = data.aws_caller_identity.caller.account_id
}

output "target_account_id" {
  value = data.aws_caller_identity.target.account_id
}

output "alice_arn" {
  value = aws_iam_user.alice.arn
}

output "admin_arn" {
  value = aws_iam_role.admin.arn
}

output "collection_role_name" {
  value = var.collection_role_name
}

output "caller_collection_role_arn" {
  value = aws_iam_role.caller_collection_reader.arn
}

output "target_collection_role_arn" {
  value = aws_iam_role.target_collection_reader.arn
}
