# Env 6 - positive admin_reachability validation benchmark.
#
# Scenario: env06-alice can directly assume env06-admin.
#   - alice has an identity policy allowing sts:AssumeRole on env06-admin
#   - env06-admin trusts alice
#   - env06-admin has AdministratorAccess
#
# Expected IAMScope output:
#   - admin_reachability: VALIDATED for alice -> admin
#   - no blocker on that validated target finding
#
# Cost: $0 - all IAM resources, no paid services.
# Cleanup: terraform destroy (run.sh wraps this with trap).

terraform {
  required_version = ">= 1.5"
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
  }
}

provider "aws" {
  region  = "us-east-1"
  profile = "iamscope-admin"

  default_tags {
    tags = {
      Purpose      = "iamscope-env06-acceptance"
      ManagedBy    = "terraform"
      iamscope-env = "env06"
    }
  }
}

data "aws_caller_identity" "current" {}

locals {
  account_id = data.aws_caller_identity.current.account_id
}

resource "aws_iam_user" "alice" {
  name = "env06-alice"
  path = "/iamscope-test/"
}

resource "aws_iam_role" "admin" {
  name = "env06-admin"
  path = "/iamscope-test/"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Principal = { AWS = aws_iam_user.alice.arn }
      Action    = "sts:AssumeRole"
    }]
  })
}

resource "aws_iam_user_policy" "alice_assume_admin" {
  name = "env06-alice-assume-admin"
  user = aws_iam_user.alice.name

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Sid      = "AllowAssumeAdmin"
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

output "account_id" {
  value       = local.account_id
  description = "AWS account ID"
}

output "alice_arn" {
  value       = aws_iam_user.alice.arn
  description = "ARN of env06-alice - source principal"
}

output "admin_arn" {
  value       = aws_iam_role.admin.arn
  description = "ARN of env06-admin - admin-equivalent target role"
}
