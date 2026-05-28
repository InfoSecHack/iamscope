# Env 9 ? mutation pair of Env05 with the devops permission boundary removed.
#
# Scenario: alice -> devops -> admin
#   - alice can assume devops
#   - devops can assume admin
#   - admin has AdministratorAccess
#   - unlike Env05, devops has no permission boundary
#
# Expected IAMScope output:
#   - admin_reachability: VALIDATED for alice -> admin
#   - no blocked/inconclusive admin_reachability for alice -> admin
#   - assume_role_chain may validate for the same path; the benchmark logs it but does not require it
#
# Cost: $0 ? all IAM resources, no paid services.
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
      Purpose      = "iamscope-env09-acceptance"
      ManagedBy    = "terraform"
      iamscope-env = "env09"
    }
  }
}

data "aws_caller_identity" "current" {}

locals {
  account_id = data.aws_caller_identity.current.account_id
}

resource "aws_iam_user" "alice" {
  name = "env09-alice"
  path = "/iamscope-test/"
}

resource "aws_iam_user_policy" "alice_assumerole" {
  name = "env09-alice-assumerole"
  user = aws_iam_user.alice.name

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Sid      = "AllowAssumeDevops"
      Effect   = "Allow"
      Action   = "sts:AssumeRole"
      Resource = aws_iam_role.devops.arn
    }]
  })
}

resource "aws_iam_role" "devops" {
  name = "env09-devops"
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

resource "aws_iam_policy" "devops_assumerole" {
  name        = "env09-devops-assumerole"
  path        = "/iamscope-test/"
  description = "Env09: grants devops permission to assume admin role"

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

resource "aws_iam_role_policy_attachment" "devops_assumerole" {
  role       = aws_iam_role.devops.name
  policy_arn = aws_iam_policy.devops_assumerole.arn
}

resource "aws_iam_role" "admin" {
  name = "env09-admin"
  path = "/iamscope-test/"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Principal = { AWS = aws_iam_role.devops.arn }
      Action    = "sts:AssumeRole"
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
  description = "ARN of env09-alice ? chain source principal"
}

output "devops_arn" {
  value       = aws_iam_role.devops.arn
  description = "ARN of env09-devops ? intermediate role without a blocking boundary"
}

output "admin_arn" {
  value       = aws_iam_role.admin.arn
  description = "ARN of env09-admin ? admin-equivalent chain endpoint"
}
