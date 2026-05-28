# Env 16 - Env03 mutation: explicit identity-policy Deny removed.
#
# Scenario: env16-alice has an identity policy with:
#   - Allow iam:AddUserToGroup on env16-admins
#   - no matching Deny
#
# env16-admins has AdministratorAccess, so the group-membership escalation
# should validate. This is the positive mutation pair for Env03.
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
      Purpose      = "iamscope-env16-acceptance"
      ManagedBy    = "terraform"
      iamscope-env = "env16"
    }
  }
}

data "aws_caller_identity" "current" {}

locals {
  account_id = data.aws_caller_identity.current.account_id
}

resource "aws_iam_user" "alice" {
  name = "env16-alice"
  path = "/iamscope-test/"
}

resource "aws_iam_user_policy" "alice_allow_add_user_to_group" {
  name = "env16-allow-add-user-to-group"
  user = aws_iam_user.alice.name

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid      = "AllowAddUserToAdmins"
        Effect   = "Allow"
        Action   = "iam:AddUserToGroup"
        Resource = aws_iam_group.admins.arn
      },
    ]
  })
}

resource "aws_iam_group" "admins" {
  name = "env16-admins"
  path = "/iamscope-test/"
}

resource "aws_iam_group_policy_attachment" "admins_administrator" {
  group      = aws_iam_group.admins.name
  policy_arn = "arn:aws:iam::aws:policy/AdministratorAccess"
}

output "account_id" {
  value       = local.account_id
  description = "AWS account ID"
}

output "alice_arn" {
  value       = aws_iam_user.alice.arn
  description = "ARN of env16-alice - source principal"
}

output "admins_arn" {
  value       = aws_iam_group.admins.arn
  description = "ARN of env16-admins - admin-equivalent target group"
}
