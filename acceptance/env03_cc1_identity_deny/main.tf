# Env 3 - CC-1 regression test: explicit identity-policy Deny overrides Allow.
#
# Scenario: env03-cc1-alice has an identity policy with both:
#   - Allow iam:AddUserToGroup on env03-cc1-admins
#   - Deny  iam:AddUserToGroup on env03-cc1-admins
#
# env03-cc1-admins has AdministratorAccess, so an Allow-only graph would look
# like an IAM group-membership escalation. AWS IAM evaluation says explicit Deny
# overrides Allow, so iamscope must emit BLOCKED, not VALIDATED.
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
      Purpose      = "iamscope-env03-cc1-acceptance"
      ManagedBy    = "terraform"
      iamscope-env = "env03-cc1"
    }
  }
}

# ----------------------------------------------------------------------
# Data sources
# ----------------------------------------------------------------------

data "aws_caller_identity" "current" {}

locals {
  account_id = data.aws_caller_identity.current.account_id
}

# ----------------------------------------------------------------------
# Source principal: env03-cc1-alice
#
# The inline identity policy deliberately contains a matching Allow and Deny.
# The Allow creates the permission edge that the group-membership escalation
# reasoner would otherwise validate. The Deny should bind to that same edge and
# force the finding to BLOCKED.
# ----------------------------------------------------------------------

resource "aws_iam_user" "alice" {
  name = "env03-cc1-alice"
  path = "/iamscope-test/"
}

resource "aws_iam_user_policy" "alice_allow_and_deny_add_user_to_group" {
  name = "env03-cc1-allow-deny-add-user-to-group"
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
      {
        Sid      = "DenyAddUserToAdmins"
        Effect   = "Deny"
        Action   = "iam:AddUserToGroup"
        Resource = aws_iam_group.admins.arn
      },
    ]
  })
}

# ----------------------------------------------------------------------
# Target: env03-cc1-admins
#
# AdministratorAccess makes this group an admin-equivalent endpoint. If the
# explicit Deny is ignored, iamscope would incorrectly emit VALIDATED for
# alice -> admins.
# ----------------------------------------------------------------------

resource "aws_iam_group" "admins" {
  name = "env03-cc1-admins"
  path = "/iamscope-test/"
}

resource "aws_iam_group_policy_attachment" "admins_administrator" {
  group      = aws_iam_group.admins.name
  policy_arn = "arn:aws:iam::aws:policy/AdministratorAccess"
}

# ----------------------------------------------------------------------
# Outputs - consumed by run.sh via `terraform output -raw`
# ----------------------------------------------------------------------

output "account_id" {
  value       = local.account_id
  description = "AWS account ID"
}

output "alice_arn" {
  value       = aws_iam_user.alice.arn
  description = "ARN of env03-cc1-alice - source principal"
}

output "admins_arn" {
  value       = aws_iam_group.admins.arn
  description = "ARN of env03-cc1-admins - admin-equivalent target group"
}
