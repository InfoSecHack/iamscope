# Session 5 Step 8 — real-AWS acceptance testing for iamscope verify v2.
# Creates minimal test resources in the operator's personal AWS account
# so iamscope verify can be exercised against real iam:SimulatePrincipalPolicy.
#
# Resources created:
#   - 1 IAM user: iamscope-target-user (the "victim" principal for test findings)
#   - 1 IAM role: iamscope-target-lambda-role (Lambda service trust policy)
#   - 1 Secrets Manager secret: iamscope-test/sample-secret
#   - Inline policies on the user granting specific allows/denies
#
# Design: three test findings we'll emit against these resources:
#   1. secrets_blast_radius — user can GetSecretValue on the secret (expect simulator_validated)
#   2. passrole_lambda — user can PassRole to the Lambda role (expect simulator_validated)
#   3. cross_account_trust — user "can" AssumeRole on a fictional cross-account role
#      (the test deliberately fails the simulator side — user has no policy for this,
#      proving simulator_disagreement path works in disagreement scenarios)
#
# Cost: ~$0.40/month for the Secrets Manager secret (only paid resource).
# IAM users/roles/policies: free. Run `terraform destroy` to clean up.

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
      Purpose = "iamscope-step8-acceptance"
      ManagedBy = "terraform"
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
# Test resources
# ----------------------------------------------------------------------

# The "target user" — principal that our test findings will reference as the source.
# This is distinct from iamscope-verify (which is the credentials running the tool).
resource "aws_iam_user" "target" {
  name = "iamscope-target-user"
  path = "/iamscope-test/"
}

# The Lambda execution role — target for the passrole_lambda finding.
resource "aws_iam_role" "lambda_exec" {
  name = "iamscope-target-lambda-role"
  path = "/iamscope-test/"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect = "Allow"
      Principal = {
        Service = "lambda.amazonaws.com"
      }
      Action = "sts:AssumeRole"
    }]
  })
}

# The secret — target for the secrets_blast_radius finding.
resource "aws_secretsmanager_secret" "test_secret" {
  name                    = "iamscope-test/sample-secret"
  description             = "Step 8 acceptance test secret — safe to delete"
  recovery_window_in_days = 0  # Immediate deletion on destroy
}

resource "aws_secretsmanager_secret_version" "test_secret" {
  secret_id     = aws_secretsmanager_secret.test_secret.id
  secret_string = jsonencode({ placeholder = "for-testing-only" })
}

# ----------------------------------------------------------------------
# Inline policy on the target user — defines what the target CAN do
# ----------------------------------------------------------------------

resource "aws_iam_user_policy" "target_allow" {
  name = "iamscope-test-allow"
  user = aws_iam_user.target.name

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid      = "AllowSecretRead"
        Effect   = "Allow"
        Action   = "secretsmanager:GetSecretValue"
        Resource = aws_secretsmanager_secret.test_secret.arn
      },
      {
        Sid      = "AllowPassRoleToLambda"
        Effect   = "Allow"
        Action   = "iam:PassRole"
        Resource = aws_iam_role.lambda_exec.arn
      }
    ]
  })
}

# ----------------------------------------------------------------------
# Outputs — emitted after apply, used to construct the test findings.json
# ----------------------------------------------------------------------

output "account_id" {
  value       = local.account_id
  description = "AWS account ID"
}

output "target_user_arn" {
  value       = aws_iam_user.target.arn
  description = "ARN of iamscope-target-user — used as source in test findings"
}

output "lambda_role_arn" {
  value       = aws_iam_role.lambda_exec.arn
  description = "ARN of the Lambda exec role — used as target for passrole_lambda finding"
}

output "secret_arn" {
  value       = aws_secretsmanager_secret.test_secret.arn
  description = "ARN of the test secret — used as target for secrets_blast_radius finding"
}

# Fictional cross-account ARN — does not exist, used to test simulator_disagreement
output "fictional_cross_account_role_arn" {
  value       = "arn:aws:iam::999999999999:role/fictional-target"
  description = "Fictional role ARN to test simulator_disagreement path"
}
