# Env 10 - mutation pair of Env08 with the MFA trust condition removed.
#
# Scenario: alice -> admin
#   - alice has sts:AssumeRole permission on env10-admin
#   - env10-admin trusts alice without the Env08 MFA condition
#   - env10-admin has AdministratorAccess
#
# Expected IAMScope output:
#   - admin_reachability: VALIDATED for alice -> admin
#   - no blocked/inconclusive admin_reachability for alice -> admin
#   - no TRUST_CONDITION constraint bound to the trust edge
#
# Cost: $0 - all IAM resources, no paid services.
# Cleanup: terraform destroy (run.sh wraps this with trap).

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
      Purpose      = "iamscope-env10-acceptance"
      iamscope-env = "env10"
    }
  }
}

data "aws_caller_identity" "current" {}

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
  name               = "env10-admin"
  path               = "/iamscope-test/"
  assume_role_policy = data.aws_iam_policy_document.admin_trust.json
}

resource "aws_iam_role_policy_attachment" "admin_access" {
  role       = aws_iam_role.admin.name
  policy_arn = "arn:aws:iam::aws:policy/AdministratorAccess"
}

resource "aws_iam_user" "alice" {
  name = "env10-alice"
  path = "/iamscope-test/"
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
  name   = "env10-alice-assume-admin"
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
