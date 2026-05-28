# Env 11 - broad-looking same-account trust guarded by MFA.
#
# Scenario: alice -> admin
#   - alice has sts:AssumeRole permission on env11-broad-conditioned-admin
#   - env11-broad-conditioned-admin has AdministratorAccess
#   - trust policy allows the same-account root principal, but requires MFA
#
# Expected IAMScope output:
#   - scenario exports permission/trust structure and TRUST_CONDITION evidence
#   - admin_reachability must not be VALIDATED for alice -> admin
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
      Purpose      = "iamscope-env11-acceptance"
      iamscope-env = "env11"
    }
  }
}

data "aws_caller_identity" "current" {}

locals {
  account_id = data.aws_caller_identity.current.account_id
  root_arn   = "arn:aws:iam::${local.account_id}:root"
}

data "aws_iam_policy_document" "broad_conditioned_admin_trust" {
  statement {
    sid     = "AllowSameAccountRootWithMFA"
    effect  = "Allow"
    actions = ["sts:AssumeRole"]

    principals {
      type        = "AWS"
      identifiers = [local.root_arn]
    }

    condition {
      test     = "Bool"
      variable = "aws:MultiFactorAuthPresent"
      values   = ["true"]
    }
  }
}

resource "aws_iam_role" "broad_conditioned_admin" {
  name               = "env11-broad-conditioned-admin"
  path               = "/iamscope-test/"
  assume_role_policy = data.aws_iam_policy_document.broad_conditioned_admin_trust.json
}

resource "aws_iam_role_policy_attachment" "broad_conditioned_admin_access" {
  role       = aws_iam_role.broad_conditioned_admin.name
  policy_arn = "arn:aws:iam::aws:policy/AdministratorAccess"
}

resource "aws_iam_user" "alice" {
  name = "env11-alice"
  path = "/iamscope-test/"
}

data "aws_iam_policy_document" "alice_assume_broad_conditioned_admin" {
  statement {
    sid       = "AllowAssumeBroadConditionedAdmin"
    effect    = "Allow"
    actions   = ["sts:AssumeRole"]
    resources = [aws_iam_role.broad_conditioned_admin.arn]
  }
}

resource "aws_iam_user_policy" "alice_assume_broad_conditioned_admin" {
  name   = "env11-alice-assume-broad-conditioned-admin"
  user   = aws_iam_user.alice.name
  policy = data.aws_iam_policy_document.alice_assume_broad_conditioned_admin.json
}

output "account_id" {
  value = local.account_id
}

output "alice_arn" {
  value = aws_iam_user.alice.arn
}

output "broad_conditioned_admin_arn" {
  value = aws_iam_role.broad_conditioned_admin.arn
}

output "root_arn" {
  value = local.root_arn
}
