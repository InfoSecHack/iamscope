# Env 5 — AR-1 regression test: permission boundary blocks hop 2 of a chain.
#
# Scenario: alice -> devops -> admin
#   - alice has no policies (just exists as a principal)
#   - devops trusts alice, has sts:AssumeRole permission to admin,
#     BUT has a permission boundary that excludes sts:AssumeRole
#   - admin trusts devops, has AdministratorAccess (admin-equivalent endpoint)
#
# Expected iamscope output:
#   - assume_role_chain: BLOCKED (alice -> admin)
#       boundary on devops blocks hop 2 (devops -> admin)
#   - admin_reachability: INCONCLUSIVE, blocker kind=cross_reasoner_blocked
#       Phase 2 AR-1 fix: post-processor demotes VALIDATED to INCONCLUSIVE
#       because the overlapping assume_role_chain finding is BLOCKED
#
# Without the Phase 2 fix, admin_reachability would emit VALIDATED.
# This test is the regression guard against bringing that bug back.
#
# Cost: $0 — all IAM resources, no paid services.
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
      Purpose       = "iamscope-env05-acceptance"
      ManagedBy     = "terraform"
      iamscope-env  = "env05"
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
# Principal: env05-alice
# Has sts:AssumeRole permission on devops, creating the permission edge
# alice→devops needed for the chain to be detected. iamscope requires
# BOTH a permission edge (from alice's identity policy) AND a trust edge
# (from devops's trust policy) to build a hop; without alice's policy
# no chain starting from alice exists in the graph.
# ----------------------------------------------------------------------

resource "aws_iam_user" "alice" {
  name = "env05-alice"
  path = "/iamscope-test/"
}

resource "aws_iam_user_policy" "alice_assumerole" {
  name = "env05-alice-assumerole"
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

# ----------------------------------------------------------------------
# Intermediate role: env05-devops
#
# Trust: accepts assume from alice (explicit ARN in trust policy)
# Permission: has sts:AssumeRole on admin (permission edge exists)
# Boundary: allows only s3:ListBucket — sts:AssumeRole is absent,
#   so the boundary produces an implicit deny on hop 2.
#
# iamscope's permission_boundary.py resolves this:
#   the boundary edge binds to the devops->admin permission edge,
#   sets likely_blocking=True, and assume_role_chain emits BLOCKED.
# ----------------------------------------------------------------------

resource "aws_iam_role" "devops" {
  name                 = "env05-devops"
  path                 = "/iamscope-test/"
  permissions_boundary = aws_iam_policy.devops_boundary.arn

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Principal = { AWS = aws_iam_user.alice.arn }
      Action    = "sts:AssumeRole"
    }]
  })
}

# Permission boundary on devops: allows only s3:ListBucket on *.
# sts:AssumeRole is NOT in the Allow set → implicit deny on that action.
# An all-deny or empty boundary is invalid per IAM; at least one Allow
# statement is required for a policy to be accepted.
resource "aws_iam_policy" "devops_boundary" {
  name        = "env05-devops-boundary"
  path        = "/iamscope-test/"
  description = "Env05 permission boundary: excludes sts:AssumeRole (implicit deny)"

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Sid      = "AllowHarmlessOnly"
      Effect   = "Allow"
      Action   = "s3:ListBucket"
      Resource = "*"
    }]
  })
}

# Permission policy: grants devops sts:AssumeRole on admin.
# This creates the permission edge that iamscope picks up.
# The boundary then blocks that edge from being effective.
resource "aws_iam_policy" "devops_assumerole" {
  name        = "env05-devops-assumerole"
  path        = "/iamscope-test/"
  description = "Env05: grants devops permission to assume admin role"

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

# ----------------------------------------------------------------------
# Endpoint role: env05-admin
#
# Trust: accepts assume from devops (explicit ARN in trust policy)
# Permissions: AdministratorAccess — this is the admin-equivalent
#   endpoint that both reasoners detect.
# ----------------------------------------------------------------------

resource "aws_iam_role" "admin" {
  name = "env05-admin"
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

# ----------------------------------------------------------------------
# Outputs — consumed by run.sh via `terraform output -json`
# ----------------------------------------------------------------------

output "account_id" {
  value       = local.account_id
  description = "AWS account ID"
}

output "alice_arn" {
  value       = aws_iam_user.alice.arn
  description = "ARN of env05-alice — chain source principal"
}

output "devops_arn" {
  value       = aws_iam_role.devops.arn
  description = "ARN of env05-devops — intermediate role with blocked boundary"
}

output "admin_arn" {
  value       = aws_iam_role.admin.arn
  description = "ARN of env05-admin — admin-equivalent chain endpoint"
}
