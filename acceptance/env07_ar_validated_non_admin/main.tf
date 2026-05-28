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
      Purpose      = "iamscope-env07-acceptance"
      ManagedBy    = "terraform"
      iamscope-env = "env07"
    }
  }
}

data "aws_caller_identity" "current" {}

locals {
  account_id = data.aws_caller_identity.current.account_id
}

resource "aws_iam_user" "alice" {
  name = "env07-alice"
  path = "/iamscope-test/"
}

resource "aws_iam_role" "reader" {
  name = "env07-reader"
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

resource "aws_iam_user_policy" "alice_assume_reader" {
  name = "env07-alice-assume-reader"
  user = aws_iam_user.alice.name

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Sid      = "AllowAssumeReader"
      Effect   = "Allow"
      Action   = "sts:AssumeRole"
      Resource = aws_iam_role.reader.arn
    }]
  })
}

resource "aws_iam_role_policy" "reader_non_admin" {
  name = "env07-reader-non-admin"
  role = aws_iam_role.reader.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Sid      = "AllowListBucketsOnly"
      Effect   = "Allow"
      Action   = ["s3:ListAllMyBuckets"]
      Resource = "*"
    }]
  })
}

output "account_id" {
  value       = local.account_id
  description = "AWS account ID"
}

output "alice_arn" {
  value       = aws_iam_user.alice.arn
  description = "ARN of env07-alice - source principal"
}

output "reader_arn" {
  value       = aws_iam_role.reader.arn
  description = "ARN of env07-reader - reachable non-admin target role"
}