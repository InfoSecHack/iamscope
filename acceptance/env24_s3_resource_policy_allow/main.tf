terraform {
  required_version = ">= 1.5.0"

  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
    random = {
      source  = "hashicorp/random"
      version = "~> 3.5"
    }
  }
}

provider "aws" {
  region = "us-east-1"

  default_tags {
    tags = {
      ManagedBy    = "terraform"
      Purpose      = "iamscope-env24-acceptance"
      iamscope-env = "env24"
    }
  }
}

data "aws_caller_identity" "current" {}

resource "random_id" "suffix" {
  byte_length = 4
}

locals {
  bucket_name = "env24-rp-allow-${data.aws_caller_identity.current.account_id}-${random_id.suffix.hex}"
  bucket_arn  = "arn:aws:s3:::${local.bucket_name}"
}

resource "aws_iam_user" "reader" {
  name = "env24-reader"
  path = "/iamscope-test/"
}

resource "aws_s3_bucket" "target" {
  bucket        = local.bucket_name
  force_destroy = true
}

resource "aws_s3_bucket_public_access_block" "target" {
  bucket = aws_s3_bucket.target.id

  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

data "aws_iam_policy_document" "bucket_policy" {
  statement {
    sid     = "AllowEnv24ReaderGetObject"
    effect  = "Allow"
    actions = ["s3:GetObject"]

    principals {
      type        = "AWS"
      identifiers = [aws_iam_user.reader.arn]
    }

    resources = ["${aws_s3_bucket.target.arn}/*"]
  }
}

resource "aws_s3_bucket_policy" "target" {
  bucket = aws_s3_bucket.target.id
  policy = data.aws_iam_policy_document.bucket_policy.json

  depends_on = [aws_s3_bucket_public_access_block.target]
}

output "account_id" {
  value = data.aws_caller_identity.current.account_id
}

output "reader_arn" {
  value = aws_iam_user.reader.arn
}

output "bucket_arn" {
  value = aws_s3_bucket.target.arn
}

output "bucket_name" {
  value = aws_s3_bucket.target.bucket
}
