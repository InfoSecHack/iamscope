terraform {
  required_version = ">= 1.5.0"

  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = ">= 5.0"
    }
  }
}

provider "aws" {
  profile = var.aws_profile
  region  = var.aws_region

  default_tags {
    tags = var.tags
  }
}

data "aws_caller_identity" "current" {}

resource "terraform_data" "expected_account_guard" {
  input = data.aws_caller_identity.current.account_id

  lifecycle {
    precondition {
      condition     = data.aws_caller_identity.current.account_id == var.expected_account_id
      error_message = "AWS caller account does not match expected_account_id; aborting test fixture creation."
    }
  }
}

data "aws_iam_policy_document" "lambda_assume_role" {
  statement {
    actions = ["sts:AssumeRole"]

    principals {
      type        = "Service"
      identifiers = ["lambda.amazonaws.com"]
    }
  }
}

data "aws_iam_policy_document" "lambda_basic_logs" {
  statement {
    actions = [
      "logs:CreateLogGroup",
      "logs:CreateLogStream",
      "logs:PutLogEvents",
    ]
    resources = ["arn:aws:logs:*:*:*"]
  }
}

resource "aws_iam_role" "lambda_execution" {
  depends_on = [terraform_data.expected_account_guard]

  name               = "${var.name_prefix}-lambda-exec-role"
  assume_role_policy = data.aws_iam_policy_document.lambda_assume_role.json
  description        = "Test-only IAMScope controlled live PassRole-to-Lambda validation role."
  tags               = var.tags
}

resource "aws_iam_policy" "lambda_basic_logs" {
  depends_on = [terraform_data.expected_account_guard]

  name        = "${var.name_prefix}-lambda-basic-logs"
  description = "Test-only IAMScope controlled live validation Lambda logging policy."
  policy      = data.aws_iam_policy_document.lambda_basic_logs.json
  tags        = var.tags
}

resource "aws_iam_role_policy_attachment" "lambda_basic_logs" {
  role       = aws_iam_role.lambda_execution.name
  policy_arn = aws_iam_policy.lambda_basic_logs.arn
}
