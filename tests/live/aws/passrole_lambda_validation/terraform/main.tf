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

locals {
  denied_source_trusted_principal_arn = (
    var.denied_source_trusted_principal_arn != null && trimspace(var.denied_source_trusted_principal_arn) != ""
    ? var.denied_source_trusted_principal_arn
    : data.aws_caller_identity.current.arn
  )
}

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

data "aws_iam_policy_document" "denied_source_assume_role" {
  statement {
    actions = ["sts:AssumeRole"]

    principals {
      type        = "AWS"
      identifiers = [local.denied_source_trusted_principal_arn]
    }
  }
}

data "aws_iam_policy_document" "denied_source_lambda_create" {
  statement {
    actions = ["lambda:CreateFunction"]
    resources = [
      "arn:aws:lambda:${var.aws_region}:${var.expected_account_id}:function:${var.name_prefix}-*",
    ]
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

resource "aws_iam_role" "denied_source" {
  depends_on = [terraform_data.expected_account_guard]

  name               = "${var.name_prefix}-denied-source-role"
  assume_role_policy = data.aws_iam_policy_document.denied_source_assume_role.json
  description        = "Test-only IAMScope denied source role with Lambda CreateFunction but no PassRole allow."
  tags               = var.tags
}

resource "aws_iam_policy" "denied_source_lambda_create" {
  depends_on = [terraform_data.expected_account_guard]

  name        = "${var.name_prefix}-denied-source-lambda-create"
  description = "Test-only IAMScope denied source policy for Lambda CreateFunction only."
  policy      = data.aws_iam_policy_document.denied_source_lambda_create.json
  tags        = var.tags
}

resource "aws_iam_role_policy_attachment" "denied_source_lambda_create" {
  role       = aws_iam_role.denied_source.name
  policy_arn = aws_iam_policy.denied_source_lambda_create.arn
}
