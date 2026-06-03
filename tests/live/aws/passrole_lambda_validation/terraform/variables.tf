variable "aws_profile" {
  description = "Explicit AWS profile for the authorized test account."
  type        = string
}

variable "expected_account_id" {
  description = "Expected 12-digit AWS account id for the authorized test account."
  type        = string

  validation {
    condition     = can(regex("^[0-9]{12}$", var.expected_account_id))
    error_message = "expected_account_id must be a 12-digit AWS account id."
  }
}

variable "aws_region" {
  description = "AWS region for the test-only controlled live validation fixture."
  type        = string
}

variable "name_prefix" {
  description = "Name prefix for test-only resources."
  type        = string
  default     = "iamscope-live-passrole-lambda-test"
}

variable "denied_source_trusted_principal_arn" {
  description = "Optional AWS principal ARN trusted to assume the denied source role. Defaults to the current caller ARN."
  type        = string
  default     = null
}

variable "tags" {
  description = "Required tags for all taggable resources."
  type        = map(string)
  default = {
    Project = "IAMScope"
    Purpose = "ControlledLiveValidation"
    Owner   = "TestOnly"
  }
}
