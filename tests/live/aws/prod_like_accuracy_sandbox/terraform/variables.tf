variable "aws_profile" {
  description = "Explicit AWS profile for the future dedicated IAMScope sandbox."
  type        = string
  nullable    = false
}

variable "aws_region" {
  description = "Explicit AWS region for the future dedicated IAMScope sandbox."
  type        = string
  nullable    = false
}

variable "expected_account_id" {
  description = "Expected dedicated sandbox AWS account ID. Must match the caller identity account."
  type        = string
  nullable    = false

  validation {
    condition     = can(regex("^[0-9]{12}$", var.expected_account_id))
    error_message = "expected_account_id must be a 12-digit AWS account ID for the future dedicated sandbox."
  }
}

variable "resource_prefix" {
  description = "Resource name prefix for the IAMScope prod-like v1 sandbox."
  type        = string
  default     = "iamscope-prodlike-v1-"

  validation {
    condition     = startswith(var.resource_prefix, "iamscope-prodlike-v1-")
    error_message = "resource_prefix must begin with iamscope-prodlike-v1-."
  }
}

variable "live_ack" {
  description = "Explicit acknowledgement required before any future live sandbox use."
  type        = string
  nullable    = false

  validation {
    condition     = var.live_ack == "I_UNDERSTAND_THIS_IS_A_DEDICATED_IAMSCOPE_SANDBOX"
    error_message = "live_ack must equal I_UNDERSTAND_THIS_IS_A_DEDICATED_IAMSCOPE_SANDBOX."
  }
}
