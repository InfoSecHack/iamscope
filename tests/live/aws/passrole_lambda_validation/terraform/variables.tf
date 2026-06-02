variable "aws_region" {
  description = "AWS region for the test-only controlled live validation fixture."
  type        = string
}

variable "name_prefix" {
  description = "Name prefix for test-only resources."
  type        = string
  default     = "iamscope-live-passrole-lambda-test"
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
