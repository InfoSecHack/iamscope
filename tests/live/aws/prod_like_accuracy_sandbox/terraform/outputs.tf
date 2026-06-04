output "source_principal_user_names" {
  description = "IAM user names for future controlled collection. No credentials or secrets."
  value       = { for key, user in aws_iam_user.source : key => user.name }
}

output "source_principal_user_arns" {
  description = "IAM user ARNs for future controlled collection. These must be sanitized before commit."
  value       = { for key, user in aws_iam_user.source : key => user.arn }
}

output "target_role_names" {
  description = "IAM role names for future controlled collection."
  value       = { for key, role in aws_iam_role.target : key => role.name }
}

output "target_role_arns" {
  description = "IAM role ARNs for future controlled collection. These must be sanitized before commit."
  value       = { for key, role in aws_iam_role.target : key => role.arn }
}

output "source_inline_policy_names" {
  description = "IAM source-principal inline policy names for future controlled collection."
  value       = { for key, policy in aws_iam_user_policy.source_relationships : key => policy.name }
}

output "role_inline_policy_names" {
  description = "IAM role inline policy names for future controlled collection."
  value = {
    prod_observer = aws_iam_role_policy.assume_chain_continuation.name
  }
}

output "identity_deny_policy_arn" {
  description = "Explicit deny policy ARN for future controlled collection. This must be sanitized before commit."
  value       = aws_iam_policy.identity_deny.arn
}

output "guardrail_simulation_policy_arns" {
  description = "IAM-only guardrail simulation policy ARNs for future controlled collection. These must be sanitized before commit."
  value       = { for key, policy in aws_iam_policy.guardrail_simulation : key => policy.arn }
}

output "oracle_row_mapping" {
  description = "Static mapping from frozen oracle rows to planned Terraform resource groups."
  value       = local.oracle_row_mapping
}

output "unsupported_static_only_rows" {
  description = "Unsupported rows that have no live resources in v1."
  value       = local.unsupported_static_only_rows
}
