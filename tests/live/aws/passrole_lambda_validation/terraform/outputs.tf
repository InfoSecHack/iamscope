output "lambda_execution_role_arn" {
  description = "Test-only Lambda execution role ARN used by the live validation runner."
  value       = aws_iam_role.lambda_execution.arn
}

output "lambda_execution_role_name" {
  description = "Test-only Lambda execution role name."
  value       = aws_iam_role.lambda_execution.name
}

output "denied_source_role_arn" {
  description = "Test-only denied source role ARN used by denied-mode live validation."
  value       = aws_iam_role.denied_source.arn
}

output "denied_source_role_name" {
  description = "Test-only denied source role name."
  value       = aws_iam_role.denied_source.name
}
