output "lambda_execution_role_arn" {
  description = "Test-only Lambda execution role ARN used by the live validation runner."
  value       = aws_iam_role.lambda_execution.arn
}

output "lambda_execution_role_name" {
  description = "Test-only Lambda execution role name."
  value       = aws_iam_role.lambda_execution.name
}
