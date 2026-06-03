# PassRole Lambda Selected Finding Fixture

This sanitized local fixture selects one IAMScope `passrole_lambda` finding/path for the controlled live PassRole-to-Lambda binding follow-up.

It is local-only and synthetic/redacted. It does not run live AWS, Terraform, AWS CLI, STS, Lambda APIs, or `iam:PassRole`. It does not commit raw live output, a real AWS account id, or a real role ARN.

The selected path represents only service-mediated Lambda `CreateFunction` plus `iam:PassRole` plus Lambda trust. It does not include an admin-equivalent execution role edge. It does not claim Lambda invocation behavior, downstream authorization, or exploitability proof. It does not claim broad IAMScope correctness, broad PassRole correctness, production readiness, composite benchmark scoring, or pass/fail benchmark labeling.
