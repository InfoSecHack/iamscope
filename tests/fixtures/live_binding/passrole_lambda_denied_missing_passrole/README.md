# PassRole Lambda Denied Missing-PassRole Fixture

This sanitized local fixture represents the denied side of the controlled
PassRole-to-Lambda live binding evidence.

It is local-only and synthetic/redacted. It does not run live AWS, Terraform,
AWS CLI, STS, Lambda APIs, or `iam:PassRole`. It does not commit raw live
output, a real AWS account id, or a real role ARN.

The selected source/target shape represents only service-mediated Lambda
`CreateFunction` plus Lambda trust with missing `iam:PassRole` evidence. The
fixture intentionally omits an `iam:PassRole_permission` edge from the denied
source role to the selected Lambda execution role.

The expected local IAMScope behavior is that the existing
`PassRoleLambdaReasoner` emits no selected validated `passrole_lambda` finding
for this source/target pair because `source_has_passrole_to_target` has no
witness.

This fixture does not claim Lambda invocation behavior, downstream
authorization, admin-equivalent execution role behavior, exploitability proof,
broad IAMScope correctness, broad PassRole correctness, production readiness,
composite benchmark scoring, or pass/fail benchmark labeling.
