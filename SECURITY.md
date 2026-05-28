# Security Policy

## Reporting Security Issues

IAMScope is a research-preview project. Please do not file public issues containing credentials, raw AWS artifacts, account-specific secrets, or exploit details.

For now, report security concerns privately to the repository maintainer through the existing private-review channel or GitHub private vulnerability reporting if it is enabled for the repository. If neither channel is available, request a private contact path from the maintainer before sharing sensitive details.

## Scope

Security review should preserve the repository boundaries:

- Do not run live AWS commands unless a separate reviewed protocol explicitly allows it.
- Do not call STS, `iam:PassRole`, Lambda APIs, or resource-changing AWS APIs by default.
- Do not attach credentials, raw AWS logs, Terraform state, `/tmp` outputs, generated bundles, or raw collect artifacts to issues or pull requests.
- Keep IAMScope claims bounded to research-preview evidence unless a future release changes that posture.

## Supported Versions

No production support window is defined. Treat the current default branch as the review target for research-preview feedback.
