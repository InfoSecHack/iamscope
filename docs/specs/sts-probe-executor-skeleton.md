# STS Probe Executor Skeleton Spec

This slice added a no-call/simulation skeleton for the future STS AssumeRole probe executor. A later slice adds the minimal live-capable path behind explicit safety gates.

The skeleton must validate STS probe plans with the existing dry-run validator before emitting any executor-shaped output. It supports only `simulate` and `validate_only` modes, rejects live execution modes, makes no AWS calls, does not call STS AssumeRole, does not require credentials, and does not import or use live AWS SDK paths.

The live-capable path supports only `live_probe`, requires explicit `allow_live_mode`, requires the exact operator confirmation phrase, requires a dry-run-valid one-probe plan, requires caller-provided JSON and Markdown output paths, and keeps the STS client injectable so tests use only fakes/mocks.

Outputs are safe JSON/Markdown summaries written only to caller-provided paths. They must preserve the evidence boundary that live results are narrow STS AssumeRole observations only, and avoid pass/fail labels, composite scoring, raw credentials, raw AWS logs, Terraform artifacts, downstream AWS actions, and generated repo-local outputs.
