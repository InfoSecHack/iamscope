# Contributing

IAMScope is preparing for a research-preview release. The detailed contributor guide lives at [`docs/CONTRIBUTING.md`](docs/CONTRIBUTING.md).

Before opening a change, use the safe local validation path:

```bash
source .venv/bin/activate
./scripts/check.sh
./scripts/test_fast.sh
```

Do not run live AWS, STS probes, `iam:PassRole`, Lambda APIs, Terraform, or resource-changing acceptance scripts unless a separate reviewed protocol explicitly authorizes that work. Do not commit credentials, raw AWS artifacts, `/tmp` outputs, Terraform state/cache/provider artifacts, generated bundles, pass/fail benchmark labels, or composite scores.
