# Env 7: Reachable Non-Admin AssumeRole Benchmark

## Overview

This environment is the smallest positive non-admin AssumeRole benchmark.
It creates one user and one non-admin role with a truthful direct assume-role path:

```text
env07-alice --[sts:AssumeRole allow + matching trust]--> env07-reader
```

`env07-reader` has only `s3:ListAllMyBuckets`, so the path is reachable but not
admin-equivalent.

## AWS Resources Created

- IAM user: `env07-alice`
- Inline IAM user policy: `env07-alice-assume-reader`
- IAM role: `env07-reader`
- Inline IAM role policy: `env07-reader-non-admin`

No paid AWS services are created.