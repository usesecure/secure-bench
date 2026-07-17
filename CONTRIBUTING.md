# Contributing

Secure Bench accepts improvements to tool-neutral contracts, adapters, deterministic evaluation, provenance, isolation, failure accounting, synthetic corpora, and reproducibility checks.

Benchmark changes must preserve historical artifacts and clearly separate prospective methodology from retrospective diagnostics. Do not add scanner-specific aliases, exceptions, hidden weighting, post-result answer changes, or claims unsupported by the measured scope.

Before submitting a change, run formatting, strict Clippy, tests, RustSec, and `cargo-deny` for every workspace touched. Commits must include a Developer Certificate of Origin sign-off (`git commit -s`). Open an issue before changing a frozen contract or authoring a new holdout.

Security reports must follow [SECURITY.md](./SECURITY.md) instead of a public issue.
