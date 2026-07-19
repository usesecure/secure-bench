# Secure Bench Phase 24

Phase 24 is a Semgrep CE 1.170.0-only post-open recovery study using the exact
Phase 23 corrected sandbox. It executes 112 frozen capability-normalized case
attempts once, preserves raw evidence, and compares the resulting lane only
with OpenGrep capability-normalized Phase 22.

Lifecycle:

```text
secure-bench-phase24 prepare .
secure-bench-phase24 preflight .
secure-bench-phase24 execute-once .
secure-bench-phase24 verify .
```

`prepare` and `preflight` do not open case files. `execute-once` creates the
irreversible marker before reading the Phase 19 manifest or cases. `verify`
never starts a scanner. The independent verifier is also scanner-free:

```text
/usr/bin/python3 phase24/reproducer/independent_verify.py .
```

CI includes Phase 24 format, strict Clippy, offline tests, RustSec, cargo-deny,
the Rust verifier, and the independent Python recalculation. Scanner execution
is intentionally not a CI action; the sealed evidence is verified instead.
