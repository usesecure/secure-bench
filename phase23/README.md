# Secure Bench Phase 23

Phase 23 diagnoses the Phase 22 Semgrep CE 1.170.0 segmentation fault using
only newly authored synthetic fixtures, applies a minimal external resource
limit correction, and qualifies the corrected environment for a separate
future Phase 24 normalized recovery lane.

The cause is Semgrep's pre-exec stack-limit elevation interacting with the
4 GiB address-space cap and automatic parallel workers. The correction adds
`--stack=8388608` to the outer `prlimit`, bounding both soft and hard stack at
the already-effective 8 MiB soft value.

Phase 23 contains 39 synthetic scanner executions: 28 diagnostic and 11
qualification. Four additional non-scanner probes capture the limit mutation
and confinement properties. There are zero retries and zero holdout accesses.
Phase 22 remains immutable, and Phase 24 is designed but not executed.

Scanner-free verification after checkout:

```bash
cargo run --offline --locked --manifest-path phase23/Cargo.toml \
  --bin independent-verify -- .
```

See `ROOT_CAUSE.md`, `EXPERIMENT_MATRIX.md`, `QUALIFICATION.md`, the corrected
environment contract, retained raw evidence, exhaustive hashes, and
`PHASE24_DESIGN.md`.

