# Secure Bench Phase 17

Phase 17 contains two Rust crates:

- `secure-bench-scanner-protocol`: reusable scanner manifest, availability, raw-artifact,
  post-projection identity, and separate process-policy types;
- `secure-bench-opengrep-adapter`: fail-closed OpenGrep JSON projection and scanner-free offline
  conformance verifier.

Run the bounded offline verifier from the repository root:

```text
cargo run --offline --manifest-path phase17/Cargo.toml \
  -p secure-bench-opengrep-adapter -- verify .
```

Run the full Phase 17 gate after `cargo-audit` and `cargo-deny` are installed:

```text
phase17/scripts/verify-phase17.sh
```

The verifier never launches OpenGrep or any other scanner. It reads only the public Phase 17
manifest, provenance, rules, schema, disclosed source fixture, and synthetic raw reports.
