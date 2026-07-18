# Secure Bench Phase 15

This Rust workspace reconstructs the Phase 15 causal postmortem entirely offline from committed,
retired Phase 13 fixtures and contracts plus immutable retained Phase 14 reports and evaluator
decisions. It contains no scanner, AI, network, or subprocess execution path.

Run `cargo run --manifest-path phase15/Cargo.toml -- verify .` from the repository root after the
generated package has been committed. Phase 15 is additive and never rewrites or rescores Phase 14.
