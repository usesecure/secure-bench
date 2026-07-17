# Secure Bench Phase 11 verifier

This Rust crate reconstructs the retired Phase 9 and Phase 10 diagnostic package entirely offline.
It has no scanner execution command and no process-launch API.

```bash
cargo run --manifest-path phase11/Cargo.toml -- generate /path/to/secure-bench
cargo run --manifest-path phase11/Cargo.toml -- verify /path/to/secure-bench
cargo run --manifest-path phase11/Cargo.toml -- summary /path/to/secure-bench
```

Generation is create-new only. Verification reconstructs every output in memory, validates the
schemas and ledger chain, and requires byte-identical committed output. Phase 10 remains the
official preregistered result and is never rescored.
