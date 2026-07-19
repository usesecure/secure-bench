# Phase 24 verification matrix

The final matrix is scanner-free except for the single explicit
`execute-once` lifecycle action. It must be run once after the frozen Semgrep
cache passes preflight.

```text
cargo fmt --manifest-path phase24/Cargo.toml --all --check
cargo clippy --manifest-path phase24/Cargo.toml --workspace --all-targets --all-features --offline -- -D warnings
cargo test --manifest-path phase24/Cargo.toml --workspace --all-features --offline
cargo audit --file phase24/Cargo.lock --no-fetch --deny warnings
cargo deny --manifest-path phase24/Cargo.toml check
cargo run --offline --locked --manifest-path phase24/Cargo.toml -- verify .
/usr/bin/python3 phase24/reproducer/independent_verify.py .
```

Detached clean verification repeats the matrix at the final signed Phase 24
commit. It verifies committed evidence and must not invoke `prepare`,
`preflight`, `execute-once`, Semgrep, OpenGrep, Secure Engine, or a native lane.
