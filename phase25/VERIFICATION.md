# Phase 25 verification

Before freeze, run the exact local toolchain in offline locked mode:

```text
RUSTC=/tmp/secure-bench-tools/rust/1.96.1/bin/rustc RUSTDOC=/tmp/secure-bench-tools/rust/1.96.1/bin/rustdoc /tmp/secure-bench-tools/rust/1.96.1/bin/cargo test --offline --locked --manifest-path phase25/Cargo.toml
PYTHONDONTWRITEBYTECODE=1 /usr/bin/python3.14 -m unittest discover -s phase25/reproducer -p 'test_*.py'
/tmp/secure-bench-tools/rust/1.96.1/bin/cargo fmt --manifest-path phase25/Cargo.toml -- --check
RUSTC=/tmp/secure-bench-tools/rust/1.96.1/bin/rustc /tmp/secure-bench-tools/rust/1.96.1/bin/cargo clippy --offline --locked --all-targets --manifest-path phase25/Cargo.toml -- -D warnings
```

The synthetic qualification runs exactly two scanner processes and reads no
holdout files. The final Rust and Python verification commands start zero
scanner processes and recalculate only sealed evidence after corpus opening.

Signature verification obtains the trusted signer file from the common Git
directory, so the same policy applies in the primary repository, a linked
worktree, and a detached linked worktree.
