# Secure Bench Phase 25

Phase 25 performs the final Semgrep CE 1.170.0 capability-normalized recovery
over the already-open 112-case corpus, with zero retries and a comparison only
against OpenGrep capability-normalized Phase 22.

Lifecycle, from the repository root:

```text
/tmp/secure-bench-tools/rust/1.96.1/bin/cargo run --offline --locked --release --manifest-path phase25/Cargo.toml -- qualify .
/tmp/secure-bench-tools/rust/1.96.1/bin/cargo run --offline --locked --release --manifest-path phase25/Cargo.toml -- prepare .
/tmp/secure-bench-tools/rust/1.96.1/bin/cargo run --offline --locked --release --manifest-path phase25/Cargo.toml -- preflight .
/tmp/secure-bench-tools/rust/1.96.1/bin/cargo run --offline --locked --release --manifest-path phase25/Cargo.toml -- execute-once .
/tmp/secure-bench-tools/rust/1.96.1/bin/cargo run --offline --locked --release --manifest-path phase25/Cargo.toml -- verify .
```

Only `execute-once` may open the manifest and cases. It writes
`CORPUS_OPENED.json` immediately before the first such read. After `prepare`,
network and implementation changes are forbidden. The Python verifier is
scanner-free:

```text
PYTHONDONTWRITEBYTECODE=1 /usr/bin/python3.14 phase25/reproducer/independent_verify.py .
```
