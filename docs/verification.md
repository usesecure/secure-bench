# Phase 0 Verification

## Environment baseline

Phase 0 was implemented against Fedora 44 with Rust and Cargo 1.96.1. Dependency versions were selected from the current crates.io registry while retaining Rust 1.96 compatibility:

- `clap` 4.6.2 for the Rust CLI;
- `serde` 1.0.228 and `serde_json` 1.0.150 for typed contracts;
- `toml` 1.1.3 for human-authored suite manifests;
- `jsonschema` 0.47.0 for runtime schema validation;
- `sha2` 0.11.0 for artifact fingerprints; and
- `thiserror` 2.0.18 for structured errors.

`Cargo.lock` pins the resolved transitive graph. `deny.toml` rejects wildcard dependencies, unknown sources, unapproved licenses, and known advisories. The workspace forbids unsafe Rust and denies the Clippy `all`, `pedantic`, `unwrap_used`, `expect_used`, `panic`, `dbg_macro`, and `todo` lint groups.

No scanner, scanner package, external corpus, skill, or system package is installed or modified by the benchmark or its verification commands.

## Required gates

Run from the repository root:

```bash
cargo fmt --all --check
cargo clippy --workspace --all-targets --all-features -- -D warnings
cargo test --workspace --all-features
cargo audit --deny warnings
cargo deny check
```

The CI workflow runs the same gates with Rust 1.96.1 and the required Rust components.

## Behavioral coverage

The end-to-end tests prove:

- equivalent native JSON and SARIF findings produce identical matching decisions and score cards;
- identical committed inputs serialize byte-for-byte identically;
- safe-control false positives remain visible and reduce clean coverage;
- duplicate alerts do not increase detection credit;
- matching requires category, invariant, source, sink, and evidence constraints;
- malformed, privacy-unsafe, unsupported, missing, crashed, and timed-out inputs cannot appear as clean scans;
- suite, recorded-run, and result projections validate against committed schemas;
- exported paths remain repository-relative and source/report messages are not embedded; and
- fingerprints and matching decisions link aggregate metrics back to committed raw inputs.

## Manual mock-only check

```bash
cargo run --bin secure-bench -- evaluate \
  --suite fixtures/suite.toml \
  --run fixtures/reports/runs/native-success.json \
  --output /tmp/secure-bench-native.json

cargo run --bin secure-bench -- evaluate \
  --suite fixtures/suite.toml \
  --run fixtures/reports/runs/sarif-success.json \
  --output /tmp/secure-bench-sarif.json
```

The tool provenance and artifact fingerprints differ, as they should. Their normalized matching decisions and score cards are equivalent. Neither command executes a scanner.
