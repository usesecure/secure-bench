# Secure Bench Phase 0–1 Verification

## Environment baseline

Phase 0 and Phase 1 are verified on Fedora 44 with Rust and Cargo 1.96.1. `Cargo.lock` pins the dependency graph. Direct dependencies remain current Rust 1.96-compatible releases:

- `clap` 4.6.2 for the Rust CLI;
- `serde` 1.0.228, `serde_json` 1.0.150, and `toml` 1.1.3 for typed contracts;
- `jsonschema` 0.47.0 for committed schema validation;
- `sha2` 0.11.0 for content and artifact fingerprints;
- `tempfile` 3.27.0 for isolated workspaces;
- `nix` 0.31.3 for Unix process-group cleanup;
- `ctrlc` 3.5.2 for explicit cancellation; and
- `thiserror` 2.0.18 for structured errors.

The workspace forbids unsafe Rust and denies the Clippy `all`, `pedantic`, `unwrap_used`, `expect_used`, `panic`, `dbg_macro`, and `todo` lint groups. Dependency policy rejects wildcard versions, unknown registries and Git sources, unapproved licenses, and known advisories.

The benchmark never installs, builds, updates, discovers, or modifies a scanner. Tests execute only the committed Rust mock helper. A real Secure Engine binary is used only when a user explicitly supplies its path to the `run` command. Opengrep, CodeQL, Joern, Semgrep, Secure Skill, and external corpora are outside Phase 1 and are not installed or executed.

## Required gates

Run from the repository root:

```bash
cargo fmt --all --check
cargo clippy --workspace --all-targets --all-features -- -D warnings
cargo test --workspace --all-features
cargo audit --deny warnings
cargo deny check
```

The CI workflow uses Rust 1.96.1 and runs the same gates. Schema compilation and fixture projections are part of the Rust test suite.

## Behavioral coverage

Phase 0 regression tests continue to prove equivalent native/SARIF treatment, byte-stable evaluation, path privacy, deterministic one-to-one matching, duplicate resistance, control false-positive visibility, and distinct missing, crash, timeout, unsupported, malformed, and unsafe-report accounting.

Phase 1 tests additionally prove:

- suite-v2 and live-run schema validation;
- required family pairing, language/framework coverage, authorship, licensing, and eligibility rationale;
- scanner-visible answer-leakage rejection and committed fingerprint verification;
- exact portable argument construction without a shell;
- binary and output paths containing spaces and Unicode;
- timeout, cancellation, process-group cleanup, crash, missing report, malformed report, oversized report, unsupported schema, observed memory limit, and execution failure accounting;
- atomic bundles containing one result for every suite case;
- absence of absolute paths and configuration secrets in manifests;
- exact source, sink, and evidence matching;
- separate vulnerable and control scoring;
- duplicate findings without inflated detection credit;
- equivalent recorded and live adapter entry points; and
- byte-identical repeated evaluation of one captured live bundle.

## Mock end-to-end check

The mock helper is a Rust executable used only to exercise public black-box behavior. Its output is not a Secure Engine baseline and must not be represented as analyzer quality.

```bash
cargo build --bin secure-bench --bin secure-bench-mock-tool

cargo run --bin secure-bench -- run fixtures/corpus-v1.toml \
  --tool secure-engine \
  --binary target/debug/secure-bench-mock-tool \
  --output /tmp/secure-bench-phase-1-mock \
  --run-id phase-1-mock

cargo run --bin secure-bench -- evaluate \
  fixtures/corpus-v1.toml /tmp/secure-bench-phase-1-mock \
  --output /tmp/secure-bench-phase-1-mock-result.json
```

Evaluate the same bundle twice and compare the result bytes. Runtime and host fields vary when a process is executed, but evaluating one retained bundle is deterministic.

## Explicit real baseline check

The final Phase 1 verification requires a user-provided binary path and an audited argument template compatible with its public `secure-json-v1` CLI. No source repository is inspected to locate or build it.

```bash
cargo run --release --bin secure-bench -- run fixtures/corpus-v1.toml \
  --tool secure-engine \
  --binary /explicit/user-provided/path/to/secure \
  --output artifacts/phase-1-secure-engine \
  --run-id phase-1-secure-engine

cargo run --release --bin secure-bench -- evaluate \
  fixtures/corpus-v1.toml artifacts/phase-1-secure-engine \
  --output artifacts/phase-1-secure-engine-result.json
```

Before a baseline is committed, verify the binary hash and reported version, inspect exact arguments and all statuses, compare the corpus fingerprint, validate raw report hashes, search every artifact for absolute paths and secrets, evaluate twice byte-for-byte, and record all quality, evidence, failure, timing, memory, and limitation data described in [Baseline reporting](phase-1-baseline.md).

## Fedora verification record

On 2026-07-16, the signed Phase 0 anchor `5e911044f8692d2611b3bc685086a39eac3cf843` was checked in an isolated detached worktree on Fedora Linux 44 x86_64 with Rust and Cargo 1.96.1. Formatting, strict Clippy, all 22 Phase 0 tests, RustSec audit, and dependency policy passed.

On the Phase 1 branch, formatting, strict Clippy, all 46 workspace tests, RustSec audit, and dependency policy were rerun after the final baseline was captured. Corpus validation reported 14 cases, split into seven vulnerable cases and seven controls, with aggregate fingerprint `9a32028a28d7c0396a630db8a2698a8977e173328578b1108f14603372e77761`. The committed Rust mock helper completed an end-to-end run; evaluating its retained bundle twice produced byte-identical results. Mock output is contract evidence only and is not the Secure Engine baseline.

The real Phase 6 baseline used locally verified binary SHA-256 `3787db2091b9e5d5e05495d8642e7fe0005cd035ee3d9d84a402f5c08dae0504` under an outer Linux network namespace. AI validation was disabled, no configuration or credentials were supplied, and only `scan {fixture} --format secure-json-v1 --output {report}` was invoked. All 14 reports were complete, used `secure-json-v1`, and declared zero scanner errors. The evaluated result was byte-identical across two evaluations and retained zero failures, 11 normalized findings, zero exact expectation matches, three flagged controls, four clean controls, and zero duplicates. The retained JSON privacy scan found no absolute paths, secrets, prior-binary identifiers, provider data, or credentials.
