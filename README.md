# Secure Bench

Reproducible, evidence-aware benchmarks for static security analyzers.

Secure Bench is an independent, local-first Rust benchmark harness. Phase 0 established versioned contracts, scoring-blind adapters, deterministic matching, separate metrics, provenance, and explicit failure accounting using committed mock reports. Phase 1 adds an original JavaScript and TypeScript corpus and a direct black-box runner for an explicitly supplied Secure Engine binary.

This remains an intentionally neutral foundation. It is not a production benchmark, scanner comparison, public leaderboard, or basis for claiming that Secure Engine—or any other analyzer—is superior. A Phase 1 baseline measures one explicitly identified binary on a small synthetic corpus and must be reported with its raw artifacts, denominators, environment, and limitations.

The committed Phase 1 Secure Engine Phase 6 bundle is one deterministic black-box measurement with raw public reports and matching decisions. Its exact-match result is preserved without post-execution vocabulary aliases or tool-specific scoring exceptions. See [Phase 1 baseline reporting](docs/phase-1-baseline.md).

Secure Bench never downloads, installs, builds, updates, or discovers scanners. Secure Engine receives no internal API access, private fixtures, expected answers, matcher data, or product-specific scoring treatment. No other scanner is installed or executed in Phase 1.

## Workspace

```text
secure-bench/
|- apps/secure-bench-cli/       Corpus, runner, evaluation, and summary commands
|- crates/secure-bench-core/    Contracts, adapters, matching, scoring, and runner
|- docs/                        Architecture, methodology, provenance, and verification
|- fixtures/corpus/             Original scanner-visible JavaScript/TypeScript projects
|- fixtures/reports/            Committed Phase 0 mock reports
|- schemas/                     Versioned JSON Schemas
|- GOAL.md                      Preserved Phase 0 goal
`- PLAN.md                      Product plan and boundaries
```

All benchmark executables are Rust. Corpus source files use JavaScript, JSX, TypeScript, and TSX because those are the languages under evaluation; the harness copies but never loads or executes fixture code.

## Phase 1 commands

Validate corpus schemas, semantic pairing, answer-leakage controls, provenance, and fingerprints:

```bash
cargo run --bin secure-bench -- corpus validate fixtures/corpus-v1.toml
```

Run an explicitly supplied binary. The default public argument contract is `scan {fixture} --format secure-json-v1 --output {report}`; repeat `--argument` to provide an audited alternative template.

```bash
cargo run --bin secure-bench -- run fixtures/corpus-v1.toml \
  --tool secure-engine \
  --binary /explicit/path/to/secure \
  --output artifacts/phase-1-run \
  --run-id phase-1-baseline
```

An optional `--configuration` file is copied outside the scanned project, fingerprinted, and exposed only through an explicit `{configuration}` argument placeholder. Configuration text containing matcher-owned categories, invariants, or expectation identifiers is rejected.

Evaluate the retained raw reports and render a summary:

```bash
cargo run --bin secure-bench -- evaluate \
  fixtures/corpus-v1.toml artifacts/phase-1-run \
  --output artifacts/phase-1-result.json

cargo run --bin secure-bench -- summary artifacts/phase-1-result.json
```

Machine-readable JSON is written only to the requested file or standard output. Human diagnostics and summaries use standard error during evaluation when JSON is emitted.

## Preserved Phase 0 commands

The original option-based forms remain supported and continue to evaluate only committed recorded reports:

```bash
cargo run --bin secure-bench -- evaluate \
  --suite fixtures/suite.toml \
  --run fixtures/reports/runs/native-success.json \
  --output artifacts/native-result.json

cargo run --bin secure-bench -- validate \
  --suite fixtures/suite.toml \
  --run fixtures/reports/runs/native-success.json
```

## Verification

```bash
cargo fmt --all --check
cargo clippy --workspace --all-targets --all-features -- -D warnings
cargo test --workspace --all-features
cargo audit --deny warnings
cargo deny check
```

See [Architecture](docs/architecture.md), [Methodology](docs/methodology.md), [Contracts](docs/contracts.md), [Corpus provenance](docs/phase-1-corpus.md), [Runner boundaries](docs/phase-1-runner.md), and [Verification](docs/verification.md).

## License

Secure Bench is licensed under the Apache License 2.0. The original synthetic fixtures use the same license and carry explicit authorship, origin, revision, and modification records in their suite manifests.
