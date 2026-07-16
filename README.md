# Secure Bench

Reproducible, evidence-aware benchmarks for static security analyzers.

Secure Bench Phase 0 is an independent, local-first Rust foundation for benchmark contracts, report normalization, deterministic matching, scoring, provenance, and failure accounting. It evaluates only committed, versioned mock reports. It does not install or execute Secure Engine, CodeQL, Joern, Opengrep, Semgrep, or any other scanner.

Phase 0 is intentionally tool-neutral. It is not a production benchmark, scanner comparison, or leaderboard, and its synthetic mock data must not be used for public rankings or claims that Secure Engine—or any other tool—is superior. Tool names in fixtures identify format examples, not measured products.

## Workspace

```text
secure-bench/
|- apps/secure-bench-cli/       Mock-only evaluation and report commands
|- crates/secure-bench-core/    Contracts, adapters, matching, scoring, schemas
|- docs/                        Architecture, methodology, and verification
|- fixtures/                    Minimal synthetic cases and committed mock reports
|- schemas/                     Versioned JSON Schemas
|- GOAL.md                      Phase 0 requirements
`- PLAN.md                      Product plan and boundaries
```

All executable components are Rust. Fixture source files use the language named by the case and are never loaded or executed by the benchmark process.

## Phase 0 commands

Evaluate a committed recorded-run manifest and write deterministic JSON:

```bash
cargo run --bin secure-bench -- evaluate \
  --suite fixtures/suite.toml \
  --run fixtures/reports/runs/native-success.json \
  --output artifacts/native-result.json
```

Validate the same contracts without retaining a result:

```bash
cargo run --bin secure-bench -- validate \
  --suite fixtures/suite.toml \
  --run fixtures/reports/runs/native-success.json
```

Render the concise terminal projection of an existing result:

```bash
cargo run --bin secure-bench -- summary \
  --result artifacts/native-result.json
```

The command stored in a recorded-run manifest is provenance only. Phase 0 never invokes it. JSON results contain normalized findings, every match decision, separate quality metrics, explicit denominators, operational failures, resource measurements, and SHA-256 provenance links.

## Verification

```bash
cargo fmt --all --check
cargo clippy --workspace --all-targets --all-features -- -D warnings
cargo test --workspace --all-features
cargo audit --deny warnings
cargo deny check
```

See [Architecture](docs/architecture.md), [Methodology](docs/methodology.md), [Contracts](docs/contracts.md), and [Phase 0 verification](docs/verification.md) for the design invariants and limitations.

## License

Secure Bench is licensed under the Apache License 2.0. The original synthetic Phase 0 fixtures use the same license and carry explicit provenance in the suite manifest.
