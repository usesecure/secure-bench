# Secure Bench

Reproducible, evidence-aware benchmarks for static security analyzers.

Secure Bench is an independent, local-first Rust benchmark harness. Phase 0 established versioned contracts, scoring-blind adapters, deterministic matching, separate metrics, provenance, and explicit failure accounting using committed mock reports. Phase 1 adds an original JavaScript and TypeScript corpus and a direct black-box runner for an explicitly supplied Secure Engine binary. Phase 1.5 freezes a public neutral taxonomy for prospective reports without changing the historical Phase 1 result. Phase 2 applies that contract prospectively to two isolated, retained Secure Engine 0.1.1 runs while preserving every historical artifact. Phase 3 freezes a separate 56-case holdout examination. Phase 4 provides its one-shot, network-isolated Secure Engine 0.1.2 evaluation. Phase 5 independently freezes a new 112-case orthogonal holdout and tool-neutral evidence contract v2 without executing a scanner. Phase 6 retires the executed Phase 3 corpus and publishes an additive diagnostic package without changing the official Phase 4 result. Phase 7 records the one-shot, per-process network-isolated Secure Engine 0.1.3 evaluation of the frozen Phase 5 holdout, including every nonzero exit and retained report without reruns or result repair. Phase 8 corrects the exit-code adjudication protocol retrospectively from those immutable reports, preserves the original result, and introduces a prospective tool-neutral process-status policy without another scanner execution. Phase 9 freezes a new 224-case counterbalanced orthogonal holdout v3 for a future examination without executing a scanner.

This remains an intentionally neutral foundation. It is not a production benchmark, scanner comparison, public leaderboard, or basis for claiming that Secure Engine—or any other analyzer—is superior. A Phase 1 baseline measures one explicitly identified binary on a small synthetic corpus and must be reported with its raw artifacts, denominators, environment, and limitations.

The committed Phase 1 Secure Engine Phase 6 bundle is one deterministic black-box measurement with raw public reports and matching decisions. Its exact-match result is preserved without post-execution vocabulary aliases or tool-specific scoring exceptions. The separate Phase 2 bundle records the prospective evaluation, including raw repeat-run stability and isolation provenance. See [Phase 1 baseline reporting](docs/phase-1-baseline.md) and [Phase 2 prospective evaluation](docs/phase-2-evaluation.md).

The retired Phase 3 cases are now disclosed for development and regression work and are no longer an unseen holdout. See [the Phase 6 postmortem](docs/phase-6-postmortem.md). Post-disclosure results from that corpus are not unbiased benchmark measurements. The separate Phase 7 result and its limitations are documented in [the Phase 7 one-shot evaluation](docs/phase-7-evaluation.md). The additive offline correction is documented in [the Phase 8 exit-code adjudication](docs/phase-8-exit-code-adjudication.md).

Phase 9 is a distinct, not-yet-executed examination. Its future scanner projection contains one isolated fixture only and excludes the manifest, expected contracts, taxonomy, commitments, ledger, and paired sibling. See [the Phase 9 holdout methodology](docs/phase-9-holdout-v3.md).

Secure Bench never downloads, installs, builds, updates, or discovers scanners. Secure Engine receives no internal API access, private fixtures, expected answers, matcher data, or product-specific scoring treatment. No other scanner is installed or executed in the Phase 1 or Phase 2 measurements.

## Workspace

```text
secure-bench/
|- apps/secure-bench-cli/       Corpus, runner, evaluation, and summary commands
|- crates/secure-bench-core/    Contracts, adapters, matching, scoring, and runner
|- docs/                        Architecture, methodology, provenance, and verification
|- fixtures/corpus/             Original scanner-visible JavaScript/TypeScript projects
|- fixtures/reports/            Committed Phase 0 mock reports
|- schemas/                     Versioned JSON Schemas
|- taxonomy/                    Frozen prospective neutral taxonomy data
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

## Frozen neutral taxonomy

Taxonomy `1.0.0` defines seven stable category/invariant pairs derived from public security invariants and official MITRE CWE records. It was designed without consulting scanner output and applies only prospectively. Missing, incomplete, unknown, version-mismatched, or conflicting report metadata remains explicitly unmapped; there are no rule aliases, prose fallbacks, or scanner-specific exceptions.

```bash
cargo run --bin secure-bench -- taxonomy validate taxonomy/secure-bench-taxonomy-v1.json
cargo run --bin secure-bench -- taxonomy inspect taxonomy/secure-bench-taxonomy-v1.json
```

See [Frozen neutral taxonomy v1](docs/neutral-taxonomy-v1.md). The existing Phase 0 and Phase 1 evaluators remain unchanged in behavior, and the committed Phase 1 baseline is neither recalculated nor retrospectively remapped.

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

## Phase 2 prospective evaluation

Phase 2 adds strict taxonomy-profile, network-attestation, and prospective-result contracts. The evaluation command consumes retained run bundles only; it does not start a scanner:

```bash
cargo run --release --bin secure-bench -- phase2 evaluate \
  --suite fixtures/corpus-v1.toml \
  --taxonomy taxonomy/secure-bench-taxonomy-v1.json \
  --profile taxonomy/phase-1-corpus-taxonomy-profile-v1.json \
  --network-attestation artifacts/network-isolation.json \
  --phase1-result baselines/phase-1-secure-engine-phase6/result.json \
  --primary-run artifacts/primary \
  --repeat-run artifacts/repeat \
  --binary-sha256 <verified-sha256> \
  --source-rpm-sha256 <recorded-sha256> \
  --output artifacts/phase-2-result.json
```

## Verification

Validate Phase 5 commitments and synthetic evidence-contract tests without executing a scanner:

```bash
cargo run --bin secure-bench -- phase5 validate
cargo run --bin secure-bench -- phase5 contract-test
```

Validate or summarize the independently frozen Phase 9 holdout without executing a scanner:

```bash
cargo run --locked --manifest-path phase9/Cargo.toml -- validate .
cargo run --locked --manifest-path phase9/Cargo.toml -- summary .
```

Validate or inspect the Phase 3 commitments without exposing per-case answers in terminal output:

```bash
cargo run --bin secure-bench -- holdout validate \
  --manifest holdout/phase-3/manifest.json \
  --taxonomy taxonomy/secure-bench-taxonomy-v1.json \
  --ledger holdout/phase-3/execution-ledger.jsonl
```

```bash
cargo fmt --all --check
cargo clippy --workspace --all-targets --all-features -- -D warnings
cargo test --workspace --all-features
cargo audit --deny warnings
cargo deny check
```

See [Architecture](docs/architecture.md), [Methodology](docs/methodology.md), [Contracts](docs/contracts.md), [Frozen taxonomy](docs/neutral-taxonomy-v1.md), [Corpus provenance](docs/phase-1-corpus.md), [Runner boundaries](docs/phase-1-runner.md), [Phase 2 evaluation](docs/phase-2-evaluation.md), [Phase 3 holdout](docs/phase-3-holdout.md), [Phase 4 evaluation](docs/phase-4-evaluation.md), [Phase 5 orthogonal holdout](docs/phase-5-orthogonal-holdout.md), [Phase 6 postmortem](docs/phase-6-postmortem.md), [Phase 7 evaluation](docs/phase-7-evaluation.md), [Phase 8 adjudication](docs/phase-8-exit-code-adjudication.md), [Phase 9 holdout](docs/phase-9-holdout-v3.md), and [Verification](docs/verification.md).

## License

Secure Bench is licensed under the Apache License 2.0. The original synthetic fixtures use the same license and carry explicit authorship, origin, revision, and modification records in their suite manifests.
