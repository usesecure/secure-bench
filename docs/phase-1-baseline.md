# Phase 1 Baseline Reporting

## Publication rule

A Phase 1 baseline is produced only by an explicit invocation using a user-provided Secure Engine binary. Unit tests and continuous integration use the committed Rust mock helper and never execute Secure Engine or another scanner.

The reproducibility bundle must contain the live `run.json`, every retained raw report, the deterministic evaluated result, and a concise measurement record containing the commit, suite and corpus fingerprints, binary and configuration fingerprints, tool-reported version, command contract, host data, case counts, quality counts, evidence metrics, failures, duration, peak memory, and known limitations.

## Interpretation

The baseline is a measurement of one binary and configuration on 14 original synthetic cases. It is not a comparison with another tool, a public ranking, a production-readiness assessment, or evidence that Secure Engine is superior. Empty denominators remain empty, failures remain outside clean results, and no composite score is produced.

The result must report at least:

- detected and missed expectations over seven eligible vulnerable cases;
- falsely flagged and clean outcomes over seven eligible controls;
- source, sink, and evidence-path accuracy over detected expectations;
- duplicates over normalized findings;
- severity and confidence observations without folding them into detection credit;
- crashes, timeouts, invalid outputs, unsupported schemas, execution failures, and cancellations;
- total measured case duration and sample count; and
- maximum observed direct-process memory and sample count.

No baseline artifact is represented by mock output. The mock helper proves runner and evaluator behavior only.

## Recorded Phase 6 baseline

The committed Phase 1 bundle is [the Secure Engine Phase 6 measurement](../baselines/phase-1-secure-engine-phase6/README.md). The locally verified binary SHA-256 is `3787db2091b9e5d5e05495d8642e7fe0005cd035ee3d9d84a402f5c08dae0504`; the user-supplied source RPM SHA-256 is `a55928a226a1fe9b66a7d77e5e02280d5de203b97b14c79f3e3e79cce90a1bc8`. The exact scanner contract was `scan {fixture} --format secure-json-v1 --output {report}` with an empty configuration fingerprint.

AI validation remained disabled. The run used only deterministic `scan`, supplied no AI provider, credentials, configuration, or AI subcommand, and executed inside a fresh Linux network namespace with no host network interface. All 14 cases completed with valid `secure-json-v1` reports and no scanner errors or execution failures.

The exact-match result is 0 of 7 eligible vulnerable expectations, three of seven safe controls flagged, four controls clean, 11 normalized unmatched findings, and zero duplicates. Five vulnerable cases emitted observations, but their public category/invariant vocabulary did not exactly equal the neutral predeclared matcher vocabulary. The matcher therefore withheld credit instead of introducing post-execution aliases or scanner-specific exceptions. This limitation is part of the measurement, not a basis for changing the result after execution.
