# Secure Engine Phase 6 Measurement Record

This directory is the Phase 1 reproducibility bundle for one deterministic black-box run of the user-supplied Secure Engine Phase 6 artifact. It is an intentionally neutral foundation measurement, not a production benchmark, scanner comparison, public ranking, or claim that Secure Engine or any other tool is superior.

## Provenance

- Run identifier: `phase-1-secure-engine-phase6`
- Containing Git commit: the single signed Phase 1 commit that contains this record
- Suite: `phase-1-javascript-typescript`
- Suite schema: `secure-bench-suite-v2`
- Suite fingerprint: `57d91da3dff7393b1ee8844072d3999161371403027a6d9c78df56907d61e97b`
- Corpus fingerprint: `9a32028a28d7c0396a630db8a2698a8977e173328578b1108f14603372e77761`
- Binary SHA-256, locally verified before execution: `3787db2091b9e5d5e05495d8642e7fe0005cd035ee3d9d84a402f5c08dae0504`
- Source RPM SHA-256, supplied by the user and recorded without a local source-RPM path: `a55928a226a1fe9b66a7d77e5e02280d5de203b97b14c79f3e3e79cce90a1bc8`
- Tool-reported version: `secure 0.1.0`
- Scanner command template: `scan {fixture} --format secure-json-v1 --output {report}`
- Rendered case command: `scan . --format secure-json-v1 --output ../.secure-bench-report.json`
- Tool report schema: `secure-json-v1`
- Live-run schema: `secure-bench-live-run-v1`
- Result schema: `secure-bench-result-v2`
- Empty configuration SHA-256: `e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855`
- Run manifest SHA-256: `21d707e281109630aa2cc2172d8664dad3d55439811578aa65943cb00e2f6c41`
- Deterministic result SHA-256: `b16c374c21e5738967c82eb836992dc41a8ea0bd10627f34b4dda304b58f7099`

AI validation was disabled for the entire measurement. The benchmark invoked only the deterministic `scan` command, supplied no configuration file, provider, credentials, or AI subcommand, and found no provider or credential data in the retained JSON artifacts. The run occurred inside a fresh Linux network namespace created with `bwrap --unshare-net`; the namespace exposed no host network interface. Secure Bench also cleared the scanner environment before each invocation.

## Measurement

- Cases: 14 total; seven vulnerable cases and seven paired safe controls
- Completed scanner executions: 14
- Normalized findings: 11
- Exact matched expectations: 0 of 7 eligible and attempted
- Missed expectations: 7
- Safe controls with one or more findings: 3 of 7 (`phase1-002`, `phase1-008`, and `phase1-010`)
- Clean safe controls: 4 of 7
- Duplicate findings: 0 of 11
- Unmatched findings: 11
- Crashes, timeouts, missing reports, parse failures, unsupported schemas, invalid outputs, execution failures, and cancellations: 0
- Total measured case duration: 70 ms over 14 samples
- Maximum observed direct-process memory: 405,504 bytes over 14 samples
- Total retained raw-report size: 1,156,570 bytes over 14 reports

Five vulnerable cases (`phase1-001`, `phase1-003`, `phase1-007`, `phase1-009`, and `phase1-011`) produced candidate observations. The deterministic matcher did not award credit because the public scanner category and invariant vocabulary did not exactly equal the neutral predeclared expectation vocabulary. Four of those cases matched source, sink, and evidence constraints; `phase1-009` matched sink and evidence constraints but not source. `phase1-005` and `phase1-013` produced no candidate finding. No post-execution aliases, rule-ID exceptions, or tool-specific scoring paths were added.

Evidence-path, source, sink, severity, and confidence accuracy have empty denominators because no expectation received an exact full match. This is distinct from a zero accuracy measurement.

## Artifacts and limits

`run.json` records the exact black-box provenance and all process outcomes. `reports/` contains the 14 unmodified accepted public reports. `result.json` contains normalized findings, raw matching decisions, separate vulnerable/control metrics, failures, and performance observations. Re-evaluating the same bundle produced byte-identical result bytes.

The outer network namespace applies to this recorded baseline; the Phase 1 Rust runner does not independently create a kernel network namespace. Memory is sampled from the direct process and can miss very short peaks or descendant-only allocation. Timing and memory are descriptive host observations, not comparative performance claims.
