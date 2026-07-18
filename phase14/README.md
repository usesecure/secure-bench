# Secure Bench Phase 14

Phase 14 is the preregistered, one-shot evaluation of the public Secure Engine 0.1.4 RPM against the frozen Phase 13 prospective holdout v4. It is an evaluation of a synthetic contract corpus, not a production benchmark, public ranking, superiority claim, production-readiness claim, or claim of complete vulnerability coverage.

The runner accepts only the exact external black-box artifacts declared in the pre-execution contract. It downloads no artifact itself, does not install the RPM, and never probes, imports, inspects, modifies, debugs, disassembles, or instruments Secure Engine. The command is fixed to `scan {fixture} --format secure-json-v1 --output {report}`. AI validation is disabled, the process environment is cleared, and every case runs in a fresh Bubblewrap network namespace after an outbound-connectivity attestation.

The evaluation uses Evidence Contract v2 without a legacy override. A complete adapter-valid report is authoritative under process-status policy 1.0.0, including a findings-policy exit code. Crashes, timeouts, malformed output, missing output, internally errored output, and unsupported schemas remain distinct failure classes and receive no detection credit.

## Evidence lifecycle

`prepare` verifies all frozen Phase 13 inputs and historical Phase 0–12 integrity, binds the exact RPM and extracted binary hashes, fingerprints the Phase 14 evaluator and schemas, writes the canonical pre-execution contract, and copies the immutable Phase 13 genesis ledger byte-for-byte. It cannot launch the scanner.

`execute` first appends an irreversible reservation. It then records exactly one attempt for each of the 112 frozen cases, appending every case result to the chained ledger. It does not retry a failed or unfavorable case. The terminal result retains reports, stdout, stderr, isolation attestations, execution metadata, durations, peak RSS samples, and all failure accounting.

`verify` is scanner-free. It validates every retained artifact and ledger link, reconstructs the Evidence Contract v2 result twice from the retained reports, and requires byte-identical deterministic output. A second `execute` invocation is rejected.

## Interpretation boundary

Exact detections, partial evidence, misses, safe-control findings, duplicates, and operational failures are reported separately. Precision, recall, and F1 use exact detections only. Agreement metrics include taxonomy, category, invariant, CWE, source and sink identities and spans, connected value identity, ordered evidence path, barrier, sanitizer, guard, and dominance semantics. Results are stratified by taxonomy family, framework, language group, source format, topology, and every pairwise combination of those five dimensions.

Phase 14 must not be directly ranked against evaluations that used a different corpus. Local runtime and RSS measurements are environment-specific. The holdout is synthetic and does not establish real-world prevalence, exploitability, or operational effectiveness.
