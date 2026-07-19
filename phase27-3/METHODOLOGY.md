# Phase 27.3 dual-adapter closure certification

Phase 27.3 is scanner-free infrastructure certification. It does not open or inspect the Phase 27 holdout and does not execute Phase 28.

OpenGrep is built in the exact Phase 17 Cargo closure (`adapter 0.3.0`, `protocol 0.3.0`). Semgrep is built independently in the exact Phase 18 Cargo closure (`adapter 0.4.0`) with the unchanged Phase 17 protocol (`0.3.0`). The closures never share Rust types in one process. Their interoperability boundary is the public `secure-bench-adapted-report-v1` JSON projection.

Each runner is a nested, independent Cargo workspace used only in a temporary copy of its historical closure. It accepts one fail-closed JSON request on standard input, calls the corresponding historical `adapt_report` API exactly once, and writes only `public_projection()` to standard output. Adapter errors are preserved verbatim in a structured standard-error document. The runner contains no scanner invocation, classification, scoring, taxonomy, CWE, evidence, guard, source/sink, confidence, benchmark rule, retry, or corpus logic.

Historical synthetic conformance vectors cover clean reports, one finding, multiple findings, malformed JSON, partial output, unsafe paths, and deterministic repetition. Tests compare the complete canonical direct-API result or exact adapter error with the separate runner process. Phase 28 must treat any nonzero runner exit as part of its current attempt and must never repeat a scanner because of a runner failure.
