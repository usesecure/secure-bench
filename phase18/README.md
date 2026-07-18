# Secure Bench Phase 18

Phase 18 adds a fail-closed Semgrep Community Edition 1.170.0 JSON adapter. It imports the untouched Phase 17 scanner-neutral protocol crate for manifest validation, raw-artifact capture, availability states, stable IDs, duplicate relationships, path normalization, and process adjudication.

The adapter accepts only `engine_requested: OSS` reports whose findings each declare `engine_kind: OSS`. It preserves raw bytes separately, admits only the pinned local Phase 17 conformance rule, validates scanned and finding paths and spans, and explicitly leaves unsupported Evidence Contract v2 fields unavailable. The CE fingerprint placeholder `requires login` is unavailable, not evidence.

The only live scanner execution used the disclosed Phase 18 fixture and exact Phase 17 rules bytes inside a separate network namespace with metrics and version checks disabled and no app token. Recorded JSON tests are scanner-free and offline. SARIF is intentionally omitted because the disclosed Semgrep JSON already provides the only admitted fields and SARIF adds no independently trustworthy evidence.

Native and capability-normalized lanes are declared separately but were not executed. No frozen/private holdout, Phase 13/14 material, OpenGrep, Secure Engine, Joern, comparison case, score, ranking, or superiority claim is part of Phase 18.

Run the offline Phase 18 verifier with:

```sh
cargo run --offline --manifest-path phase18/Cargo.toml -p secure-bench-semgrep-adapter -- verify .
```
