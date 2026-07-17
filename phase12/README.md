# Secure Bench 0.2.0 prospective foundation

Phase 12 repairs the benchmark methodology prospectively. It introduces a strict Evidence Contract
v2 adapter, a disclosed public regression corpus, and a versioned authoring contract for a later
unseen holdout. It does not execute a scanner, inspect Secure Engine, rescore Phase 10, or create
Phase 13 fixtures, answers, a manifest, or a ledger.

The public corpus is development regression material. Its cases and classifications are disclosed,
so validation results are contract-conformance results rather than scanner detections. Phase 12 is
not a production benchmark, scanner comparison, public ranking, superiority claim, or
complete-coverage claim.

## Commands

Generate the committed public material deterministically:

```bash
cargo run --locked --manifest-path phase12/Cargo.toml -- generate .
```

Verify historical inputs, schemas, taxonomy, adapter vectors, fixture semantics, privacy,
provenance, reconstruction, process audit, and future-holdout absence:

```bash
cargo run --locked --manifest-path phase12/Cargo.toml -- verify .
```

Render an answer-free aggregate summary:

```bash
cargo run --locked --manifest-path phase12/Cargo.toml -- summary .
```

The library contains no process-launch or network API. Generation and verification read historical
files and write or compare Phase 12 public files only; fixture source is never loaded as executable
code.
