# Phase 11 retired diagnostic package

This directory contains additive, public diagnostics derived from the retired Phase 9 corpus and
immutable Phase 10 retained reports. It does not replace or rescore Phase 10.

- `retired-diagnostic-v1.json`: all 224 case records, all 48 finding mappings, agreement matrices,
  ten stratification maps, immutable provenance, and limitations.
- `regression-manifest-v1.json`: public generalized regression dispositions for every retired case.
- `benchmark-defect-ledger-v1.jsonl`: nine hash-chained class entries: seven confirmed defects plus
  explicit zero-count contract-ambiguity and unresolved-attribution entries.
- `evidence-contract-v2-conformance-v1.json`: 19 public synthetic mutation/inverse vectors.
- `SHA256SUMS`: hashes of the four machine-readable artifacts.

The Phase 11 verifier starts no scanner process, consults no Secure Engine source, and requires no
network access.
