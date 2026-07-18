# Secure Bench Phase 19 frozen multi-scanner holdout

Phase 19 freezes a prospective scanner-neutral examination for Secure Engine 0.1.6, OpenGrep 1.22.0, and Semgrep CE 1.170.0. It contains 56 structural vulnerable/control pairs (112 opaque cases), authoritative Evidence Contract v2 expectations, complete balance tables, deterministic ordering, overlap measurements, immutable execution contracts, commitments, a contract Merkle root, provenance, checksums, and a no-execution genesis ledger.

No scanner, fixture, AI provider, credential flow, or network operation is part of authoring or validation. Native and capability-normalized lanes remain distinct and unsupported lanes remain explicitly unavailable. Phase 19 contains no scanner observations, result, score, ranking, or production-readiness claim.

Reconstruct and validate the complete holdout without executing a case:

```sh
cargo run --offline --manifest-path phase19/Cargo.toml -- validate-holdout .
```

Run the complete offline gate:

```sh
phase19/scripts/verify-phase19-binding.sh
```

The existing Secure Engine binding remains byte-identical to its separately verified partial freeze. Optional arguments to the script hash-check an external official RPM and extracted `/usr/bin/secure`; those artifacts remain outside the repository and are never executed or rebuilt.
