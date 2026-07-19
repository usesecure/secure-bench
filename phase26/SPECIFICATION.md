# Phase 26 independent certification specification

Phase 26 is an additive, read-only successor certification of commit
`a25175dc352c006deea579b5e85643d513be6984`. It does not repair or replace any
Phase 25 file, attempt, report, or verifier. It never executes a scanner or a
holdout case.

## Trust and validation order

1. Verify the Phase 25 commit, direct parent, ED25519 signature, single DCO,
   committed tree, and the frozen Phase 19–25 subtree identities.
2. Verify the exhaustive 684-entry `phase25/output/SHA256SUMS` inventory.
3. Verify the frozen plan, contract, marker, genesis, adapter, rules,
   methodology, manifest commitments, and Phase 22 results by SHA-256.
4. Parse and validate the already-inventoried evidence. Parsing is never used
   as a substitute for exact-byte integrity.
5. Derive the ledger head, recalculate scoring, and only then compare with the
   published Phase 25 results and provenance.

## Serialization domain 1: Observation payload

`payload_sha256` is SHA-256 over the exact bytes of the corresponding
`observation.json`, including its final newline. The file's SHA-256 is checked
against the frozen inventory before parsing. JSON is then parsed separately to
validate its closed field set, identities, command, environment, evidence
bindings, and operational semantics.

The verifier never parses and reserializes an observation to obtain the ledger
payload hash. As a separate conformance check, it reconstructs the known Rust
`Observation` struct field order and proves that the resulting compact JSON plus
newline equals the inventoried file bytes. This demonstrates the producer
relationship without making reserialization the payload acceptance mechanism.

## Serialization domain 2: ledger projection

Each entry hash is derived from a new object containing only:

1. `schema_version`
2. `sequence`
3. `event`
4. `payload_sha256`
5. `previous_entry_hash`

The producer built this object as `serde_json::Value`. With the frozen
`serde_json` configuration, map keys serialize deterministically in lexical
order: `event`, `payload_sha256`, `previous_entry_hash`, `schema_version`, and
`sequence`. The representation is compact UTF-8 JSON with one final newline.
`entry_hash` is SHA-256 over precisely those projection bytes.

The complete ledger entry must contain exactly the five projection fields plus
`entry_hash`. Phase 26 validates all six fields and walks exactly 112 entries
from the genesis zero hash. The terminal head is derived; no ledger head or
per-attempt payload hash is hardcoded as an acceptance mechanism.

## Evidence and scoring rules

The verifier requires 112 unique plan cases, attempt IDs, observations, raw
reports, and ledger entries; zero retries; 112 completed states; exit codes 0/1;
zero signals/timeouts/malformed/unavailable states; exact commands,
environments, resource limits, mounts, bindings, and hashes; `PWD=/tmp/fixture`
112/112; and no OpenGrep, Secure Engine, or native attempt.

Raw JSON validation checks Semgrep CE 1.170.0, OSS engine provenance, the frozen
rule allowlist, empty errors/skipped rules, safe scanned/finding paths, and span
bounds against manifest file sizes. Scoring is independently recalculated from
raw finding counts and frozen manifest expectations. Phase 25 `results.json` is
consulted only after recalculation. The Phase 22 comparison is restricted to
the capability-normalized OpenGrep lane.
