# Secure Bench Phase 0–1 Contracts

## Phase 6 retired-corpus contracts

`secure-bench-retired-holdout-diagnostic-v1` is the deterministic public diagnostic package for the retired Phase 3 corpus. `secure-bench-retired-holdout-regression-v1` is its engine-consumable regression projection. Both are additive: they bind immutable Phase 3 and Phase 4 hashes and cannot modify the official Phase 4 result.

The committed schemas are `schemas/phase6-retired-diagnostic-v1.schema.json` and `schemas/phase6-regression-manifest-v1.schema.json`. The Rust validator reconstructs both artifacts from historical source contracts, validates every copied fixture, and rejects Phase 5 holdout references.

## Version identifiers

| Contract | Identifier | Committed schema |
|---|---|---|
| Suite | `secure-bench-suite-v1` | `schemas/suite-v1.schema.json` |
| Recorded run | `secure-bench-run-v1` | `schemas/run-v1.schema.json` |
| Result | `secure-bench-result-v1` | `schemas/result-v1.schema.json` |
| Native mock report | `secure-json-v1` | Strict typed adapter contract |
| SARIF mock report | `2.1.0` | Evidence-bearing SARIF subset |

Phase 1 adds these contracts without changing the Phase 0 schemas:

| Contract | Identifier | Committed schema |
|---|---|---|
| First-party corpus suite | `secure-bench-suite-v2` | `schemas/suite-v2.schema.json` |
| Live run bundle | `secure-bench-live-run-v1` | `schemas/live-run-v1.schema.json` |
| Live evaluated result | `secure-bench-result-v2` | `schemas/result-v2.schema.json` |

Phase 1.5 adds one prospective contract without changing any Phase 0 or Phase 1 artifact:

| Contract | Identifier | Committed schema |
|---|---|---|
| Frozen neutral taxonomy | `secure-bench-taxonomy-v1` / taxonomy `1.0.0` | `schemas/taxonomy-v1.schema.json` |

Phase 2 adds prospective evaluation contracts without changing historical artifacts:

| Contract | Identifier | Committed schema |
|---|---|---|
| Frozen corpus taxonomy profile | `secure-bench-taxonomy-profile-v1` | `schemas/taxonomy-profile-v1.schema.json` |
| Network-isolation attestation | `secure-bench-network-isolation-v1` | `schemas/network-isolation-v1.schema.json` |
| Prospective evaluation result | `secure-bench-phase2-result-v1` | `schemas/phase2-result-v1.schema.json` |

Phase 5 adds scanner-neutral prospective contracts without changing historical artifacts:

| Contract | Identifier | Committed schema |
|---|---|---|
| Evidence semantics | `secure-bench-evidence-contract-v2` | `schemas/evidence-contract-v2.schema.json` |
| Orthogonal holdout | `secure-bench-orthogonal-holdout-v2` | `schemas/phase5-holdout-v2.schema.json` |
| Commitment index | `secure-bench-phase5-commitments-v1` | `schemas/phase5-commitments-v1.schema.json` |
| Genesis/future ledger entry | `secure-bench-phase5-ledger-entry-v1` | `schemas/phase5-ledger-entry-v1.schema.json` |
| Synthetic conformance vectors | `secure-bench-phase5-contract-tests-v1` | `schemas/phase5-contract-tests-v1.schema.json` |

Phase 8 adds a prospective tool-neutral status policy and a separate retrospective adjudication
lifecycle without changing Phase 7 evidence:

| Contract | Identifier | Committed schema |
|---|---|---|
| Process-status policy | `secure-bench-process-status-policy-v1` / policy `1.0.0` | `schemas/process-status-policy-v1.schema.json` |
| Retrospective adjudication | `secure-bench-phase8-adjudication-v1` | `schemas/phase8-adjudication-v1.schema.json` |
| Separate adjudication ledger | `secure-bench-phase8-adjudication-ledger-v1` | `schemas/phase8-adjudication-ledger-v1.schema.json` |
| Adjudication artifact index | `secure-bench-phase8-artifacts-v1` | `schemas/phase8-artifacts-v1.schema.json` |

Unknown fields are rejected by the native contract and the typed benchmark contracts. The SARIF adapter tolerates unrelated standard SARIF fields while requiring the Phase 0 properties used for neutral normalization.

## Recorded runs

A recorded-run manifest describes previously captured mock output. Its `command` is an argument array retained for provenance; the Phase 0 CLI never starts that command. Each declared case execution has exactly one status:

- `success`: report normalization and matching may proceed;
- `crash`: process failure, never a clean scan;
- `timeout`: resource-limit failure, never a clean scan;
- `unsupported`: predeclared lack of eligibility, never detection credit;
- `missing`: no artifact for an eligible case; or
- `parse_failure`: adapter validation failed.

Omitted suite cases are synthesized as `missing`. If the selected adapter cannot parse the report, every otherwise successful case becomes `parse_failure`. Unsupported formats and versions become `unsupported`. Existing crash, timeout, missing, and unsupported outcomes remain distinct.

Performance values are accepted only for successful cases. This prevents failed attempts from presenting misleading runtime measurements.

## Normalized findings

Normalized findings contain case identity, native rule identity for traceability, neutral category and invariant, severity, confidence, source, sink, evidence hops, adapter identity, raw result index, and report fingerprint. They do not contain scanner messages, source text, absolute paths, usernames, or repository roots.

Prospective findings may also contain a strict `taxonomy` object with `taxonomy_version`, `category_id`, and `invariant_id`. The native JSON and SARIF adapters preserve the same object without inferring aliases. Absence remains absence, partial coordinates remain incomplete, and unknown or conflicting identifiers remain unmapped. Historical reports omit this optional object and serialize exactly as before.

The content-derived finding identifier excludes native rule identity and tool identity. Equivalent native and SARIF evidence therefore enters the matcher under the same neutral identity. A raw-index suffix keeps identical duplicate alerts separately inspectable.

## Result linkage

The result contains:

- all normalized findings;
- one decision per expected finding;
- one disposition per normalized finding;
- separate quality, failure, and performance metrics;
- structured adapter errors; and
- fingerprints and public provenance.

No public Phase 0 field represents a leaderboard score or scanner rank.

## Phase 1 live runs

A live-run bundle accounts for every suite case exactly once. It links the suite and corpus fingerprints to an explicit binary hash, public version probe, schema, argument template, configuration hash, sanitized host data, per-case arguments, process exit codes, timing, observed memory, stream hashes, report sizes and hashes, and explicit statuses. Paths remain bundle-relative and raw process streams are not retained. A complete, internally error-free, adapter-valid public report is authoritative when the scanner uses a nonzero finding exit code; incomplete or errored reports remain failures.

The evaluator rejects missing or unrelated report files, unsafe or duplicate paths, altered case or corpus fingerprints, mismatched argument arrays, inconsistent aggregate status, invalid timestamp ordering, report size or hash drift, outcome/report disagreement, and success records carrying failure codes. A failed status cannot be interpreted as an empty report.

The v2 result adds invalid-output, execution-failure, and cancellation counts while retaining every Phase 0 metric and its explicit denominator. It still has no composite score, rank, or tool-comparison field.

## Phase 2 prospective results

The frozen profile binds all seven vulnerable Phase 1 expectations to exact taxonomy 1.0.0 pairs before execution. The evaluator rejects incomplete coverage, duplicates, identifier conflicts, or fingerprint drift. The isolation attestation must cover the version probe and every scanner process, expose only loopback, and record blocked outbound connectivity.

The Phase 2 result preserves normalized findings, per-case criteria and outcomes, exact and diagnostic agreement metrics, safe-control outcomes, primary/repeat operational measurements, semantic stability, historical comparison, and complete hashed provenance. Raw-report byte equality is independent from semantic equality. Partial matches never count as exact detections, failures never appear clean, and the result contains no rank, leaderboard score, or superiority field.

## Phase 3 holdout contracts

`holdout-v1.schema.json` fixes corpus identity, taxonomy linkage, pair strata, precise expectations, safe-control properties, reversible mutations, provenance, scoring semantics, commitments, and the future one-shot policy. The manifest is canonical JSON and binds 56 fixture fingerprints into an aggregate hash and 56 complete case contracts into a domain-separated Merkle root.

`holdout-ledger-entry-v1.schema.json` defines a canonical JSON Lines hash chain. The committed ledger contains only `holdout_sealed`. A future execution must append exactly one `execution_started` reservation before processing and exactly one immutable completion or explicit failure. A second reservation, replacement result, broken chain, or post-terminal append fails validation.
