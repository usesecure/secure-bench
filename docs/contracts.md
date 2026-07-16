# Secure Bench Phase 0–1 Contracts

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
