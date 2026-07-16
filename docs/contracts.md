# Phase 0 Contracts

## Version identifiers

| Contract | Identifier | Committed schema |
|---|---|---|
| Suite | `secure-bench-suite-v1` | `schemas/suite-v1.schema.json` |
| Recorded run | `secure-bench-run-v1` | `schemas/run-v1.schema.json` |
| Result | `secure-bench-result-v1` | `schemas/result-v1.schema.json` |
| Native mock report | `secure-json-v1` | Strict typed adapter contract |
| SARIF mock report | `2.1.0` | Evidence-bearing SARIF subset |

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
