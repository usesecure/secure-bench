# Secure Bench Phase 0–1.5 Architecture

## Purpose and boundary

Phase 0 establishes a neutral contract before any scanner is installed or executed. Its only inputs are committed suite manifests, recorded-run manifests, and versioned mock reports. The recorded command is retained as provenance and is never invoked.

This architecture is intentionally independent from Secure Engine and every other analyzer. The core crate imports no scanner implementation, private API, rule registry, or product-specific matcher. Secure JSON is treated as one public input format beside SARIF; it receives no scoring privilege.

Phase 0 is not a production benchmark, scanner comparison, or basis for a public ranking. Synthetic mock outcomes prove the harness contracts, not analyzer quality.

## Data flow and trust boundaries

```text
committed suite.toml ------------------------------+
                                                     |
committed recorded-run.json -> selected adapter      | expectations enter here
                                  |                  v
committed mock report ----------> normalized findings -> deterministic matcher
                                                               |
                                                               v
                                         score card + raw decisions + provenance
                                                               |
                                             JSON and terminal projections
```

The adapter receives only report bytes and the report fingerprint. Its Rust trait does not accept a suite, case expectations, or scorer. Expected results are introduced only after normalization, at the matcher boundary. This makes accidental answer leakage and adapter-assigned credit structurally testable.

## Components

### Model

The core model covers suites, cases, expected findings, recorded tool runs, normalized findings, expectation decisions, finding dispositions, score cards, structured errors, resource measurements, and provenance. Each external contract carries an explicit schema version.

### Schema

Committed JSON Schemas define suite, recorded-run, and result projections. Human-authored suite TOML is deserialized to the typed Rust model and validated through its JSON projection. Semantic checks add invariants that JSON Schema alone does not express cleanly, including globally unique identifiers, vulnerable/safe-control consistency, and Phase 0 network denial.

### Adapters

`secure-json-v1` and SARIF 2.1.0 adapters parse untrusted mock reports into the same neutral finding model. Adapter selection depends only on the declared report format, never the tool name. Unsupported formats, unsupported schema versions, malformed JSON, oversized reports, zero-based locations, absolute paths, traversal, encoded paths, and Windows-style paths fail explicitly.

Native messages and source snippets are not copied into exported results. Native rule identifiers remain only for traceability and do not participate in matching.

### Matcher

The matcher canonicalizes category and invariant text, then requires all declared category, invariant, source, sink, and evidence-path constraints. It performs deterministic one-to-one assignment, selects the most constrained expectations first, orders ties by stable identifiers, records ambiguity, and prevents one alert from satisfying multiple expectations.

Semantically duplicate alerts retain separate raw provenance but only the canonical alert can receive credit. Additional identical alerts are marked as duplicates.

### Scorer

The scorer has no tool-identity input and emits no composite or leaderboard score. It reports vulnerable recall, attempted vulnerable recall, safe-control false-positive rate, safe-control clean coverage, evidence accuracy, source and sink localization, severity and confidence calibration, duplicate rate, operational failures, and resource measurements separately.

Rates are exact integer numerators and denominators with a deterministic integer basis-point projection. A zero denominator has no rate. This avoids floating-point drift and hidden populations.

### CLI and report projections

The CLI reads bounded regular files, rejects symlinks for input artifacts, confines report references to the `reports` fixture tree, and uses atomic result writes. `evaluate` produces deterministic JSON and a concise terminal summary. `summary` is a projection over the same typed result model.

## Determinism

Maps use stable key ordering, findings and decisions are sorted by content-derived identifiers, ratios use integer arithmetic, and JSON uses a stable pretty-printed projection. The same committed bytes produce byte-identical output. In future execution phases, measured timing and host values will legitimately vary; those fields will remain raw provenance and will not alter matching.

## Phase 1 live boundary

Phase 1 preserves the Phase 0 path unchanged and adds a separate live-run path:

```text
matcher-owned suite ------------------------------+
                                                    |
one scanner-visible case copy -> external binary   | expectations enter here
                                  |                 v
bounded secure-json-v1 report -> scoped adapter -> deterministic matcher
                                  |
                                  +-> raw report + live provenance bundle
```

The runner accepts only an explicit regular-file binary, invokes it without a shell, clears its environment, isolates it in a fresh copied project, monitors time and direct-process memory, drains streams with bounded retained metadata, cleans its process group, and publishes artifacts atomically. It records fingerprints rather than absolute binary, repository, or temporary paths.

The suite, labels, and expectations remain outside the temporary scan directory. The live adapter receives only report bytes, report fingerprint, neutral case scope, and a path prefix. It cannot inspect expectations or award credit. Every successful raw report follows the same normalized model and matcher used by recorded input.

Phase 1 does not claim the kernel-enforced network and read-only filesystem sandboxing planned for Phase 3. Its declared network-disabled policy, cleared environment, copied temporary project, direct invocation, time/output bounds, observed memory termination, and process cleanup are documented precisely in [Phase 1 runner boundaries](phase-1-runner.md).

## Phase 1.5 prospective taxonomy boundary

Phase 1.5 adds a frozen, typed taxonomy document and an independent prospective matcher API. Native JSON and SARIF adapters may preserve canonical version/category/invariant metadata, but cannot create it, translate scanner rule IDs, compare prose, or consult expectations. Resolution is explicit before source, sink, and evidence constraints are evaluated.

The Phase 0 and Phase 1 pipeline entry points do not invoke this API. This separation prevents a newly published taxonomy from changing the bytes or interpretation of the retained Phase 1 baseline. See [Frozen neutral taxonomy v1](neutral-taxonomy-v1.md).

## Phase 2 prospective evaluation boundary

Phase 2 freezes a suite-specific taxonomy profile before scanner execution and evaluates two retained live bundles through a separate typed path. The scanner-visible boundary remains unchanged: one copied fixture and the public report command. Profile data, expectations, historical decisions, and scoring code remain outside the scan workspace.

## Phase 3 holdout boundary

The Phase 3 manifest and ledger are matcher-side contracts. Only one neutral fixture directory would be scanner-visible during a future evaluation; labels, expectations, taxonomy coordinates, mutations, hashes, and scoring remain outside that directory. Secure Engine development tasks and any other scanner-development work must not inspect `holdout/phase-3/`. The current CLI can validate and inspect aggregate commitments but cannot execute or evaluate the holdout.

The evaluator validates every run and raw report before normalization, resolves only exact taxonomy coordinates, performs deterministic one-to-one matching, and emits per-criterion decisions. A second retained run supplies stability evidence. Volatile raw-report equality is recorded separately from content-derived finding identity, semantic finding sets, decisions, and metrics.

The complete scanner lifecycle is wrapped by a caller-created network namespace attested through a strict versioned contract. This is measurement-specific provenance, not an assertion that the generic Phase 1 runner independently creates a network namespace.
