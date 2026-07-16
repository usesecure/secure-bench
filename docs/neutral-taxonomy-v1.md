# Frozen Neutral Security Taxonomy v1

## Status and boundary

Secure Bench taxonomy `1.0.0` was published on 2026-07-16 as a prospective, scanner-independent matching contract. The versioned data is `taxonomy/secure-bench-taxonomy-v1.json`; its schema is `schemas/taxonomy-v1.schema.json`. The internal content hash is `22852bd7401020b315af11dfa2b60c0b46f78eb19f95079e6400d7b3bea3272c`.

This taxonomy is an intentionally neutral foundation. It is not a production benchmark, scanner comparison, public leaderboard, or basis for claiming that Secure Engine or any other analyzer is superior. It does not recalculate, reinterpret, or replace the committed Phase 1 baseline. That baseline remains an immutable measurement under the vocabulary and matcher contract that preceded this publication.

The taxonomy was derived from public security invariants and official MITRE CWE definitions without consulting Secure Engine output. CWE associations are public metadata for review and interpretation; they are not scanner aliases and do not grant matching credit.

## Frozen categories

| Neutral category ID | Neutral invariant ID | Primary public association |
|---|---|---|
| `secure-bench.category.authorization-dominance` | `secure-bench.invariant.authorization-before-sensitive-operation` | CWE-862 |
| `secure-bench.category.command-execution` | `secure-bench.invariant.command-control-data-separation` | CWE-78 |
| `secure-bench.category.dynamic-code-execution` | `secure-bench.invariant.dynamic-code-control-data-separation` | CWE-95 |
| `secure-bench.category.filesystem-boundary` | `secure-bench.invariant.filesystem-path-confinement` | CWE-22 |
| `secure-bench.category.outbound-request-boundary` | `secure-bench.invariant.outbound-destination-policy` | CWE-918 |
| `secure-bench.category.redirect-boundary` | `secure-bench.invariant.redirect-destination-policy` | CWE-601 |
| `secure-bench.category.sql-construction` | `secure-bench.invariant.sql-control-data-separation` | CWE-89 |

Category and invariant identifiers are the only taxonomy coordinates used for prospective matching. Titles, descriptions, CWE identifiers, CWE URLs, scanner messages, native rule identifiers, severity, confidence, and tool identity are excluded from taxonomy identity matching. Source, sink, and evidence-path constraints remain independently required.

## Report boundary

Future native `secure-json-v1` findings and SARIF result `properties` may carry the same optional object:

```json
{
  "taxonomy": {
    "taxonomy_version": "1.0.0",
    "category_id": "secure-bench.category.command-execution",
    "invariant_id": "secure-bench.invariant.command-control-data-separation"
  }
}
```

Adapters preserve these values but do not infer, translate, or score them. Extra scanner-specific fields are rejected inside the taxonomy object. A report with no metadata, incomplete coordinates, another version, an unknown category, an unknown invariant, or identifiers belonging to different frozen pairs is explicitly `unmapped`. Unmapped findings receive no taxonomy credit; the evaluator does not fall back to prose, CWE values, rule names, fingerprints, or post-execution exception tables.

The public Rust API exposes the resolution state and every matching criterion. The existing Phase 0 and Phase 1 evaluator entry points do not invoke the prospective taxonomy matcher, which keeps their result bytes and historical interpretation unchanged.

## Versioning and canonicalization

The taxonomy document is strict typed JSON with unknown fields rejected. It contains exactly seven entries sorted by category identifier and a complete sorted set of official source URLs. Semantic validation checks stable namespaces, unique category and invariant identifiers, public-reference consistency, frozen publication metadata, and bounded display prose.

The `content_hash` is lowercase SHA-256 over compact deterministic JSON containing, in field order, `schema_version`, `taxonomy_version`, `publication_date`, `source_version`, `source_urls`, and `categories`. The `content_hash` field itself is excluded. The committed artifact is deterministic pretty JSON with one trailing newline.

Any change to identifiers, associations, prose, or ordering requires a new content hash. A breaking change to coordinates or resolution behavior requires a new taxonomy version and schema contract. Published versions are never silently rewritten.

The Rust CLI provides read-only contract operations:

```bash
cargo run --bin secure-bench -- taxonomy validate taxonomy/secure-bench-taxonomy-v1.json
cargo run --bin secure-bench -- taxonomy inspect taxonomy/secure-bench-taxonomy-v1.json
cargo run --bin secure-bench -- taxonomy canonicalize taxonomy/secure-bench-taxonomy-v1.json
```

## Official source record

The recorded upstream release label is CWE 4.20. The frozen source set links directly to the official MITRE definitions for CWE-22, CWE-78, CWE-89, CWE-95, CWE-601, CWE-862, and CWE-918. These links establish public provenance; Secure Bench does not reproduce MITRE definition text or treat CWE membership as proof that a scanner finding satisfies a benchmark expectation.

## Current limits

Seven broad invariants cannot represent every security weakness, language behavior, framework semantic, or data-flow condition. One primary CWE association is a review aid rather than an assertion of complete equivalence. The contract does not define scanner capability claims, alias registries, rule mappings, comparative weights, composite scores, rankings, production readiness, or retrospective baseline migration.
