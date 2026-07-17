# Phase 6 Phase 4 postmortem

Phase 6 retires the executed Phase 3 holdout as a public development and diagnostic corpus. It is an additive analysis of immutable Phase 3 contracts and retained Phase 4 reports. It does not rescore Phase 4, execute a scanner, inspect a scanner implementation, or use any Phase 5 case, answer, identifier, or metadata.

The retired corpus is no longer unseen. It must not be used for future unbiased evaluation, public rankings, production-readiness claims, superiority claims, or claims of complete coverage. The official Phase 4 result remains the authoritative historical score.

## Historical result

| Official Phase 4 measure | Count |
|---|---:|
| Eligible vulnerable expectations | 28 |
| Exact detections | 0 |
| Partial matches | 12 |
| Misses | 16 |
| Out of scope / not attempted | 0 / 0 |
| Flagged / clean controls | 10 / 18 |
| Normalized / duplicate findings | 32 / 0 |

Exact precision, recall, and F1 were all zero under the frozen contract. Taxonomy category, invariant, and primary-CWE agreement were each 7/28; source, sink, and ordered evidence agreement were 0/28, 12/28, and 0/28. These numbers are copied from the immutable result and have not been recalculated or replaced.

## Diagnostic method

The Rust analyzer consumes only:

- the immutable Phase 3 manifest and completed append-only ledger;
- the frozen neutral taxonomy;
- the official Phase 4 result, run record, artifact index, and 56 retained reports; and
- the public evidence-contract v2 definition for a prospective contract-only comparison.

For every retired case it records the original contract hash, fixture hash, copied fixture path, retained-report hash, normalized observations, official outcome and criteria, and one or more neutral diagnostic classes. Each record has a content hash. Validation reconstructs the complete package from the immutable sources, compares every public fixture copy byte-for-byte, and rejects non-canonical serialization or changed provenance.

The classifications separate three layers:

- `scanner_behavior` describes retained black-box observations, such as an empty successful report, a source disagreement, an unrelated observation, or a flagged safe control.
- `evaluator_behavior` describes the frozen adapter or evidence-contract boundary, such as exact line or ordered hop-kind rejection where semantic endpoint observations are still present.
- `experimental_design` describes conclusions the retired design cannot support.

The classes are diagnostic labels, not new scoring outcomes. A case may have more than one class, so category totals are not mutually exclusive and must not be summed as a case count.

## Aggregate diagnostic classes

| Diagnostic class | Cases |
|---|---:|
| No finding emitted | 16 |
| Wrong taxonomy, category, invariant, or CWE | 5 |
| Missing or incorrect source | 12 |
| Missing or incorrect sink | 0 |
| Evidence-path mismatch | 12 |
| Transformation or value-identity mismatch | 12 |
| Guard, sanitizer, or dominance mismatch | 10 |
| Safe-control false positive | 10 |
| Duplicate or unrelated finding | 22 |
| Adapter or evidence-contract ambiguity | 12 |
| Framework/language/topology attribution uncertainty | 56 |

The source/sink/evidence matrix distinguishes the 16 successful empty reports from the 12 selected observations. All 12 selected observations had a same-file source at a different line and an exact or declared sink. Eleven had semantic endpoint roles with incompatible contract-v1 hop vocabulary, while one was below the minimum hop count. The official atomic criteria remain unchanged.

## Pair analysis and experimental confounding

All 28 vulnerable/control pairs are represented explicitly. Ten controls emitted findings; their paired security property was therefore not distinguished by the retained observation. The other 18 controls were clean. Pair records report only finding-count differentiation and official outcomes; they do not infer scanner implementation causes.

Framework, language, and topology are perfectly associated in the retired design:

| Framework | Language | Topology | Pairs |
|---|---|---|---:|
| Node.js | JavaScript | Direct | 7 |
| Express | JSX | Helper-mediated | 7 |
| Next.js App Router | TypeScript | Inter-file aliased | 7 |
| Next.js Server Actions | TSX | Control-flow-sensitive | 7 |

Each pairwise 4-by-4 contingency table has Pearson chi-square 84.000 and Cramer's V 1.0000. Consequently, framework, language, and topology effects cannot be estimated independently. The matrices quantify association only; they do not establish causality, scanner architecture, or general production behavior.

## Evidence contract audit

The contract-v1 audit uses synthetic vectors and retained reports. Synthetic checks confirm that contract v1 accepts exact coordinates and declared alternatives, rejects undeclared line shifts and reversed paths, compares ordered normalized hop-kind strings rather than semantic role equivalence, and cannot match absent prospective taxonomy metadata.

The retained audit found 7/28 taxonomy agreements, 0/28 source agreements, 12/28 sink agreements, and 0/28 ordered evidence agreements. Semantic observations that fail the frozen criteria receive no retrospective credit.

The conceptual v2 comparison is prospective only. It reads the public v2 contract definition, not Phase 5 cases or answers. Contract v2 adds canonical endpoint semantics, bounded bidirectional span containment, explicit path-compression rules, barrier semantics, and partial uncertainty. This comparison does not imply that any retired case would receive a particular v2 outcome and does not change Phase 4.

## Public package

The package is intentionally suitable for development and regression work:

- `diagnostics/phase-6/retired-holdout-diagnostic-v1.json` contains all case records, pair comparisons, matrices, confounding proof, retained-report examples, and historical provenance.
- `diagnostics/phase-6/regression-manifest-v1.json` is the standalone engine-consumable regression contract.
- `diagnostics/phase-6/fixtures/` is a byte-identical public copy of all 56 retired fixtures.
- `schemas/phase6-retired-diagnostic-v1.schema.json` and `schemas/phase6-regression-manifest-v1.schema.json` are the versioned package schemas.

The canonical diagnostic artifact SHA-256 is `6966c507db9fb0c1efda62dd9e07ccecb80aff56962c29af27a1b0f2877cd4f4`; its internal content hash is `4d3a312356f55f12f016ac233c0483ff2276b2fc004804b586e1749a2c09642d`. The regression artifact SHA-256 is `68269560554cb9f3c1d837912321e2f34a1cc1bef81602aec9994efa726a7a17`. These artifact hashes are also committed in `diagnostics/phase-6/SHA256SUMS`.

Because the fixture sources and expectations are disclosed, test results produced from this package are development diagnostics, not unseen benchmark measurements.

## Limitations

- The evidence supports observation-level mismatch descriptions, not internal root causes.
- Category labels overlap and are not an alternative scoring system.
- The design cannot separate framework, language, and topology effects.
- Retained reports reflect one historical black-box execution and no rerun.
- Contract-v2 observations are prospective and synthetic; they never reinterpret Phase 4.
- The package does not establish production readiness, superiority, or complete security coverage.
- No remediation is proposed or implemented in this phase.

## Reproduction and validation

Generate once from the exact historical parent:

```text
secure-bench phase6 generate --repository-root . --published-at-utc YYYY-MM-DDTHH:MM:SSZ
```

Validate without regeneration or scanner execution:

```text
secure-bench phase6 validate --repository-root .
```

Validation fails closed on historical hash drift, report drift, copied-fixture drift, schema failure, non-canonical JSON, record hash failure, diagnostic reconstruction drift, or prohibited Phase 5 references.
