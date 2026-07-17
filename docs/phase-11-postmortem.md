# Phase 11: Phase 10 postmortem and retired Phase 9 disclosure

Phase 11 is an additive, offline diagnostic analysis. It does not rescore, replace, or amend the
preregistered Phase 10 result. Secure Engine remained an external black box: no scanner process was
started and no Secure Engine source was inspected. The retired Phase 9 corpus is now public
diagnostic material, not a hidden holdout.

This analysis is not a ranking, scanner comparison, superiority claim, production-readiness claim,
or complete-coverage claim.

## Immutable historical result

The official Phase 10 result remains 0 exact matches, 0 partial matches, 112 misses, 24 flagged
controls, 88 clean controls, and 48 distinct unrelated findings. Its semantic fingerprint remains
`6c7292820f3fed8e6a245b2c9a485dea6f54b58fbf2b7c346fb90f96ae514603`.

Phase 11 verifies the result, completed ledger, report aggregate, artifact index, pre-execution
contract, process audit, all 224 retained report hashes, all fixture fingerprints, the Phase 9
aggregate corpus commitment, and the Phase 9 contract Merkle root before reconstructing a
diagnostic. Historical files are read-only inputs.

## Confirmed causal chain

The zero exact-match score has multiple overlapping causes:

1. Eighty-eight vulnerable reports contain no finding. Twenty-six of those cases use the defective
   direct renderer and are not valid source-to-sink expectations. The remaining 62 have a
   source-supported non-direct vulnerable flow and are confirmed scanner false negatives.
2. Twenty-four vulnerable reports contain one finding. Phase 10 classified every one as
   `unmapped_semantics` because its adapter reconstructs canonical semantics from generic
   `evidence_path` identities and ignores the report's complete `evidence_contract_v2` object.
   This is a confirmed systemic adapter defect affecting all 48 retained findings.
3. After parsing only the already-declared Evidence Contract v2 object, 18 vulnerable findings
   satisfy the source, sink, connected path, value identity, barriers, and corrected frozen
   taxonomy contract. Four more are vulnerability-related but anchor the source at Next.js request
   parsing rather than the expected body-field assignment span. Two findings claim a connected
   path in direct fixtures whose source code contains no such value connection.
4. Only nine of the 24 vulnerable findings could have been reconciled fully with the historical
   expectation through adapter normalization alone. Nine SQL findings also require correction of
   the benchmark's invalid invariant ID; four require a source-span correction in the finding; and
   two belong to invalid direct fixtures. Granting credit to the latter six would weaken the
   contract.
5. All 24 flagged controls are non-direct controls whose barrier or structurally safe API is
   present and terminating. They are confirmed scanner false positives: 12 command allowlist and
   fixed-executable cases, four filesystem-confinement cases, and eight redirect-policy cases.
   The adapter defect is present in these finding records but did not cause the official control
   flag, because Phase 10 flags a control for any distinct finding.

These statements distinguish causation from correlation. Adapter causation is supported by the
frozen adapter implementation and the retained declared-v2 objects. Benchmark causation is
supported by exact source and taxonomy comparisons. Scanner attribution is limited to cases where
the retired fixture source deterministically establishes the relevant flow or barrier. No claim is
derived from scanner implementation details.

## Confirmed defects and overlap

The chained ledger contains seven confirmed defect records:

- Four scanner records affect 92 distinct cases: 62 no-finding vulnerable cases, 24 flagged safe
  controls, two unsupported connected-path claims in invalid direct fixtures, and four source-span
  mismatches.
- Two benchmark records affect 200 distinct cases. The Phase 9 invariant IDs disagree with the
  frozen taxonomy in 192 cases. The direct renderer disconnects `candidate` from the `value` used
  at the sink in 56 cases. These populations overlap in 48 cases.
- One adapter/matcher record affects all 48 retained findings.
- There are zero confirmed contract-ambiguity records and zero unresolved-attribution records.

Counts are overlapping diagnostic populations and must not be added as mutually exclusive score
categories.

## Independent fixture validation

All 224 fixture fingerprints and all vulnerable source and sink spans validate against committed
source. All 168 non-direct cases preserve the intended value-flow topology. The 84 non-direct
controls contain the required terminating barrier or structurally safe API. The 56 direct cases
use an undefined `value` rather than the declared `candidate`: 28 vulnerable expectations are
disconnected and 28 controls do not demonstrate the intended barrier semantics. Those controls are
classified as ambiguous, even though the undefined identifier prevents the sensitive call from
completing.

The frozen taxonomy agrees with the Phase 9 category, invariant, and CWE only for the authorization
family. Six other families use an invented Phase 9 invariant ID instead of the committed taxonomy
invariant. This affects 192 cases. The union of taxonomy and direct-renderer benchmark defects is
200 cases; only the 24 non-direct authorization cases are fully contract-valid as originally
written.

## Primary stratification

The columns below are diagnostic-only: fully valid original contracts, contract-supported retained
findings, scanner false negatives, scanner false positives, adapter-affected findings, and cases
affected by a benchmark defect.

| Family | Cases | Valid | Supported | FN | FP | Adapter | Benchmark |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| SE1001 | 32 | 24 | 9 | 1 | 0 | 13 | 8 |
| SE1002 | 32 | 0 | 0 | 12 | 12 | 12 | 32 |
| SE1003 | 32 | 0 | 0 | 12 | 0 | 0 | 32 |
| SE1004 | 32 | 0 | 0 | 12 | 4 | 4 | 32 |
| SE1005 | 32 | 0 | 0 | 12 | 0 | 0 | 32 |
| SE1006 | 32 | 0 | 0 | 12 | 8 | 8 | 32 |
| SE1007 | 32 | 0 | 9 | 1 | 0 | 11 | 32 |

| Framework | Cases | Valid | Supported | FN | FP | Adapter | Benchmark |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| Node.js | 56 | 6 | 6 | 15 | 4 | 10 | 50 |
| Express | 56 | 6 | 6 | 15 | 7 | 13 | 50 |
| Next.js App Router | 56 | 6 | 0 | 17 | 6 | 11 | 50 |
| Server Actions | 56 | 6 | 6 | 15 | 7 | 14 | 50 |

| Language | Cases | Valid | Supported | FN | FP | Adapter | Benchmark |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| JavaScript | 112 | 12 | 10 | 32 | 12 | 23 | 100 |
| TypeScript | 112 | 12 | 8 | 30 | 12 | 25 | 100 |

| Topology | Cases | Valid | Supported | FN | FP | Adapter | Benchmark |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| Direct | 56 | 0 | 0 | 0 | 0 | 2 | 56 |
| Helper-mediated | 56 | 8 | 6 | 20 | 7 | 15 | 48 |
| Inter-file aliased | 56 | 8 | 6 | 22 | 6 | 12 | 48 |
| Control-flow-sensitive | 56 | 8 | 6 | 20 | 11 | 19 | 48 |

The diagnostic package contains all six frozen pairwise intersections: taxonomy/framework,
taxonomy/language, taxonomy/topology, framework/language, framework/topology, and
language/topology. It contains 28, 14, 28, 8, 16, and 8 cells respectively.

## Agreement matrices

The independent fixture-versus-expectation matrix covers all 112 vulnerable cases. Taxonomy
version, category, CWE, source identity/span, sink identity/span, and absence of an effective
barrier agree in 112/112. The invariant agrees in 16/112 because six Phase 9 family mappings drift
from the frozen taxonomy. Ordered path and transform/value identity agree in 84/112 because all 28
direct vulnerable fixtures are disconnected.

Among the 24 vulnerable retained findings, taxonomy version, category, CWE, source identity, sink
identity, sink span, connected path, transform/value identity, and barrier/dominance agree in all
24 records. The historical invariant agrees in 13 records and disagrees in 11 SQL records. Source
span agrees in 18 and disagrees in six: four non-direct Next.js cases and two invalid direct cases.

The separate control-versus-paired-expectation matrix is diagnostic context only. Its spans are not
expected to agree because paired safe mutations move or replace the sensitive operation. The full
matrix is retained to make every finding mapping auditable, not to grant control-case credit.

## Evidence lifecycle and future use

The machine-readable package maps every rejected finding to a related expectation, exact mismatch
reasons, and normalization legitimacy. The generalized regression manifest exposes all 224 cases;
168 non-direct cases are eligible as public regression candidates, while 56 direct cases are
excluded until a newly versioned fixture repairs the value flow. No benchmark-specific scanner
exception or new hidden holdout is created.

Nineteen public synthetic Evidence Contract v2 vectors cover exact matching, taxonomy, category,
invariant, CWE, source and sink identity/span, connectivity, order, value identity, guard,
sanitizer, authorization/dominance, uncertainty, unresolved calls, duplicates, and unrelated
findings. Each mutation has an inverse restoring the exact base vector.

## Limitations

This analysis uses synthetic retired fixtures and static retained evidence. It does not establish
real-world prevalence, exploitability, runtime behavior, or complete framework semantics. The
diagnostic does not infer scanner implementation causes and does not compare scores across
different corpora. Future fixture repairs and adapter changes require new versions and cannot
rewrite Phase 9 or Phase 10 history.
