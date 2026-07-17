# Phase 10 one-shot Phase 9 holdout evaluation

Phase 10 is one preregistered, local, black-box measurement of the exact user-supplied Secure
Engine 0.1.4 artifact against the frozen Phase 9 synthetic holdout. It is not a production
benchmark, public ranking, scanner comparison, coverage guarantee, or evidence that Secure Engine
or another analyzer is superior.

All 224 cases were executed exactly once. Each scanner process ran only after an in-namespace
isolation check inside a fresh Bubblewrap network namespace exposing loopback alone. The process
environment was cleared and contained no AI provider, endpoint, credentials, configuration, or AI
command. AI validation remained disabled. No case was retried, repaired, replaced, or rescored
after execution.

## Aggregate result

The frozen Evidence Contract v2 grants exact credit only when canonical taxonomy, source, sink,
span, connected path, and barrier semantics agree. A finding may have some taxonomy agreement
without qualifying as an exact or partial evidence match.

| Measure | Result |
|---|---:|
| Vulnerable expectations | 112 |
| Exact detections | 0 |
| Partial matches | 0 |
| Completed misses | 112 |
| Out of scope / not attempted | 0 / 0 |
| Safe controls | 112 |
| Flagged / clean controls | 24 / 88 |
| Distinct / duplicate / unrelated findings | 48 / 0 / 48 |
| Strict precision | 0.00% (0 / 48) |
| Strict recall | 0.00% (0 / 112) |
| Strict F1 | 0.00% |

All 48 findings were retained and normalized, but none satisfied the frozen source, sink, and
connected evidence-path requirements. Consequently, all are unrelated under the strict matching
contract even where individual taxonomy coordinates agreed.

| Agreement dimension | Agreement |
|---|---:|
| Taxonomy / invariant | 13 / 112 (11.61%) |
| Category / CWE | 24 / 112 (21.43%) |
| Source / sink / ordered evidence path | 0 / 112 each |
| Barrier / sanitizer / guard / dominance | 24 / 112 (21.43%) each |

## Execution and process-status adjudication

| Execution measure | Result |
|---|---:|
| Retained adapter-valid reports | 224 |
| Exit code 0 / exit code 1 | 176 / 48 |
| Clean successful / valid-findings policy exit | 176 / 48 |
| Failures / crashes / timeouts | 0 / 0 / 0 |
| Malformed / missing / internally errored reports | 0 / 0 / 0 |
| Unsupported reports / execution failures | 0 / 0 |
| Scanner launch attempts / maximum per case | 224 / 1 |
| Isolation-attested scanner processes | 224 |
| Version probes / AI commands / network-permitted processes | 0 / 0 / 0 |
| Sum of measured case durations | 2,240 ms |
| Runner wall duration | 7,799 ms |
| Sampled direct-process peak RSS | 348,160 bytes |
| Retained report output | 21,588,137 bytes |
| Retained stdout / stderr | 0 / 80,836 bytes |
| Deterministic semantic fingerprint | `6c7292820f3fed8e6a245b2c9a485dea6f54b58fbf2b7c346fb90f96ae514603` |

The Phase 8 process-status policy was applied before failure accounting. Every exit-code-1 process
retained a complete, adapter-valid report containing findings and was classified as a valid
findings policy exit, not a crash. Offline verification performs the policy adjudication and
Evidence Contract v2 evaluation twice and requires byte-identical deterministic projections.

## Balanced breakdowns

Every vulnerable member in every stratum was a completed miss; there were no exact, partial,
out-of-scope, or not-attempted vulnerable outcomes. The tables therefore focus on controls and
retained distinct findings while retaining the vulnerable denominator.

### Taxonomy family

| Family | Vulnerable misses | Flagged controls | Clean controls | Distinct findings |
|---|---:|---:|---:|---:|
| SE1001 | 16 / 16 | 0 | 16 | 13 |
| SE1002 | 16 / 16 | 12 | 4 | 12 |
| SE1003 | 16 / 16 | 0 | 16 | 0 |
| SE1004 | 16 / 16 | 4 | 12 | 4 |
| SE1005 | 16 / 16 | 0 | 16 | 0 |
| SE1006 | 16 / 16 | 8 | 8 | 8 |
| SE1007 | 16 / 16 | 0 | 16 | 11 |

### Framework

| Framework | Vulnerable misses | Flagged controls | Clean controls | Distinct findings |
|---|---:|---:|---:|---:|
| Node.js | 28 / 28 | 4 | 24 | 10 |
| Express | 28 / 28 | 7 | 21 | 13 |
| Next.js App Router | 28 / 28 | 6 | 22 | 11 |
| Server Actions | 28 / 28 | 7 | 21 | 14 |

### Language

| Language | Vulnerable misses | Flagged controls | Clean controls | Distinct findings |
|---|---:|---:|---:|---:|
| JavaScript | 56 / 56 | 12 | 44 | 23 |
| TypeScript | 56 / 56 | 12 | 44 | 25 |

The frozen language factor is JavaScript versus TypeScript. JSX and TSX source forms are covered
inside the framework assignments and are not separately scored as independent language levels.

### Topology

| Topology | Vulnerable misses | Flagged controls | Clean controls | Distinct findings |
|---|---:|---:|---:|---:|
| Direct | 28 / 28 | 0 | 28 | 2 |
| Helper-mediated | 28 / 28 | 7 | 21 | 15 |
| Inter-file aliased | 28 / 28 | 6 | 22 | 12 |
| Control-flow-sensitive | 28 / 28 | 11 | 17 | 19 |

### All pairwise intersections

The canonical result records every cell of all six required pairwise intersections. Each
intersection totals 112 vulnerable misses, 24 flagged controls, 88 clean controls, and 48 distinct
unrelated findings; exact and partial counts are zero in every cell.

| Intersection | Cells | Vulnerable cases per cell | Flagged-control range | Finding range |
|---|---:|---:|---:|---:|
| Taxonomy × framework | 28 | 4 | 0–3 | 0–4 |
| Taxonomy × language | 14 | 8 | 0–6 | 0–7 |
| Taxonomy × topology | 28 | 4 | 0–4 | 0–4 |
| Framework × language | 8 | 14 | 1–5 | 5–8 |
| Framework × topology | 16 | 7 | 0–3 | 0–5 |
| Language × topology | 8 | 14 | 0–6 | 1–10 |

The exact per-cell values are in the `breakdowns` object of the immutable result artifact; this
document intentionally does not expose holdout source or per-case answers.

## Provenance and integrity

| Artifact or commitment | SHA-256 |
|---|---|
| External binary | `fe15135e878a768d452eaae2c014da4bd1e61f6ca0dca45d7ada54fd69a6c075` |
| Source RPM | `c470f8bab478c937d6924f4d1bf7f6328da564cc392624622b4cc234130c0aef` |
| Phase 9 manifest | `136f92a3bbe324d8f0e3c49438b93aa4ef6eb09731998784feed0b6f75553a9f` |
| Phase 9 commitments | `31c83b443c889e8f3dbc0ddea358f27d4ec990dae11a4138373ea9a6fb6e13b0` |
| Evidence Contract v2 | `142c7f31c6c584cc808410130fa7db8451427e87504e72e64868c9cbc6564c42` |
| Taxonomy artifact | `059fe22d7707cf8d17f2c1621fdae9819787a1958ba2ef0421eca4e4ec858452` |
| Aggregate corpus | `30f51f643da6d27c8c94758289ee77c937104d372b97f0de90d4d40ced56dbe2` |
| Contract Merkle root | `7c41259cb2bc36cdab2582ac9867df6a95c1fd59686315118f70c07fe5eedf6a` |
| Frozen Phase 10 evaluator | `fe90f41b15c68f3835e741d9962cd1c3f1098aca13eca83a1805ee8586e6392a` |
| Genesis ledger | `edd48b4b70115db7c43d93d987003b62b025b5943c17d96b3dfd0262dbc69841` |
| Pre-execution contract | `9ae54bb31edeaeee736b52a0d667d8f3c12d2d6c73d66690f7af7905d777def1` |
| Retained run | `7cc49fd2d988855619a2eb9e0c41bf7aa71db26f00310993d79bfdb0c504e1a3` |
| Case journal | `c4b2a7fed5390c4457a1c2bf7274a38dd081068debae6fe8dcec72c11a3cdbe2` |
| Aggregate retained reports | `b7c5ba7bb3c7f6f2ed82a3aabd12daaf15b09b6c3cabda4e39d29827b46ee0e1` |
| Aggregate retained streams | `34832d701e5afc3ceda6f2c191680b0e175d08018d509761f538d32e54142b20` |
| Isolation attestations | `99170f2e5ce5b00b1dfadf1dae34fde5894c72b2d6f945cafe0c4c9bbd0f018b` |
| Process audit | `3c48f3cdae5c6f69af747c978e7e4bc35dc6b3c57f71aadf2c5e1d7693cce43b` |
| Result | `bfb74fbc89345bcb6c8584fc8774b2347f31816bdbf1efc9628e96cab8904a7c` |
| Completed ledger | `ddcbcfda08af81b89374091bfd42b0aeef8bcde9339d6f6b40506953c07b6b77` |
| Artifact index | `a1d41915269937bd4570ea238731e0d83d9717fa2f22c9ffe2c1cd234cab57ef` |

The exact command template was
`scan {fixture} --format secure-json-v1 --output {report}`. Public evidence uses portable paths,
cleared-environment provenance, fixed schema versions, hashes, and isolation attestations. The
separate Phase 10 ledger is an exact byte-prefix extension of the immutable Phase 9 genesis and
contains one reservation, 224 case entries, and one completion entry.

## Historical interpretation and limitations

- Phase 1, Phase 2, Phase 4, Phase 7, Phase 8, and Phase 9 evidence remains immutable. Scores from
  different corpora or contracts must not be directly ranked.
- This synthetic holdout does not establish production prevalence, exploitability, production
  readiness, superiority, or complete coverage.
- Taxonomy alignment alone is not a true detection. Exact and partial detection credit requires
  the frozen evidence semantics; all 48 retained findings were unrelated under that contract.
- The sampled peak RSS observes the directly supervised Bubblewrap process and can understate the
  scanner descendant's memory use. Runtime and memory values are local, non-portable measurements.
- The one-shot protocol forbids reruns and post-execution changes to the evaluator, adapters,
  matching, scoring, fixtures, expectations, taxonomy, or evidence contract.
