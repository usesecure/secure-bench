# Secure Bench Phase 14 Result

Phase 14 is a retrospective report of the preregistered one-shot execution, not another scanner run. Secure Engine 0.1.4 was evaluated once against the 112-case Phase 13 prospective holdout v4. All subsequent reconstruction was offline from the retained reports.

This synthetic evaluation is not a public ranking, scanner comparison, superiority claim, production-readiness claim, or claim of complete coverage. Its scores must not be directly compared with results produced on a different corpus.

## Aggregate result

| Measure | Result |
|---|---:|
| Vulnerable expectations | 56 |
| Exact detections | 0 |
| Partial matches | 0 |
| Misses | 56 |
| Out of scope / not attempted | 0 / 0 |
| Safe controls | 56 |
| Flagged / clean controls | 40 / 16 |
| Distinct / duplicate / unrelated findings | 96 / 0 / 96 |
| Precision | 0 / 96 (0.00%) |
| Recall | 0 / 56 (0.00%) |
| F1 | 0 / 152 (0.00%) |

Taxonomy, category, invariant, and CWE each agreed for 56/56 selected vulnerable-case candidates. Source identity agreed for 0/56 and source span for 28/56; sink identity agreed for 8/56 and sink span for 56/56. Connected value identity and the ordered evidence path each agreed for 0/56. Barrier, sanitizer, guard, and dominance criteria each agreed for 56/56. These atomic agreements are partial diagnostic evidence only and do not receive exact-detection credit under Evidence Contract v2.

## Primary strata

| Stratum | Vulnerable: exact / partial / missed | Controls: flagged / clean |
|---|---:|---:|
| SE1001 | 0 / 0 / 8 | 0 / 8 |
| SE1002 | 0 / 0 / 8 | 8 / 0 |
| SE1003 | 0 / 0 / 8 | 8 / 0 |
| SE1004 | 0 / 0 / 8 | 8 / 0 |
| SE1005 | 0 / 0 / 8 | 8 / 0 |
| SE1006 | 0 / 0 / 8 | 8 / 0 |
| SE1007 | 0 / 0 / 8 | 0 / 8 |
| Node.js | 0 / 0 / 14 | 10 / 4 |
| Express | 0 / 0 / 14 | 10 / 4 |
| Next.js App Router | 0 / 0 / 14 | 10 / 4 |
| Server Actions | 0 / 0 / 14 | 10 / 4 |
| JavaScript language group | 0 / 0 / 28 | 20 / 8 |
| TypeScript language group | 0 / 0 / 28 | 20 / 8 |
| JavaScript / JSX / TypeScript / TSX (each) | 0 / 0 / 14 | 10 / 4 |
| Direct / helper-mediated / inter-file aliased / control-flow-sensitive (each) | 0 / 0 / 14 | 10 / 4 |

The result artifact contains all 15 required one-dimensional and pairwise breakdown tables across taxonomy family, framework, language group, source format, and topology.

## Execution and failure accounting

All 112 reports were complete and adapter-valid. Sixteen cases exited 0 with clean reports; 96 exited 1 with findings reports and were correctly treated as authoritative policy exits. There were no crashes, timeouts, malformed reports, missing reports, internally errored reports, unsupported schemas, or execution-infrastructure failures. Every case has one launch attempt and one valid isolation attestation. No version probe or AI command was executed, and no scanner process was permitted network access.

The sum of per-case wall time was 1,120 ms and end-to-end runner time was 2,812 ms. Peak sampled RSS was 344,064 bytes. Retained reports total 13,277,050 bytes; stdout is empty and stderr totals 38,122 bytes. The deterministic semantic fingerprint is `a88216b7f1b6a3231afdbff3444a581153b56f28048252f344f5e143390926a2`.

## Artifact hashes

| Artifact | SHA-256 |
|---|---|
| Pre-execution contract | `40ac463147310ff84d408f751812be423b92b5bb7ec4167ffecfc09389a0d81a` |
| Result | `6782bf22740f57aa31345065356986a8d91f9aef012c0c4d65ce39d124830a4d` |
| Completed ledger | `e0b66144ccfaf571307339282d918169d3738e8de64289e9de4975d8517c5629` |
| Run | `2fddca2bf6de2bcfc99a1bd1753985ff2f5eaf480a0bfad670329e250e23542b` |
| Case journal | `38e40596ba14dac85f6b839598dce8bee0efcc7da17c77fb365422bb20a6a92c` |
| Report-set aggregate | `34e20e8970da844317115b8f1d9cf05b673cf338b09b06e9307567ac9c4ed082` |
| Stream aggregate | `ae574bf5ba1d9d2d9243e4df6f9bc325e77f26e7b2c23b9a3e823e6fade8dd87` |
| Isolation aggregate | `6985d4bb111d09d6ef8e26caf12f31457823f821a7a02f3893c2e0385ae4f090` |
| Process audit | `11f9761ca4b2add7a6acf0a15e7290ae7a452407ebb82615acf355750d17e255` |
| Artifact index | `4ffc4b52f6421a4c5d230f3425e6dec538a3592b8acb02c899d6781ddfe2ceae` |

The immutable Phase 13 genesis ledger remains `fadb09649e2dba60b566096cf33aad0675e5eeb806d4501ea13a232c7af0a1ee`; it is the exact byte prefix of the completed ledger. The external RPM and extracted binary remain `c470f8bab478c937d6924f4d1bf7f6328da564cc392624622b4cc234130c0aef` and `fe15135e878a768d452eaae2c014da4bd1e61f6ca0dca45d7ada54fd69a6c075`, respectively.

## Limitations

The corpus is synthetic and does not establish production prevalence, exploitability, or operational effectiveness. Exact scoring intentionally rejects findings that lack the frozen source-to-sink evidence contract even when taxonomy metadata agrees. Runtime and RSS are measurements from one local environment. Historical Phase results remain immutable, and Phase 14 is not score-comparable with evaluations that used another corpus.
