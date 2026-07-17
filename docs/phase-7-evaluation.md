# Phase 7 one-shot orthogonal holdout evaluation

Phase 7 is one preregistered, local, black-box measurement of the exact user-supplied Secure Engine 0.1.3 artifact against the frozen Phase 5 synthetic holdout. It is not a production benchmark, public ranking, scanner comparison, coverage guarantee, or evidence that Secure Engine or another analyzer is superior.

The 112 cases were executed exactly once. Each scanner process ran after an in-namespace isolation check inside a fresh Bubblewrap network namespace exposing only loopback. The scanner environment was cleared and contained no AI provider, endpoint, credentials, configuration, or AI command. AI validation remained disabled. No case was retried, repaired, replaced, or rescored after execution.

## Aggregate result

The strict evidence-contract v2 metric grants detection credit only to exact canonical taxonomy, endpoint, span, connected-path, and barrier semantics. Partial evidence receives no exact credit. An operational failure is `not_attempted`, never a clean scan or miss.

| Measure | Result |
|---|---:|
| Vulnerable expectations | 56 |
| Exact detections | 0 |
| Partial matches | 0 |
| Completed misses | 36 |
| Out of scope | 0 |
| Vulnerable not attempted | 20 |
| Safe controls | 56 |
| Flagged controls | 0 |
| Clean controls | 43 |
| Controls not attempted | 13 |
| Distinct / duplicate / unrelated findings | 0 / 0 / 0 |
| Strict precision | undefined (0 exact / 0 distinct findings) |
| Strict recall | 0.00% (0 / 56) |
| Strict F1 | 0.00% |

Taxonomy, category, invariant, CWE, source, sink, and ordered evidence-path agreement were each 0/56. These are agreement measurements against all frozen vulnerable expectations; they are not evidence that a completed report contained a wrong coordinate. The run emitted no findings, while 20 vulnerable cases did not produce a scoreable completed execution.

| Execution measure | Result |
|---|---:|
| Completed scanner processes | 79 |
| Nonzero exits / crashes / failures | 33 / 33 / 33 |
| Timeouts | 0 |
| Malformed reports | 0 |
| Missing reports | 0 |
| Retained reports | 112 |
| Sum of measured case durations | 1,175 ms |
| Runner wall duration | 2,517 ms |
| Sampled peak RSS | 2,469,888 bytes |
| Retained report output | 11,910,427 bytes |
| Semantic fingerprint | `fcc86fcba4c42a58565b2af96d94b7e27d97d22f6cde6d9888a09caa4ace8b2c` |

All 33 exit-code-1 processes produced reports, which were retained unchanged and ledger-bound. Under the preregistered protocol, a nonzero process exit remains a crash even when a report exists; those outputs were not silently promoted to successful scans.

## Balanced breakdowns

In the tables, `miss` means a completed vulnerable scan without an exact or partial match. `V-NA` and `C-NA` mean vulnerable and control executions that were not attempted for scoring because the scanner process failed. Every row has zero exact detections, partial matches, out-of-scope cases, and flagged controls.

### Taxonomy family

| Family | Vulnerable | Miss | V-NA | Controls | Clean | C-NA |
|---|---:|---:|---:|---:|---:|---:|
| Authorization dominance | 8 | 4 | 4 | 8 | 4 | 4 |
| Command execution | 8 | 4 | 4 | 8 | 4 | 4 |
| Dynamic code execution | 8 | 5 | 3 | 8 | 8 | 0 |
| Filesystem boundary | 8 | 8 | 0 | 8 | 8 | 0 |
| Outbound request boundary | 8 | 7 | 1 | 8 | 7 | 1 |
| Redirect boundary | 8 | 4 | 4 | 8 | 4 | 4 |
| SQL construction | 8 | 4 | 4 | 8 | 8 | 0 |

### Framework

| Framework | Vulnerable | Miss | V-NA | Controls | Clean | C-NA |
|---|---:|---:|---:|---:|---:|---:|
| Node.js | 14 | 14 | 0 | 14 | 14 | 0 |
| Express | 14 | 14 | 0 | 14 | 14 | 0 |
| Next.js App Router | 14 | 4 | 10 | 14 | 7 | 7 |
| Server Actions | 14 | 4 | 10 | 14 | 8 | 6 |

### Language

| Language | Vulnerable | Miss | V-NA | Controls | Clean | C-NA |
|---|---:|---:|---:|---:|---:|---:|
| JavaScript | 28 | 18 | 10 | 28 | 21 | 7 |
| TypeScript | 28 | 18 | 10 | 28 | 22 | 6 |

### Topology

| Topology | Vulnerable | Miss | V-NA | Controls | Clean | C-NA |
|---|---:|---:|---:|---:|---:|---:|
| Direct | 14 | 14 | 0 | 14 | 14 | 0 |
| Helper-mediated | 14 | 7 | 7 | 14 | 10 | 4 |
| Inter-file aliased | 14 | 7 | 7 | 14 | 8 | 6 |
| Control-flow-sensitive | 14 | 8 | 6 | 14 | 11 | 3 |

### Framework × language

| Stratum | Vulnerable | Miss | V-NA | Clean controls | C-NA |
|---|---:|---:|---:|---:|---:|
| Express × JavaScript | 7 | 7 | 0 | 7 | 0 |
| Express × TypeScript | 7 | 7 | 0 | 7 | 0 |
| Next.js App Router × JavaScript | 7 | 2 | 5 | 3 | 4 |
| Next.js App Router × TypeScript | 7 | 2 | 5 | 4 | 3 |
| Node.js × JavaScript | 7 | 7 | 0 | 7 | 0 |
| Node.js × TypeScript | 7 | 7 | 0 | 7 | 0 |
| Server Actions × JavaScript | 7 | 2 | 5 | 4 | 3 |
| Server Actions × TypeScript | 7 | 2 | 5 | 4 | 3 |

### Topology × language

| Stratum | Vulnerable | Miss | V-NA | Clean controls | C-NA |
|---|---:|---:|---:|---:|---:|
| Control-flow-sensitive × JavaScript | 7 | 3 | 4 | 4 | 3 |
| Control-flow-sensitive × TypeScript | 7 | 5 | 2 | 7 | 0 |
| Direct × JavaScript | 7 | 7 | 0 | 7 | 0 |
| Direct × TypeScript | 7 | 7 | 0 | 7 | 0 |
| Helper-mediated × JavaScript | 7 | 4 | 3 | 5 | 2 |
| Helper-mediated × TypeScript | 7 | 3 | 4 | 5 | 2 |
| Inter-file aliased × JavaScript | 7 | 4 | 3 | 5 | 2 |
| Inter-file aliased × TypeScript | 7 | 3 | 4 | 3 | 4 |

### Framework × topology

| Stratum | Vulnerable | Miss | V-NA | Clean controls | C-NA |
|---|---:|---:|---:|---:|---:|
| Express × control-flow-sensitive | 4 | 4 | 0 | 4 | 0 |
| Express × direct | 3 | 3 | 0 | 3 | 0 |
| Express × helper-mediated | 4 | 4 | 0 | 4 | 0 |
| Express × inter-file aliased | 3 | 3 | 0 | 3 | 0 |
| Next.js App Router × control-flow-sensitive | 3 | 0 | 3 | 1 | 2 |
| Next.js App Router × direct | 4 | 4 | 0 | 4 | 0 |
| Next.js App Router × helper-mediated | 3 | 0 | 3 | 1 | 2 |
| Next.js App Router × inter-file aliased | 4 | 0 | 4 | 1 | 3 |
| Node.js × control-flow-sensitive | 3 | 3 | 0 | 3 | 0 |
| Node.js × direct | 4 | 4 | 0 | 4 | 0 |
| Node.js × helper-mediated | 3 | 3 | 0 | 3 | 0 |
| Node.js × inter-file aliased | 4 | 4 | 0 | 4 | 0 |
| Server Actions × control-flow-sensitive | 4 | 1 | 3 | 3 | 1 |
| Server Actions × direct | 3 | 3 | 0 | 3 | 0 |
| Server Actions × helper-mediated | 4 | 0 | 4 | 2 | 2 |
| Server Actions × inter-file aliased | 3 | 0 | 3 | 0 | 3 |

## Provenance and integrity

| Artifact or commitment | SHA-256 |
|---|---|
| External binary | `8678666b532380187d38968628908363970c960078c63489d26af35d31840902` |
| Source RPM | `ceb9ce77feee5df9a1a5766e72fd610504f67cdd1a2a958753c75e4001501d8d` |
| Manifest | `0bf17f093146c99bdc128fd39513b490f9774b427a252bc5fa508b4444c05827` |
| Evidence contract v2 | `142c7f31c6c584cc808410130fa7db8451427e87504e72e64868c9cbc6564c42` |
| Aggregate corpus | `8f5f43e497e953be79cfb23891e2d3059392c2a24b3143b136e7dc9609cc3b04` |
| Contract Merkle root | `f21b545b942beeb3f37232f39da7adecc1eb1f7694c24ea37a981c8ac20110cb` |
| Frozen evaluator | `363db2f0201ceb681134687e87313359ad7db83bec767ac99473201fde8b2b7a` |
| Genesis ledger | `dee6f5be204c4d4b7758c3afbbdd52997eaac090f636b6b15df7f7aabe7a1704` |
| Pre-execution contract | `418d7d592a4748b9457cdd264e01369501b5b1e3c4a09dd276c6555ef3fbd40a` |
| Retained run | `df0fc817f1aaf54d70dc3faa9e3717201dc31bbcc2ef1540091458cd51a65611` |
| Case journal | `914ec63dd9ca3c6b4670db030e8a32c65d1f5a2640a8274db1f62704dc5ac513` |
| Aggregate retained reports | `f00251036ece1bc6a8370c6c21159d7146d47323534fb4e207675f7c7ecc918d` |
| Result | `5fc423073f11578a2deaf1e21f37e71e72802be17235fd1ad4d7cc0542ea9379` |
| Completed ledger | `1a11d2d0cb97a800d868e84280fa41ab0b332b367c5c19873faa50603151459e` |
| Artifact index | `14fbef2e5194970dd424d7ae4b41172b8978ba850a8ca7314ec875dc6f003cbd` |

The exact command template was `scan {fixture} --format secure-json-v1 --output {report}`. Public artifacts contain portable paths, hashes, sanitized host information, the fixed schema versions, and isolation provenance; they contain no external absolute paths or credentials. The append-only ledger preserves the Phase 5 genesis entry and adds one reservation, 112 case outcomes, and one completion entry.

## Limitations and interpretation

- The corpus is synthetic and limited to seven invariant families, four framework forms, two languages, and four topology classes. It does not represent arbitrary applications or production prevalence.
- Thirty-three scanner processes returned exit code 1. Their reports remain retained, but the frozen protocol accounts for those executions as crashes. The affected 20 vulnerable cases and 13 controls are not misses or clean controls.
- No report emitted a finding, so this run did not exercise observed exact, partial, duplicate, unrelated, or false-positive finding behavior. Zero agreement numerators must be read alongside the 20 unattempted vulnerable cases.
- Strict precision is undefined because both exact detections and distinct findings are zero. Reporting it as 0% would conceal the zero denominator.
- Sampled peak RSS measures the direct supervised Bubblewrap process and can understate memory used by its scanner descendant. Runtime and memory values are local measurements, not portable performance guarantees.
- Phase 2, Phase 4, and Phase 7 use different corpora and contracts. Their scores must not be directly ranked. Historical Phase 1, Phase 2, Phase 4, and Phase 6 artifacts remain unchanged.
- The one-shot protocol prevents reruns, diagnosis against the hidden cases, or post-execution changes to adapters, matching, scoring, fixtures, expectations, taxonomy, evidence contract, or evaluator code. This protects the preregistered result but does not explain the external scanner's nonzero exits.
