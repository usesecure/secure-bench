# Secure Bench Phase 4 Aggregate Record

This directory retains the one-shot Secure Engine 0.1.2 evaluation of the frozen Phase 3 holdout. The machine-readable JSON and append-only ledger are authoritative. This record discloses aggregate outcomes only; it does not disclose exact holdout source or matcher-side answers.

Phase 4 is an intentionally neutral research foundation. It is not a production benchmark, public ranking, scanner comparison, complete security assessment, or claim that Secure Engine or another tool is superior.

## Aggregate outcomes

| Measure | Result |
| --- | ---: |
| Vulnerable expectations | 28 |
| Exact canonical detections | 0 |
| Partial matches | 12 |
| Misses | 16 |
| Out of scope | 0 |
| Operationally not attempted | 0 |
| Safe controls flagged | 10 |
| Safe controls clean | 18 |
| Safe controls not attempted | 0 |
| Normalized findings | 32 |
| Duplicate findings | 0 |
| Finding-level precision | 0/32 (0.00%) |
| Expectation-level recall | 0/28 (0.00%) |
| F1 | 0.00% |

Partial evidence receives no exact-detection credit. A flagged safe control is reported separately from unmatched distinct findings, and an operational failure is never interpreted as a clean result.

## Agreement

| Dimension | Agreement |
| --- | ---: |
| Canonical taxonomy mapping | 7/28 (25.00%) |
| Category | 7/28 (25.00%) |
| Invariant | 7/28 (25.00%) |
| Primary CWE | 7/28 (25.00%) |
| Source | 0/28 (0.00%) |
| Sink | 12/28 (42.85%) |
| Ordered evidence path | 0/28 (0.00%) |

## Breakdowns

Each row is `exact / partial / missed` for four or seven vulnerable expectations, followed by `flagged / clean` controls. All groups had zero out-of-scope and zero not-attempted cases.

| Taxonomy family | Vulnerable | Controls |
| --- | ---: | ---: |
| Authorization dominance | 0 / 0 / 4 | 0 / 4 |
| Command execution | 0 / 2 / 2 | 2 / 2 |
| Dynamic code execution | 0 / 2 / 2 | 0 / 4 |
| Filesystem boundary | 0 / 2 / 2 | 2 / 2 |
| Outbound request boundary | 0 / 2 / 2 | 2 / 2 |
| Redirect boundary | 0 / 2 / 2 | 2 / 2 |
| SQL construction | 0 / 2 / 2 | 2 / 2 |

| Framework | Vulnerable | Controls |
| --- | ---: | ---: |
| Node.js | 0 / 0 / 7 | 0 / 7 |
| Express | 0 / 0 / 7 | 0 / 7 |
| Next.js App Router | 0 / 6 / 1 | 5 / 2 |
| Next.js Server Actions | 0 / 6 / 1 | 5 / 2 |

| Language | Vulnerable | Controls |
| --- | ---: | ---: |
| JavaScript | 0 / 0 / 7 | 0 / 7 |
| JSX | 0 / 0 / 7 | 0 / 7 |
| TypeScript | 0 / 6 / 1 | 5 / 2 |
| TSX | 0 / 6 / 1 | 5 / 2 |

| Topology | Vulnerable | Controls |
| --- | ---: | ---: |
| Direct | 0 / 0 / 7 | 0 / 7 |
| Helper-mediated | 0 / 0 / 7 | 0 / 7 |
| Inter-file aliased | 0 / 6 / 1 | 5 / 2 |
| Control-flow-sensitive | 0 / 6 / 1 | 5 / 2 |

## Execution and failure accounting

All 56 cases completed with retained, adapter-valid `secure-json-v1` reports: 22 reports contained findings and 34 were empty. There were zero runner failures, crashes, timeouts, malformed reports, unsupported schemas, missing reports, oversized reports, cancellations, or cases without a result. Some scanner processes used their documented nonzero findings exit convention; complete reports remained the source of result status.

The sum of per-case durations was 280 ms; end-to-end runner duration was 414 ms. Maximum sampled direct-process RSS was 442,368 bytes. Retained reports totaled 4,342,808 bytes. The deterministic semantic fingerprint is `b3b7d27ceabcd5774578a6623545cee8d592abf0046a8ec937297b4a9841cdb8`.

## Provenance

| Item | Value |
| --- | --- |
| External binary SHA-256 | `20e941f2f4633f0d1a62bd57d61d6969f5d251568f7abaff5a7a0fc8d5b31055` |
| Source RPM SHA-256 | `8d6ed234ad87cd422a8c53de08117454423241972caa272a4bbb8bb7282c2276` |
| Taxonomy artifact SHA-256 | `059fe22d7707cf8d17f2c1621fdae9819787a1958ba2ef0421eca4e4ec858452` |
| Taxonomy content hash | `22852bd7401020b315af11dfa2b60c0b46f78eb19f95079e6400d7b3bea3272c` |
| Manifest SHA-256 | `a7a2e47fa85c5fcda305e2c193b91216fd9df1c28fd52dd0179b588f83790da2` |
| Aggregate corpus SHA-256 | `28f4599c9711465a7cbbfe0ebc356e017a3bb6145bc77d57577b3b5d31790844` |
| Contract Merkle root | `fcfbe4f8d5dc0fc871ce55c1eac3e3d2618bcc76261bfa16bd4b1f98833c96e5` |
| Command | `scan {fixture} --format secure-json-v1 --output {report}` |
| Configuration SHA-256 | `e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855` |
| AI validation | Disabled; no provider, credentials, endpoint, or AI command |
| Isolation | Complete runner under `bwrap --unshare-net`; loopback only; outbound probe blocked |
| Host | Linux x86_64, kernel 7.1.3-200.fc44.x86_64, 16 logical CPUs, 16,673,927,168 bytes memory |
| Pre-execution contract SHA-256 | `acf053a550720e8b3f37093859bab3ae494f08f9e585fd5472f782a37c031ee9` |
| Run manifest SHA-256 | `44785c69d87fd293b35b9e5d59d02ec5cf3d5de050c01acf1a3b2a0df550c98a` |
| Case journal SHA-256 | `84dfd6fdbbbca11d4b1b14ecb947e0bd82b4a04655ae137a5e1530ba6ce6c2f0` |
| Retained report aggregate SHA-256 | `4dfee834691ee7743a1b2124cf4eb7d2a25e03de8fbd0c3977d650d38b86c456` |
| Result SHA-256 | `86fa3a373dbc6b7eb346ecaa84b86c1a1aef04bf7f05c807f3f3f6cfaa0b0911` |
| Completed ledger SHA-256 | `4153d6ef7a3728f0dd5c29a0782c919debc60b963d2e8c22865ce65b6c1d480c` |
| Artifact index SHA-256 | `891ffd0264590e04b3fc78b69e77ec9c2cf39a7d4b0a23bee9a14e0b8104a10d` |

## Historical interpretation and limitations

Phase 1 and Phase 2 remain immutable. Phase 2 and Phase 4 scores must not be directly ranked because their corpora differ. Taxonomy alignment, true exact detections, partial evidence, unmatched findings, flagged controls, and execution failures are distinct observations.

This one-shot result covers one supplied artifact, one synthetic 56-case holdout, seven taxonomy families, four framework strata, four languages, and four flow topologies. It does not establish production readiness, complete coverage, behavior on real applications, comparative quality, or superiority. Runtime and RSS are host- and sampling-dependent, and the retained reports reflect only the public deterministic scanner with AI disabled.

The pre-reservation mock test is intentionally defined against the genesis ledger committed in the frozen evaluator. Post-execution verification runs that test against a read-only projection of the exact genesis entry, while the actual three-entry completed ledger is validated separately and is never truncated, rewritten, or replaced. This preserves the pre-execution evaluator fingerprint and append-only evidence at the cost of requiring the documented lifecycle projection for the full post-execution test command.
