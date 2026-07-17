# Phase 9 orthogonal holdout v3

Phase 9 freezes a new first-party synthetic examination for future Secure Engine validation. It
defines the corpus, expected contracts, commitments, and genesis ledger only. No Secure Engine
binary or other scanner was inspected, built, installed, imported, modified, or executed.

This is an intentionally neutral foundation. It is not a production benchmark, scanner
comparison, public ranking, superiority claim, or claim of complete vulnerability coverage.

## Independence and evidence contract

Every fixture is original Phase 9 work. Validation rejects exact fixture and source hashes,
normalized source-shape duplicates, and trivial token-shingle variants against the Phase 1,
retired Phase 3, and executed Phase 5 corpora. No Secure Engine source, internal rule, test,
fixture, prompt, or private API informed the corpus.

Phase 9 reuses evidence-contract-v2 byte-for-byte. Its four source semantics, seven sink
semantics, exact/contained location rules, connected path requirements, effective barrier rules,
partial classification, and semantic duplicate policy already cover the Phase 9 examination.
Evidence contract v3 was therefore unnecessary.

## Corpus design

The corpus contains 112 pairs and 224 isolated cases. Every pair contains one vulnerable case and
one meaningful safe control under the same taxonomy family, framework, language, and topology.
The first/second orientation is counterbalanced within every category/framework/language cell.
Future scanner processes receive one fixture only, never its paired sibling or matcher-owned data.

| Dimension | Levels | Pairs per level | Cases per level |
|---|---:|---:|---:|
| Answer | vulnerable, safe control | 112 paired assignments | 112 each |
| Taxonomy family | 7 | 16 | 32 |
| Language | JavaScript, TypeScript | 56 | 112 |
| Framework | Node.js, Express, Next.js App Router, Server Actions | 28 | 56 |
| Topology | direct, helper-mediated, inter-file aliased, control-flow-sensitive | 28 | 56 |

All pairwise factor margins are exact: category/framework 4 pairs per cell,
category/language 8, category/topology 4, framework/language 14, framework/topology 7, and
language/topology 14. Because each assignment contributes both answers, framework, language,
topology, category, case position, and their declared pairwise intersections have zero answer
association by construction.

The seven frozen families remain SE1001 authorization dominance, SE1002 command execution,
SE1003 dynamic code execution, SE1004 filesystem boundary, SE1005 outbound request boundary,
SE1006 redirect boundary, and SE1007 SQL construction.

## Mutation and inverse requirements

Each pair has one declared mutation file and exact line ranges. The validator proves both
directions reproduce the other file byte-for-byte, all other files are identical, fragment hashes
match, and the changed fragments remain different after identifiers and literals are normalized.
Safe controls retain realistic source and operation structure while adding a terminating
authorization decision, fixed command mapping, non-executable operation mapping, canonical path
boundary, final URL policy, local redirect policy, or parameter binding as applicable.

This prevents controls from being empty stubs and prevents vulnerabilities from differing only by
renamed identifiers, string literals, comments, or filenames.

## Answer and scanner boundary

The manifest is matcher-owned data and is never part of a scanner fixture projection. Scanner
inputs exclude expectations, taxonomy, commitments, ledger, pair identity, sibling fixtures, and
answer-bearing environment or command data. Fixture paths, package names, declarations, and
comments are checked for expected labels and host paths. Public summaries contain aggregate
counts and commitments only; they never print case-level expected answers or source.

AI validation is disabled. Future scanner processes must run once per isolated case with network
blocked and append every outcome to the chained ledger. Phase 9 itself has no execution command.

## Frozen artifacts

| Artifact | SHA-256 |
|---|---|
| Aggregate corpus | `30f51f643da6d27c8c94758289ee77c937104d372b97f0de90d4d40ced56dbe2` |
| Contract Merkle root | `7c41259cb2bc36cdab2582ac9867df6a95c1fd59686315118f70c07fe5eedf6a` |
| Manifest | `136f92a3bbe324d8f0e3c49438b93aa4ef6eb09731998784feed0b6f75553a9f` |
| Genesis ledger | `edd48b4b70115db7c43d93d987003b62b025b5943c17d96b3dfd0262dbc69841` |
| Commitment index | `31c83b443c889e8f3dbc0ddea358f27d4ec990dae11a4138373ea9a6fb6e13b0` |
| Evidence contract v2 | `142c7f31c6c584cc808410130fa7db8451427e87504e72e64868c9cbc6564c42` |

These commitments freeze the examination; they are not evaluation results.

## Limitations

Synthetic balance does not establish prevalence, production exploitability, or coverage of every
JavaScript/TypeScript program shape. Pairwise balance does not imply every four-way factor
combination is present. A future result must report failures, safe-control flags, evidence quality,
and every denominator without ranking it directly against results from a different corpus.
