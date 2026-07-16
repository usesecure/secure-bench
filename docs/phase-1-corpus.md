# Phase 1 Corpus and Provenance

## Scope

The Phase 1 corpus is an original, first-party set of 14 small JavaScript and TypeScript projects. Seven cases contain one declared invariant violation, and seven paired controls demonstrate a corresponding defensive pattern. The corpus exercises public security behavior, not Secure Engine implementation details.

The suite is intentionally small and synthetic. It establishes executable corpus contracts and a reproducible one-tool baseline; it does not estimate production detection quality, comparative quality, statistical confidence, or language-wide coverage.

## Coverage

| Pair | Vulnerable case | Control case | Public rule family | Defensive pattern |
|---|---|---|---|---|
| 1 | `phase1-001` | `phase1-002` | Command execution | Fixed executable and argument array with shell processing disabled |
| 2 | `phase1-003` | `phase1-004` | Raw SQL construction | Parameterized query |
| 3 | `phase1-005` | `phase1-006` | Filesystem boundary | Canonicalized path constrained to an approved root |
| 4 | `phase1-007` | `phase1-008` | Outbound request boundary | HTTPS requirement and fixed host allowlist |
| 5 | `phase1-009` | `phase1-010` | Redirect boundary | Explicit destination allowlist |
| 6 | `phase1-011` | `phase1-012` | Dynamic code execution | Fixed operation dispatch without runtime code generation |
| 7 | `phase1-013` | `phase1-014` | Authorization dominance | Dominating session, organization, and role guard before mutation |

The cases collectively use JavaScript, JSX, TypeScript, and TSX across Node.js, Express-style handlers, Next.js App Router handlers, and a Next.js Server Action.

## Authorship and license

Every project was authored for Secure Bench by the Secure Bench maintainers and is licensed under Apache-2.0. The suite manifest records origin, authors, license, revision, and modifications at both suite and case level. No Secure Engine fixture, private rule implementation, external vulnerable project, generated scanner output, or third-party corpus was copied.

## Scanner-visible boundary

Scanner-visible projects use only neutral `case-NNN`, `entry`, route, handler, and application names. Their paths, packages, declarations, variables, and comments are checked for outcome labels, rule-family names, invariant text, and common answer markers. The scanner receives an isolated copy of one case at a time.

Expected categories, invariants, source and sink constraints, evidence requirements, eligibility, and labels exist only in `fixtures/corpus-v1.toml`, outside every copied project. The runner does not pass the suite bytes, repository root, case identifier, expectations, configuration contents, or environment secrets to the child process.

## Integrity gates

Corpus validation enforces:

- exactly paired vulnerable and control coverage for all seven public families;
- presence of all four source forms and all three framework groups;
- declared eligibility rationale, authorship, SPDX license, and resource budgets;
- regular scanner-visible files only, with symlinks and special files rejected;
- file-count, per-file, and per-project size limits;
- portable repository-relative paths;
- answer-leakage checks over paths, comments, declarations, categories, and invariants;
- SHA-256 fingerprints for every case; and
- a deterministic aggregate corpus fingerprint ordered by case identifier.

The committed aggregate fingerprint is `9a32028a28d7c0396a630db8a2698a8977e173328578b1108f14603372e77761`.
