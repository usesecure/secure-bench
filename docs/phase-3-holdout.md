# Phase 3 Expanded Frozen Holdout

> **Retired in Phase 6:** This corpus completed its one-shot Phase 4 evaluation and is now disclosed as a public development and diagnostic corpus. It is no longer unseen and must not be used for future unbiased evaluation. The commitments and historical artifacts below remain immutable.

Phase 3 freezes an independent examination corpus before any scanner sees it. It contains 56 new cases: 28 vulnerable cases and 28 paired safe controls. Each of the seven taxonomy families has four pairs, with balanced JavaScript, JSX, TypeScript, and TSX coverage across Node.js, Express, Next.js App Router, and Next.js Server Action forms. The four structural strata are direct, helper-mediated, inter-file aliased, and control-flow-sensitive.

The cases were authored from the frozen neutral taxonomy, official MITRE CWE records, and public Node.js, Express, and Next.js platform contracts. Secure Engine source, binaries, rules, reports, aliases, and prior outcomes were excluded. Framework-mandated names and public API strings are the only syntax-level reuse exemptions; case identities, project names, routes, application declarations, application literals, and implementation shapes are independently checked against Phase 1.

Every vulnerable case has one exact source, sink, evidence shape, taxonomy coordinate, primary CWE, and rationale. Every control states the security property that blocks the paired behavior. A declared line replacement is the only source delta in each pair, and validation must reproduce the control from the vulnerable member and the vulnerable member from the control byte for byte.

The manifest commits every scanner-visible fixture, every complete case contract, an aggregate corpus hash, and a domain-separated Merkle root. The canonical append-only ledger starts in `sealed-not-executed` state. A future evaluator must reserve the single execution before invoking a scanner, keep network access disabled, create a commitment-bound result without replacing any existing file, and append one terminal ledger entry. Failed execution consumes the slot and cannot be presented as a clean result.

Scanner-visible files contain no labels, expected outcomes, taxonomy identifiers, CWE identifiers, matcher hints, host paths, credentials, or scanner-specific data. Terminal inspection reports counts and hashes only. Exact case details remain in the matcher-side manifest and should not be copied into public summaries.

Secure Engine development tasks, rule development, tuning, and any other scanner-development work must not inspect `holdout/phase-3/`. The same restriction should be applied to every analyzer that may later take the examination.

Phase 3 does not execute Secure Engine or any other scanner. It is an intentionally neutral foundation for a future one-shot examination. It is not a production benchmark, public ranking, scanner comparison, broad coverage claim, or evidence that Secure Engine or any other tool is superior.

## Public design sources

- MITRE CWE definitions 22, 78, 89, 95, 601, 862, and 918
- Node.js `child_process`, filesystem, path, and VM documentation
- Express 5 request and response API documentation
- Next.js App Router route-handler, data-security, authentication, and `use server` documentation

The exact versioned URLs are sorted and committed in the manifest.

## Verification

Run the aggregate-only validator:

```bash
cargo run --bin secure-bench -- holdout validate \
  --manifest holdout/phase-3/manifest.json \
  --taxonomy taxonomy/secure-bench-taxonomy-v1.json \
  --ledger holdout/phase-3/execution-ledger.jsonl
```

No command in the Phase 3 interface runs a scanner or scores a result.
