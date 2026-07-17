# Phase 5 Orthogonal Holdout and Evidence Contract v2

Phase 5 freezes a new, first-party synthetic examination independently of all scanner outcomes. It is an intentionally neutral foundation for a future one-shot evaluation. It is not a production benchmark, scanner comparison, public ranking, coverage guarantee, or evidence that Secure Engine or any other analyzer is superior.

No scanner was executed, inspected, imported, built, installed, updated, debugged, or consulted while Phase 5 was designed. Phase 4 outcomes, misses, partial matches, flagged controls, case identifiers, report wording, and scanner documentation were excluded. Phase 0–4 artifacts retain their historical meaning and bytes; Phase 3 remains sealed.

## Preregistered design

The corpus contains 56 vulnerable/control pairs, 112 cases total, with eight pairs in each frozen taxonomy family. Every framework has 14 pairs, every language has 28 pairs, and every topology has 14 pairs. Each framework/language and topology/language cell has seven pairs. Framework/topology cells contain either three or four pairs, so their maximum cell-count difference is one.

The deterministic schedule rotates all seven taxonomy families through every framework/language cell. Framework/language and topology/language association are exactly zero. The committed manifest records complete contingency tables, integer-scaled Pearson chi-square values, and Cramer's V. No single framework, language, topology, filename, identifier, route, or literal deterministically identifies a label or taxonomy family.

Factors are:

- Node.js HTTP, Express, Next.js App Router Route Handlers, and Next.js Server Actions;
- JavaScript and TypeScript; and
- direct, helper-mediated, inter-file aliased, and control-flow-sensitive data flow.

Each pair changes one reversible semantic fragment. The vulnerable member violates one named invariant; the control adds structural separation, destination or path confinement, a terminating guard, or a principal/action/resource authorization decision. Validation proves both mutation directions and rejects drift in every other pair file.

Design inputs are limited to taxonomy 1.0.0, official [MITRE CWE definitions](https://cwe.mitre.org/data/index.html), [Node.js HTTP documentation](https://nodejs.org/dist/latest/docs/api/http.html), [Node.js URL documentation](https://nodejs.org/docs/latest/api/url.html), [Express API documentation](https://expressjs.com/en/4x/api/), and official Next.js documentation for [Route Handlers](https://nextjs.org/docs/app/getting-started/route-handlers), [Server Functions and Actions](https://nextjs.org/docs/app/getting-started/updating-data), and [authorization](https://nextjs.org/docs/app/guides/authentication).

## Evidence contract v2

Evidence contract v2 matches canonical taxonomy coordinates, semantic source and sink kinds, portable spans, an ordered connected path, and semantic barrier effects. Exact spans and bounded bidirectional containment are equivalent. A report may compress only expectation nodes explicitly marked summarizable; source and sink semantics and spans remain mandatory.

Effective sanitization, policy confinement, terminating rejection, and operation-bound authorization invalidate a claimed vulnerable path. An unresolved call or explicit uncertainty downgrades an otherwise exact path to partial status, which receives no detection credit. Wrong endpoints, order, connectivity, or taxonomy are no-match outcomes.

Finding fingerprints contain only canonical taxonomy, semantic roles and effects, normalized spans, connectivity, barrier state, and uncertainty state. Scanner rule identifiers, tool identity, prose, and variable names cannot grant credit or distinguish duplicates. The committed conformance suite uses synthetic reports only and includes canonical, equivalent-span, compressed-path, wrong-endpoint, wrong-order, disconnected, taxonomy-mismatch, barrier, unresolved, and uncertain cases.

## Commitments and future protocol

Every scanner-visible file has a SHA-256 commitment. Case contracts bind kind, fixture, expected evidence or safe-control property, and provenance. The manifest binds the aggregate corpus SHA-256, contract Merkle root, schedule, evidence contract, evaluator, historical hashes, and creation attestation. A separate non-circular index binds the final manifest, contract tests, genesis ledger, and every evaluator file.

The append-only ledger currently contains only `holdout_frozen`. A future evaluation must reserve the one-shot slot before execution, block network access for every scanner process, keep AI disabled without providers, credentials, or endpoints, create a new result, and account explicitly for success, failure, timeout, crash, malformed report, and missing result. Phase 5 has no execution command.

Scanner-visible copies contain no expected answers, category or invariant coordinates, CWE labels, holdout labels, scanner aliases, or tool identity. Validation performs aggregate token-shingle, syntax-shape proxy, and semantic-metadata overlap checks against earlier corpora. Only aggregate similarity measurements are public.

## Verification

```bash
cargo run --bin secure-bench -- phase5 validate
cargo run --bin secure-bench -- phase5 inspect
cargo run --bin secure-bench -- phase5 contract-test
```

The validator checks schemas, taxonomy binding, schedule balance, mutation inverses, source shape, leakage, fixture and case hashes, aggregate corpus hash, Merkle root, evaluator hashes, synthetic contract vectors, historical bindings, overlap metrics, and the genesis ledger chain. These commands never execute a scanner.

## Limitations

The cases are synthetic and cover only seven invariant families, four framework forms, two languages, and four topology classes. The source-shape validator is a deterministic structural check, not a complete JavaScript or TypeScript compiler. Overlap checks are conservative proxies, not proof of semantic novelty. Evidence contract v2 has been tested only against committed synthetic canonical and near-miss findings. No scanner quality, runtime, production readiness, real-project coverage, ranking, or comparative conclusion can be drawn until a separately authorized one-shot evaluation occurs, and even then the narrow synthetic scope must remain explicit.
