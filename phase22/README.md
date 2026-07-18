# Secure Bench Phase 22

Phase 22 is exclusively a **post-open recovery study** for the two eligible
capability-normalized scanner lanes. It does not repeat, repair, replace, or
reinterpret Phase 20.

The frozen execution population is exactly 224 case attempts:

- OpenGrep 1.22.0 / capability-normalized: 112;
- Semgrep CE 1.170.0 / capability-normalized: 112.

Each `(scanner, case)` key is executed once with zero retries under the
`phase21-null-device-v1` sandbox. Secure Engine is never executed by Phase 22.
Native and capability-normalized metrics are never combined.

Lifecycle commands are intentionally separated:

```text
secure-bench-phase22 prepare .
secure-bench-phase22 preflight .
secure-bench-phase22 execute-once .
secure-bench-phase22 verify .
```

`prepare` derives opaque case IDs only from immutable Phase 20 results and
freezes the plan and contract without opening Phase 19 cases. `preflight`
verifies Phases 19–21 and runs bounded synthetic canaries only. `execute-once`
creates the irreversible corpus-open marker before reading the Phase 19
manifest and rejects any existing output. `verify` never starts a scanner.

The sealed deliverable contains the frozen contract and canonical 224-attempt
plan, the irreversible `CORPUS_OPENED.json` marker, a hash-chained execution
ledger, per-attempt raw stdout/stderr/report/metadata evidence, canonical
machine-readable results, stratified and paired comparison/disagreement
tables, failure analysis, a readable report, an explicit limitations document,
independent scanner-free verification, provenance, and exhaustive
`SHA256SUMS`. Every artifact belongs only to this post-open recovery study.
