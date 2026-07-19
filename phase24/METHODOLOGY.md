# Phase 24 methodology

Phase 24 is an additive post-open recovery study. It executes only Semgrep CE
1.170.0 in the frozen capability-normalized lane over the 112 already-open
Phase 19 cases. Each opaque `(scanner, case)` key is frozen before corpus access
and executed exactly once with zero retries.

The Phase 23 corrected environment is used verbatim: network and PID namespaces,
fresh procfs, read-only root, private temporary paths, `/dev/null`, cleared
environment, `RLIMIT_AS=4 GiB`, `RLIMIT_NPROC=64`, and both stack limits fixed at
8 MiB. Scanner, wheel closure, dependency lock, ruleset, adapter, scoring
methodology, corpus, expectations, and case IDs remain frozen.

Raw output is preserved before strict adaptation. Operational failures remain
explicit and are never imputed. Detection metrics are emitted only if all 112
Semgrep attempts complete with adapter-valid evidence. The paired comparison
uses only OpenGrep capability-normalized Phase 22 and Semgrep
capability-normalized Phase 24. Native/Secure Engine evidence is excluded.

Each attempt preserves the exact command and cleared environment, stdout,
stderr, raw JSON when produced, exit code, terminating signal, wall duration,
GNU time output, and a wrapper-captured record of effective limits,
environment, and mount table. Every artifact is hashed, every observation is
committed to a contiguous hash-chained ledger, and no failed state receives a
numeric finding count.

Scoring is recalculated from the preserved raw reports. It includes exact
TP/FP/TN/FN counts; precision, recall, specificity, F1, and balanced accuracy
with numerator and denominator; case and vulnerable/control pair decisions;
and family, framework, source-format, topology, adversarial-variant, and
classification strata. The comparison reports case and pair agreements and
disagreements and identifies both phase-specific execution environments.

The Rust verifier and a separately implemented Python verifier are
scanner-free. The normalized comparison is labeled complete only when all 112
attempts complete and independent recalculation agrees with the canonical
results.

This study cannot restore blindness or one-shot validity and does not replace,
retry, repair, or reinterpret the 112 historical Phase 22 Semgrep failures.
