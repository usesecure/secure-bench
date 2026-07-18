# Phase 22 limitations and validity boundary

Phase 22 is exclusively a **post-open recovery study**. The Phase 19 corpus ceased to be globally blind when Phase 20 opened it, so these results cannot restore one-shot or blind-holdout validity and cannot replace or reinterpret the 224 historical Phase 20 normalized-lane failures.

The infrastructure correction changes only sandbox operability. The corpus, manifest, expectations, rules, adapters, scoring methodology, scanner versions, and lane definitions remain frozen. Secure Engine/native was not executed in Phase 22. Native and capability-normalized evidence is not merged, cross-phase metrics are not combined, and no overall three-scanner or cross-lane winner is declared.

Operational failures remain explicit states and are never imputed as zero findings. Complete-lane detection metrics exist only when all 112 attempts for that scanner have adapter-valid evidence. Performance is descriptive and separate from detection quality.

## Post-open verifier repair

After all 224 scanner attempts completed, the scanner-free verifier was repaired to accept the safe repository-relative bind sources recorded by the frozen runner. No scanner was started, no attempt or ledger entry was changed, and no retry occurred. See `verifier-repair.json`.
