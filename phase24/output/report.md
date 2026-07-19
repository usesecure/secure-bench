# Phase 24 Semgrep post-open normalized recovery

Phase 24 is additive. It neither replaces nor retries the 112 historical Phase 22 Semgrep failures.

## Phase 24 Semgrep lane

| Phase | Scanner | Lane | Environment | State | Attempts | Completed | Failed | Timeout | Malformed | Unavailable | TP | FP | TN | FN | Precision | Recall | Specificity | F1 | Balanced accuracy |
|---:|---|---|---|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| 24 | semgrep-ce | capability-normalized | phase23-stack-bounded-v1 | failed | 112 | 0 | 112 | 0 | 0 | 0 | — | — | — | — | unavailable | unavailable | unavailable | unavailable | unavailable |

## Paired normalized comparison

State: `unavailable`. Phase 22 OpenGrep/normalized is compared only with Phase 24 Semgrep/normalized. Case agreements: `unavailable`; case disagreements: `unavailable`; pair agreements: `unavailable`; pair disagreements: `unavailable`; OpenGrep-only correct: `unavailable`; Semgrep-only correct: `unavailable`; both incorrect: `unavailable`.

## Breakdowns

Canonical case and pair decisions are in `results.json`; all requested family, framework, source-format, topology, adversarial-variant, and vulnerable/control metrics with exact numerators and denominators are in `strata.json`. Paired disagreements are in `comparison.json` and `disagreements.json`.

## Validity boundary

No native or Secure Engine result is merged with normalized metrics, and no overall three-scanner winner is declared. Phase 24 cannot restore blind-holdout or one-shot validity.
