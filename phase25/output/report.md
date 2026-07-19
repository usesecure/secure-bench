# Phase 25 Semgrep post-open normalized recovery

Phase 25 is additive. It neither replaces nor retries the 112 historical Phase 22 Semgrep failures.

## Phase 25 Semgrep lane

| Phase | Scanner | Lane | Environment | State | Attempts | Completed | Failed | Timeout | Malformed | Unavailable | TP | FP | TN | FN | Precision | Recall | Specificity | F1 | Balanced accuracy |
|---:|---|---|---|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| 25 | semgrep-ce | capability-normalized | phase23-stack-bounded-v1 | completed | 112 | 112 | 0 | 0 | 0 | 0 | 56 | 16 | 40 | 0 | 7/9 (0.777778) | 1/1 (1.000000) | 5/7 (0.714286) | 7/8 (0.875000) | 6/7 (0.857143) |

## Paired normalized comparison

State: `paired-complete`. Phase 22 OpenGrep/normalized is compared only with Phase 25 Semgrep/normalized. Case agreements: `112`; case disagreements: `0`; pair agreements: `56`; pair disagreements: `0`; OpenGrep-only correct: `0`; Semgrep-only correct: `0`; both incorrect: `16`.

## Breakdowns

Canonical case and pair decisions are in `results.json`; all requested family, framework, source-format, topology, adversarial-variant, and vulnerable/control metrics with exact numerators and denominators are in `strata.json`. Paired disagreements are in `comparison.json` and `disagreements.json`.

## Validity boundary

No native or Secure Engine result is merged with normalized metrics, and no overall three-scanner winner is declared. Phase 25 cannot restore blind-holdout or one-shot validity.
