# Phase 30 Secure Engine exit-status evidence certification

Phase 30 is a **post-open evidence certification derived from Phase 28/29**. It starts no scanner,
runner, adapter, or case process and leaves every Phase 28/29 byte unchanged.

## Finding

The frozen public process policy certifies a normal nonzero exit with a complete, internally
error-free, adapter-valid findings report as `policy_exit_with_valid_findings_report`. All 32
Secure Engine exit-code-1 observations satisfy that contract. Phase 29's conservative operational
classification is superseded only for this exit-status semantic; its raw evidence is unchanged.

| Aggregate class | Count |
|---|---:|
| exit 0 + zero findings | 80 |
| exit 0 + findings | 0 |
| exit 1 + zero findings | 0 |
| exit 1 + findings | 32 |
| invalid raw/schema | 0 |
| engine errors/signals | 0 |

## Certified Secure Engine/native metrics

- TP 23, FP 9, TN 47, FN 33.
- Precision 0.718750, recall 0.410714, specificity 0.839286, F1 0.522727, balanced accuracy 0.625000.
- Completed 112/112; failed 0; scanner retries 0.

OpenGrep and Semgrep normalized results are preserved exactly from Phase 29. Native and normalized
lanes remain separate, and no direct winner is declared across those lanes.
