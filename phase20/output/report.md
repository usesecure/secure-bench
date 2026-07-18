# Phase 20 neutral multi-scanner comparison

Native and capability-normalized lanes are reported independently. Unsupported states are not zeros.

| Scanner | Lane | State | TP | FP | TN | FN | Precision | Recall | Specificity | F1 | Balanced accuracy | Attempts | Time ms |
|---|---|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| opengrep | capability-normalized | Failed | — | — | — | — | Unavailable | Unavailable | Unavailable | Unavailable | Unavailable | 112 | 153765 |
| secure-engine | capability-normalized | Unsupported | — | — | — | — | Unavailable | Unavailable | Unavailable | Unavailable | Unavailable | 0 | 0 |
| semgrep-ce | capability-normalized | Failed | — | — | — | — | Unavailable | Unavailable | Unavailable | Unavailable | Unavailable | 112 | 115590 |
| opengrep | native | Unsupported | — | — | — | — | Unavailable | Unavailable | Unavailable | Unavailable | Unavailable | 0 | 0 |
| secure-engine | native | Completed | 23 | 8 | 48 | 33 | 0.741935 (23/31) | 0.410714 (23/56) | 0.857143 (48/56) | 0.528736 (46/87) | 0.633929 (3976/6272) | 112 | 2041 |
| semgrep-ce | native | Unsupported | — | — | — | — | Unavailable | Unavailable | Unavailable | Unavailable | Unavailable | 0 | 0 |

## Limitations

- Results describe only the frozen Phase 19 holdout and exact pinned artifacts.
- Cross-lane quality deltas are intentionally unavailable.
- Unsupported native or normalized capabilities receive no score and no imputed denominator.
- Timing is descriptive process evidence and is not part of detection quality.
