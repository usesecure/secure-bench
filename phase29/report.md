# Secure Bench Phase 29 — post-open recovery study

One inherited Secure Engine raw report was adapted without scanner retry; 335 remaining scanners were executed once. Scanner retries: 0.

| Scanner / lane | Completed | TP | FP | TN | FN | Precision | Recall | F1 |
|---|---:|---:|---:|---:|---:|---:|---:|---:|
| secure-engine-0.1.7-rc1 / native | 80 | 0 | 0 | 47 | 33 | null | null | null |
| opengrep-1.22.0 / capability-normalized | 112 | 40 | 32 | 24 | 16 | 0.555556 | 0.714286 | 0.625000 |
| semgrep-ce-1.170.0 / capability-normalized | 112 | 40 | 32 | 24 | 16 | 0.555556 | 0.714286 | 0.625000 |
