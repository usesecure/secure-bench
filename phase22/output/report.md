# Phase 22 post-open normalized recovery study

Phase 22 is not a repetition or retroactive correction of Phase 20. It does not restore one-shot or blind-holdout validity.

## Normalized recovery lanes

| Scanner | State | Attempts | Completed | Failed | Timeouts | Malformed | Unsupported | Unavailable | TP | FP | TN | FN | Precision | Recall | Specificity | F1 | Balanced accuracy |
|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| opengrep | completed | 112 | 112 | 0 | 0 | 0 | 0 | 0 | 56 | 16 | 40 | 0 | 7/9 (0.777778) | 1/1 (1.000000) | 5/7 (0.714286) | 7/8 (0.875000) | 6/7 (0.857143) |
| semgrep-ce | failed | 112 | 0 | 112 | 0 | 0 | 0 | 0 | — | — | — | — | unavailable | unavailable | unavailable | unavailable | unavailable |

## Performance (separate from detection quality)

| Scanner | Total ms | Min ms | Median ms | P95 ms | Max ms |
|---|---:|---:|---:|---:|---:|
| opengrep | 187480 | 1600 | 1660 | 1801 | 1936 |
| semgrep-ce | 816202 | 6808 | 7278 | 7849 | 8200 |

## Paired normalized comparison

State: `unavailable`. Agreements: `unavailable`. OpenGrep-only correct: `unavailable`. Semgrep-only correct: `unavailable`. Both incorrect: `unavailable`. Disagreements: `0`.

### Absolute metric differences

| Metric | Absolute difference |
|---|---:|
| _unavailable_ | — |

### Disagreement table

| Case | Expected | OpenGrep positive | Semgrep positive | OpenGrep findings | Semgrep findings | OpenGrep outcome | Semgrep outcome | Family | Framework | Format | Topology | Variant |
|---|---|---:|---:|---:|---:|---|---|---|---|---|---|---|
| _none_ | — | — | — | — | — | — | — | — | — | — | — | — |

## Stratified detection quality

| Scanner | Dimension | Value | TP | FP | TN | FN | Precision | Recall | Specificity | F1 | Balanced accuracy |
|---|---|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| opengrep | family | SE1001 | 8 | 0 | 8 | 0 | 1/1 (1.000000) | 1/1 (1.000000) | 1/1 (1.000000) | 1/1 (1.000000) | 1/1 (1.000000) |
| opengrep | family | SE1002 | 8 | 0 | 8 | 0 | 1/1 (1.000000) | 1/1 (1.000000) | 1/1 (1.000000) | 1/1 (1.000000) | 1/1 (1.000000) |
| opengrep | family | SE1003 | 8 | 0 | 8 | 0 | 1/1 (1.000000) | 1/1 (1.000000) | 1/1 (1.000000) | 1/1 (1.000000) | 1/1 (1.000000) |
| opengrep | family | SE1004 | 8 | 0 | 8 | 0 | 1/1 (1.000000) | 1/1 (1.000000) | 1/1 (1.000000) | 1/1 (1.000000) | 1/1 (1.000000) |
| opengrep | family | SE1005 | 8 | 8 | 0 | 0 | 1/2 (0.500000) | 1/1 (1.000000) | 0/1 (0.000000) | 2/3 (0.666667) | 1/2 (0.500000) |
| opengrep | family | SE1006 | 8 | 8 | 0 | 0 | 1/2 (0.500000) | 1/1 (1.000000) | 0/1 (0.000000) | 2/3 (0.666667) | 1/2 (0.500000) |
| opengrep | family | SE1007 | 8 | 0 | 8 | 0 | 1/1 (1.000000) | 1/1 (1.000000) | 1/1 (1.000000) | 1/1 (1.000000) | 1/1 (1.000000) |
| opengrep | framework | express | 14 | 4 | 10 | 0 | 7/9 (0.777778) | 1/1 (1.000000) | 5/7 (0.714286) | 7/8 (0.875000) | 6/7 (0.857143) |
| opengrep | framework | next-app-router | 14 | 4 | 10 | 0 | 7/9 (0.777778) | 1/1 (1.000000) | 5/7 (0.714286) | 7/8 (0.875000) | 6/7 (0.857143) |
| opengrep | framework | node | 14 | 4 | 10 | 0 | 7/9 (0.777778) | 1/1 (1.000000) | 5/7 (0.714286) | 7/8 (0.875000) | 6/7 (0.857143) |
| opengrep | framework | server-actions | 14 | 4 | 10 | 0 | 7/9 (0.777778) | 1/1 (1.000000) | 5/7 (0.714286) | 7/8 (0.875000) | 6/7 (0.857143) |
| opengrep | source_format | javascript | 14 | 4 | 10 | 0 | 7/9 (0.777778) | 1/1 (1.000000) | 5/7 (0.714286) | 7/8 (0.875000) | 6/7 (0.857143) |
| opengrep | source_format | jsx | 14 | 4 | 10 | 0 | 7/9 (0.777778) | 1/1 (1.000000) | 5/7 (0.714286) | 7/8 (0.875000) | 6/7 (0.857143) |
| opengrep | source_format | tsx | 14 | 4 | 10 | 0 | 7/9 (0.777778) | 1/1 (1.000000) | 5/7 (0.714286) | 7/8 (0.875000) | 6/7 (0.857143) |
| opengrep | source_format | typescript | 14 | 4 | 10 | 0 | 7/9 (0.777778) | 1/1 (1.000000) | 5/7 (0.714286) | 7/8 (0.875000) | 6/7 (0.857143) |
| opengrep | topology | control-flow-sensitive | 14 | 4 | 10 | 0 | 7/9 (0.777778) | 1/1 (1.000000) | 5/7 (0.714286) | 7/8 (0.875000) | 6/7 (0.857143) |
| opengrep | topology | direct | 14 | 4 | 10 | 0 | 7/9 (0.777778) | 1/1 (1.000000) | 5/7 (0.714286) | 7/8 (0.875000) | 6/7 (0.857143) |
| opengrep | topology | helper-mediated | 14 | 4 | 10 | 0 | 7/9 (0.777778) | 1/1 (1.000000) | 5/7 (0.714286) | 7/8 (0.875000) | 6/7 (0.857143) |
| opengrep | topology | inter-file-aliased | 14 | 4 | 10 | 0 | 7/9 (0.777778) | 1/1 (1.000000) | 5/7 (0.714286) | 7/8 (0.875000) | 6/7 (0.857143) |
| opengrep | adversarial_variant | aliases | 1 | 1 | 0 | 0 | 1/2 (0.500000) | 1/1 (1.000000) | 0/1 (0.000000) | 2/3 (0.666667) | 1/2 (0.500000) |
| opengrep | adversarial_variant | ambiguous-helpers | 1 | 0 | 1 | 0 | 1/1 (1.000000) | 1/1 (1.000000) | 1/1 (1.000000) | 1/1 (1.000000) | 1/1 (1.000000) |
| opengrep | adversarial_variant | blocklists | 1 | 0 | 1 | 0 | 1/1 (1.000000) | 1/1 (1.000000) | 1/1 (1.000000) | 1/1 (1.000000) | 1/1 (1.000000) |
| opengrep | adversarial_variant | caught-exceptions | 1 | 1 | 0 | 0 | 1/2 (0.500000) | 1/1 (1.000000) | 0/1 (0.000000) | 2/3 (0.666667) | 1/2 (0.500000) |
| opengrep | adversarial_variant | destructuring | 1 | 1 | 0 | 0 | 1/2 (0.500000) | 1/1 (1.000000) | 0/1 (0.000000) | 2/3 (0.666667) | 1/2 (0.500000) |
| opengrep | adversarial_variant | misleading-names-comments | 1 | 1 | 0 | 0 | 1/2 (0.500000) | 1/1 (1.000000) | 0/1 (0.000000) | 2/3 (0.666667) | 1/2 (0.500000) |
| opengrep | adversarial_variant | mutable-allowlists | 1 | 1 | 0 | 0 | 1/2 (0.500000) | 1/1 (1.000000) | 0/1 (0.000000) | 2/3 (0.666667) | 1/2 (0.500000) |
| opengrep | adversarial_variant | non-dominating-guards | 1 | 0 | 1 | 0 | 1/1 (1.000000) | 1/1 (1.000000) | 1/1 (1.000000) | 1/1 (1.000000) | 1/1 (1.000000) |
| opengrep | adversarial_variant | none | 46 | 9 | 37 | 0 | 46/55 (0.836364) | 1/1 (1.000000) | 37/46 (0.804348) | 92/101 (0.910891) | 83/92 (0.902174) |
| opengrep | adversarial_variant | suffix-tricks | 1 | 1 | 0 | 0 | 1/2 (0.500000) | 1/1 (1.000000) | 0/1 (0.000000) | 2/3 (0.666667) | 1/2 (0.500000) |
| opengrep | adversarial_variant | wrappers | 1 | 1 | 0 | 0 | 1/2 (0.500000) | 1/1 (1.000000) | 0/1 (0.000000) | 2/3 (0.666667) | 1/2 (0.500000) |
| opengrep | classification | control | 0 | 16 | 40 | 0 | 0/1 (0.000000) | unavailable | 5/7 (0.714286) | 0/1 (0.000000) | unavailable |
| opengrep | classification | vulnerable | 56 | 0 | 0 | 0 | 1/1 (1.000000) | 1/1 (1.000000) | unavailable | 1/1 (1.000000) | unavailable |

## Pair results

| Scanner | Pair | Vulnerable case | Control case | Vulnerable flagged | Control flagged | Exact pair |
|---|---|---|---|---:|---:|---:|
| opengrep | pair-p19-0001 | case-p19-0001 | case-p19-0002 | true | true | false |
| opengrep | pair-p19-0002 | case-p19-0004 | case-p19-0003 | true | true | false |
| opengrep | pair-p19-0003 | case-p19-0005 | case-p19-0006 | true | true | false |
| opengrep | pair-p19-0004 | case-p19-0008 | case-p19-0007 | true | true | false |
| opengrep | pair-p19-0005 | case-p19-0009 | case-p19-0010 | true | false | true |
| opengrep | pair-p19-0006 | case-p19-0012 | case-p19-0011 | true | true | false |
| opengrep | pair-p19-0007 | case-p19-0013 | case-p19-0014 | true | false | true |
| opengrep | pair-p19-0008 | case-p19-0016 | case-p19-0015 | true | true | false |
| opengrep | pair-p19-0009 | case-p19-0017 | case-p19-0018 | true | false | true |
| opengrep | pair-p19-0010 | case-p19-0020 | case-p19-0019 | true | false | true |
| opengrep | pair-p19-0011 | case-p19-0021 | case-p19-0022 | true | false | true |
| opengrep | pair-p19-0012 | case-p19-0024 | case-p19-0023 | true | false | true |
| opengrep | pair-p19-0013 | case-p19-0025 | case-p19-0026 | true | true | false |
| opengrep | pair-p19-0014 | case-p19-0028 | case-p19-0027 | true | false | true |
| opengrep | pair-p19-0015 | case-p19-0029 | case-p19-0030 | true | true | false |
| opengrep | pair-p19-0016 | case-p19-0032 | case-p19-0031 | true | true | false |
| opengrep | pair-p19-0017 | case-p19-0033 | case-p19-0034 | true | false | true |
| opengrep | pair-p19-0018 | case-p19-0036 | case-p19-0035 | true | false | true |
| opengrep | pair-p19-0019 | case-p19-0037 | case-p19-0038 | true | true | false |
| opengrep | pair-p19-0020 | case-p19-0040 | case-p19-0039 | true | false | true |
| opengrep | pair-p19-0021 | case-p19-0041 | case-p19-0042 | true | false | true |
| opengrep | pair-p19-0022 | case-p19-0044 | case-p19-0043 | true | true | false |
| opengrep | pair-p19-0023 | case-p19-0045 | case-p19-0046 | true | false | true |
| opengrep | pair-p19-0024 | case-p19-0048 | case-p19-0047 | true | false | true |
| opengrep | pair-p19-0025 | case-p19-0049 | case-p19-0050 | true | false | true |
| opengrep | pair-p19-0026 | case-p19-0052 | case-p19-0051 | true | true | false |
| opengrep | pair-p19-0027 | case-p19-0053 | case-p19-0054 | true | true | false |
| opengrep | pair-p19-0028 | case-p19-0056 | case-p19-0055 | true | false | true |
| opengrep | pair-p19-0029 | case-p19-0057 | case-p19-0058 | true | false | true |
| opengrep | pair-p19-0030 | case-p19-0060 | case-p19-0059 | true | false | true |
| opengrep | pair-p19-0031 | case-p19-0061 | case-p19-0062 | true | false | true |
| opengrep | pair-p19-0032 | case-p19-0064 | case-p19-0063 | true | false | true |
| opengrep | pair-p19-0033 | case-p19-0065 | case-p19-0066 | true | false | true |
| opengrep | pair-p19-0034 | case-p19-0068 | case-p19-0067 | true | false | true |
| opengrep | pair-p19-0035 | case-p19-0069 | case-p19-0070 | true | true | false |
| opengrep | pair-p19-0036 | case-p19-0072 | case-p19-0071 | true | false | true |
| opengrep | pair-p19-0037 | case-p19-0073 | case-p19-0074 | true | false | true |
| opengrep | pair-p19-0038 | case-p19-0076 | case-p19-0075 | true | false | true |
| opengrep | pair-p19-0039 | case-p19-0077 | case-p19-0078 | true | false | true |
| opengrep | pair-p19-0040 | case-p19-0080 | case-p19-0079 | true | false | true |
| opengrep | pair-p19-0041 | case-p19-0081 | case-p19-0082 | true | false | true |
| opengrep | pair-p19-0042 | case-p19-0084 | case-p19-0083 | true | false | true |
| opengrep | pair-p19-0043 | case-p19-0085 | case-p19-0086 | true | false | true |
| opengrep | pair-p19-0044 | case-p19-0088 | case-p19-0087 | true | false | true |
| opengrep | pair-p19-0045 | case-p19-0089 | case-p19-0090 | true | true | false |
| opengrep | pair-p19-0046 | case-p19-0092 | case-p19-0091 | true | false | true |
| opengrep | pair-p19-0047 | case-p19-0093 | case-p19-0094 | true | false | true |
| opengrep | pair-p19-0048 | case-p19-0096 | case-p19-0095 | true | false | true |
| opengrep | pair-p19-0049 | case-p19-0097 | case-p19-0098 | true | false | true |
| opengrep | pair-p19-0050 | case-p19-0100 | case-p19-0099 | true | false | true |
| opengrep | pair-p19-0051 | case-p19-0101 | case-p19-0102 | true | false | true |
| opengrep | pair-p19-0052 | case-p19-0104 | case-p19-0103 | true | false | true |
| opengrep | pair-p19-0053 | case-p19-0105 | case-p19-0106 | true | false | true |
| opengrep | pair-p19-0054 | case-p19-0108 | case-p19-0107 | true | false | true |
| opengrep | pair-p19-0055 | case-p19-0109 | case-p19-0110 | true | true | false |
| opengrep | pair-p19-0056 | case-p19-0112 | case-p19-0111 | true | false | true |

## Case results

| Scanner | Case | Pair | Expected | Findings | Positive | Outcome | Family | Framework | Format | Topology | Variant |
|---|---|---|---|---:|---:|---|---|---|---|---|---|
| opengrep | case-p19-0001 | pair-p19-0001 | vulnerable | 1 | true | tp | SE1005 | server-actions | jsx | direct | misleading-names-comments |
| opengrep | case-p19-0002 | pair-p19-0001 | control | 1 | true | fp | SE1005 | server-actions | jsx | direct | misleading-names-comments |
| opengrep | case-p19-0003 | pair-p19-0002 | control | 1 | true | fp | SE1006 | next-app-router | typescript | control-flow-sensitive | aliases |
| opengrep | case-p19-0004 | pair-p19-0002 | vulnerable | 1 | true | tp | SE1006 | next-app-router | typescript | control-flow-sensitive | aliases |
| opengrep | case-p19-0005 | pair-p19-0003 | vulnerable | 1 | true | tp | SE1005 | node | typescript | direct | destructuring |
| opengrep | case-p19-0006 | pair-p19-0003 | control | 1 | true | fp | SE1005 | node | typescript | direct | destructuring |
| opengrep | case-p19-0007 | pair-p19-0004 | control | 1 | true | fp | SE1005 | next-app-router | tsx | control-flow-sensitive | wrappers |
| opengrep | case-p19-0008 | pair-p19-0004 | vulnerable | 1 | true | tp | SE1005 | next-app-router | tsx | control-flow-sensitive | wrappers |
| opengrep | case-p19-0009 | pair-p19-0005 | vulnerable | 1 | true | tp | SE1003 | express | tsx | inter-file-aliased | blocklists |
| opengrep | case-p19-0010 | pair-p19-0005 | control | 0 | false | tn | SE1003 | express | tsx | inter-file-aliased | blocklists |
| opengrep | case-p19-0011 | pair-p19-0006 | control | 1 | true | fp | SE1006 | express | tsx | direct | suffix-tricks |
| opengrep | case-p19-0012 | pair-p19-0006 | vulnerable | 1 | true | tp | SE1006 | express | tsx | direct | suffix-tricks |
| opengrep | case-p19-0013 | pair-p19-0007 | vulnerable | 1 | true | tp | SE1007 | node | tsx | inter-file-aliased | non-dominating-guards |
| opengrep | case-p19-0014 | pair-p19-0007 | control | 0 | false | tn | SE1007 | node | tsx | inter-file-aliased | non-dominating-guards |
| opengrep | case-p19-0015 | pair-p19-0008 | control | 1 | true | fp | SE1006 | node | javascript | control-flow-sensitive | caught-exceptions |
| opengrep | case-p19-0016 | pair-p19-0008 | vulnerable | 1 | true | tp | SE1006 | node | javascript | control-flow-sensitive | caught-exceptions |
| opengrep | case-p19-0017 | pair-p19-0009 | vulnerable | 1 | true | tp | SE1003 | server-actions | jsx | control-flow-sensitive | none |
| opengrep | case-p19-0018 | pair-p19-0009 | control | 0 | false | tn | SE1003 | server-actions | jsx | control-flow-sensitive | none |
| opengrep | case-p19-0019 | pair-p19-0010 | control | 0 | false | tn | SE1002 | node | typescript | inter-file-aliased | ambiguous-helpers |
| opengrep | case-p19-0020 | pair-p19-0010 | vulnerable | 1 | true | tp | SE1002 | node | typescript | inter-file-aliased | ambiguous-helpers |
| opengrep | case-p19-0021 | pair-p19-0011 | vulnerable | 1 | true | tp | SE1001 | express | tsx | control-flow-sensitive | none |
| opengrep | case-p19-0022 | pair-p19-0011 | control | 0 | false | tn | SE1001 | express | tsx | control-flow-sensitive | none |
| opengrep | case-p19-0023 | pair-p19-0012 | control | 0 | false | tn | SE1007 | server-actions | typescript | direct | none |
| opengrep | case-p19-0024 | pair-p19-0012 | vulnerable | 1 | true | tp | SE1007 | server-actions | typescript | direct | none |
| opengrep | case-p19-0025 | pair-p19-0013 | vulnerable | 1 | true | tp | SE1006 | express | javascript | direct | none |
| opengrep | case-p19-0026 | pair-p19-0013 | control | 1 | true | fp | SE1006 | express | javascript | direct | none |
| opengrep | case-p19-0027 | pair-p19-0014 | control | 0 | false | tn | SE1007 | node | javascript | inter-file-aliased | none |
| opengrep | case-p19-0028 | pair-p19-0014 | vulnerable | 1 | true | tp | SE1007 | node | javascript | inter-file-aliased | none |
| opengrep | case-p19-0029 | pair-p19-0015 | vulnerable | 1 | true | tp | SE1006 | node | tsx | helper-mediated | none |
| opengrep | case-p19-0030 | pair-p19-0015 | control | 1 | true | fp | SE1006 | node | tsx | helper-mediated | none |
| opengrep | case-p19-0031 | pair-p19-0016 | control | 1 | true | fp | SE1005 | express | jsx | helper-mediated | mutable-allowlists |
| opengrep | case-p19-0032 | pair-p19-0016 | vulnerable | 1 | true | tp | SE1005 | express | jsx | helper-mediated | mutable-allowlists |
| opengrep | case-p19-0033 | pair-p19-0017 | vulnerable | 1 | true | tp | SE1002 | next-app-router | javascript | helper-mediated | none |
| opengrep | case-p19-0034 | pair-p19-0017 | control | 0 | false | tn | SE1002 | next-app-router | javascript | helper-mediated | none |
| opengrep | case-p19-0035 | pair-p19-0018 | control | 0 | false | tn | SE1003 | server-actions | javascript | helper-mediated | none |
| opengrep | case-p19-0036 | pair-p19-0018 | vulnerable | 1 | true | tp | SE1003 | server-actions | javascript | helper-mediated | none |
| opengrep | case-p19-0037 | pair-p19-0019 | vulnerable | 1 | true | tp | SE1005 | next-app-router | javascript | inter-file-aliased | none |
| opengrep | case-p19-0038 | pair-p19-0019 | control | 1 | true | fp | SE1005 | next-app-router | javascript | inter-file-aliased | none |
| opengrep | case-p19-0039 | pair-p19-0020 | control | 0 | false | tn | SE1007 | express | tsx | helper-mediated | none |
| opengrep | case-p19-0040 | pair-p19-0020 | vulnerable | 1 | true | tp | SE1007 | express | tsx | helper-mediated | none |
| opengrep | case-p19-0041 | pair-p19-0021 | vulnerable | 1 | true | tp | SE1004 | node | javascript | control-flow-sensitive | none |
| opengrep | case-p19-0042 | pair-p19-0021 | control | 0 | false | tn | SE1004 | node | javascript | control-flow-sensitive | none |
| opengrep | case-p19-0043 | pair-p19-0022 | control | 1 | true | fp | SE1005 | node | typescript | helper-mediated | none |
| opengrep | case-p19-0044 | pair-p19-0022 | vulnerable | 1 | true | tp | SE1005 | node | typescript | helper-mediated | none |
| opengrep | case-p19-0045 | pair-p19-0023 | vulnerable | 1 | true | tp | SE1007 | server-actions | javascript | control-flow-sensitive | none |
| opengrep | case-p19-0046 | pair-p19-0023 | control | 0 | false | tn | SE1007 | server-actions | javascript | control-flow-sensitive | none |
| opengrep | case-p19-0047 | pair-p19-0024 | control | 0 | false | tn | SE1003 | express | typescript | control-flow-sensitive | none |
| opengrep | case-p19-0048 | pair-p19-0024 | vulnerable | 1 | true | tp | SE1003 | express | typescript | control-flow-sensitive | none |
| opengrep | case-p19-0049 | pair-p19-0025 | vulnerable | 1 | true | tp | SE1003 | node | javascript | direct | none |
| opengrep | case-p19-0050 | pair-p19-0025 | control | 0 | false | tn | SE1003 | node | javascript | direct | none |
| opengrep | case-p19-0051 | pair-p19-0026 | control | 1 | true | fp | SE1006 | next-app-router | jsx | inter-file-aliased | none |
| opengrep | case-p19-0052 | pair-p19-0026 | vulnerable | 1 | true | tp | SE1006 | next-app-router | jsx | inter-file-aliased | none |
| opengrep | case-p19-0053 | pair-p19-0027 | vulnerable | 1 | true | tp | SE1006 | server-actions | jsx | inter-file-aliased | none |
| opengrep | case-p19-0054 | pair-p19-0027 | control | 1 | true | fp | SE1006 | server-actions | jsx | inter-file-aliased | none |
| opengrep | case-p19-0055 | pair-p19-0028 | control | 0 | false | tn | SE1001 | express | javascript | helper-mediated | none |
| opengrep | case-p19-0056 | pair-p19-0028 | vulnerable | 1 | true | tp | SE1001 | express | javascript | helper-mediated | none |
| opengrep | case-p19-0057 | pair-p19-0029 | vulnerable | 1 | true | tp | SE1002 | express | jsx | control-flow-sensitive | none |
| opengrep | case-p19-0058 | pair-p19-0029 | control | 0 | false | tn | SE1002 | express | jsx | control-flow-sensitive | none |
| opengrep | case-p19-0059 | pair-p19-0030 | control | 0 | false | tn | SE1001 | next-app-router | tsx | direct | none |
| opengrep | case-p19-0060 | pair-p19-0030 | vulnerable | 1 | true | tp | SE1001 | next-app-router | tsx | direct | none |
| opengrep | case-p19-0061 | pair-p19-0031 | vulnerable | 1 | true | tp | SE1002 | express | typescript | inter-file-aliased | none |
| opengrep | case-p19-0062 | pair-p19-0031 | control | 0 | false | tn | SE1002 | express | typescript | inter-file-aliased | none |
| opengrep | case-p19-0063 | pair-p19-0032 | control | 0 | false | tn | SE1004 | server-actions | jsx | helper-mediated | none |
| opengrep | case-p19-0064 | pair-p19-0032 | vulnerable | 1 | true | tp | SE1004 | server-actions | jsx | helper-mediated | none |
| opengrep | case-p19-0065 | pair-p19-0033 | vulnerable | 1 | true | tp | SE1003 | node | jsx | direct | none |
| opengrep | case-p19-0066 | pair-p19-0033 | control | 0 | false | tn | SE1003 | node | jsx | direct | none |
| opengrep | case-p19-0067 | pair-p19-0034 | control | 0 | false | tn | SE1003 | next-app-router | tsx | helper-mediated | none |
| opengrep | case-p19-0068 | pair-p19-0034 | vulnerable | 1 | true | tp | SE1003 | next-app-router | tsx | helper-mediated | none |
| opengrep | case-p19-0069 | pair-p19-0035 | vulnerable | 1 | true | tp | SE1005 | express | javascript | control-flow-sensitive | none |
| opengrep | case-p19-0070 | pair-p19-0035 | control | 1 | true | fp | SE1005 | express | javascript | control-flow-sensitive | none |
| opengrep | case-p19-0071 | pair-p19-0036 | control | 0 | false | tn | SE1001 | server-actions | javascript | inter-file-aliased | none |
| opengrep | case-p19-0072 | pair-p19-0036 | vulnerable | 1 | true | tp | SE1001 | server-actions | javascript | inter-file-aliased | none |
| opengrep | case-p19-0073 | pair-p19-0037 | vulnerable | 1 | true | tp | SE1004 | node | tsx | direct | none |
| opengrep | case-p19-0074 | pair-p19-0037 | control | 0 | false | tn | SE1004 | node | tsx | direct | none |
| opengrep | case-p19-0075 | pair-p19-0038 | control | 0 | false | tn | SE1001 | node | jsx | inter-file-aliased | none |
| opengrep | case-p19-0076 | pair-p19-0038 | vulnerable | 1 | true | tp | SE1001 | node | jsx | inter-file-aliased | none |
| opengrep | case-p19-0077 | pair-p19-0039 | vulnerable | 1 | true | tp | SE1002 | server-actions | tsx | direct | none |
| opengrep | case-p19-0078 | pair-p19-0039 | control | 0 | false | tn | SE1002 | server-actions | tsx | direct | none |
| opengrep | case-p19-0079 | pair-p19-0040 | control | 0 | false | tn | SE1001 | server-actions | typescript | helper-mediated | none |
| opengrep | case-p19-0080 | pair-p19-0040 | vulnerable | 1 | true | tp | SE1001 | server-actions | typescript | helper-mediated | none |
| opengrep | case-p19-0081 | pair-p19-0041 | vulnerable | 1 | true | tp | SE1002 | server-actions | tsx | control-flow-sensitive | none |
| opengrep | case-p19-0082 | pair-p19-0041 | control | 0 | false | tn | SE1002 | server-actions | tsx | control-flow-sensitive | none |
| opengrep | case-p19-0083 | pair-p19-0042 | control | 0 | false | tn | SE1004 | next-app-router | tsx | helper-mediated | none |
| opengrep | case-p19-0084 | pair-p19-0042 | vulnerable | 1 | true | tp | SE1004 | next-app-router | tsx | helper-mediated | none |
| opengrep | case-p19-0085 | pair-p19-0043 | vulnerable | 1 | true | tp | SE1001 | node | jsx | control-flow-sensitive | none |
| opengrep | case-p19-0086 | pair-p19-0043 | control | 0 | false | tn | SE1001 | node | jsx | control-flow-sensitive | none |
| opengrep | case-p19-0087 | pair-p19-0044 | control | 0 | false | tn | SE1001 | next-app-router | typescript | direct | none |
| opengrep | case-p19-0088 | pair-p19-0044 | vulnerable | 1 | true | tp | SE1001 | next-app-router | typescript | direct | none |
| opengrep | case-p19-0089 | pair-p19-0045 | vulnerable | 1 | true | tp | SE1006 | server-actions | typescript | helper-mediated | none |
| opengrep | case-p19-0090 | pair-p19-0045 | control | 1 | true | fp | SE1006 | server-actions | typescript | helper-mediated | none |
| opengrep | case-p19-0091 | pair-p19-0046 | control | 0 | false | tn | SE1004 | next-app-router | jsx | direct | none |
| opengrep | case-p19-0092 | pair-p19-0046 | vulnerable | 1 | true | tp | SE1004 | next-app-router | jsx | direct | none |
| opengrep | case-p19-0093 | pair-p19-0047 | vulnerable | 1 | true | tp | SE1004 | express | typescript | inter-file-aliased | none |
| opengrep | case-p19-0094 | pair-p19-0047 | control | 0 | false | tn | SE1004 | express | typescript | inter-file-aliased | none |
| opengrep | case-p19-0095 | pair-p19-0048 | control | 0 | false | tn | SE1002 | node | jsx | helper-mediated | none |
| opengrep | case-p19-0096 | pair-p19-0048 | vulnerable | 1 | true | tp | SE1002 | node | jsx | helper-mediated | none |
| opengrep | case-p19-0097 | pair-p19-0049 | vulnerable | 1 | true | tp | SE1004 | express | javascript | inter-file-aliased | none |
| opengrep | case-p19-0098 | pair-p19-0049 | control | 0 | false | tn | SE1004 | express | javascript | inter-file-aliased | none |
| opengrep | case-p19-0099 | pair-p19-0050 | control | 0 | false | tn | SE1007 | next-app-router | jsx | helper-mediated | none |
| opengrep | case-p19-0100 | pair-p19-0050 | vulnerable | 1 | true | tp | SE1007 | next-app-router | jsx | helper-mediated | none |
| opengrep | case-p19-0101 | pair-p19-0051 | vulnerable | 1 | true | tp | SE1007 | next-app-router | typescript | control-flow-sensitive | none |
| opengrep | case-p19-0102 | pair-p19-0051 | control | 0 | false | tn | SE1007 | next-app-router | typescript | control-flow-sensitive | none |
| opengrep | case-p19-0103 | pair-p19-0052 | control | 0 | false | tn | SE1004 | server-actions | typescript | control-flow-sensitive | none |
| opengrep | case-p19-0104 | pair-p19-0052 | vulnerable | 1 | true | tp | SE1004 | server-actions | typescript | control-flow-sensitive | none |
| opengrep | case-p19-0105 | pair-p19-0053 | vulnerable | 1 | true | tp | SE1002 | next-app-router | javascript | direct | none |
| opengrep | case-p19-0106 | pair-p19-0053 | control | 0 | false | tn | SE1002 | next-app-router | javascript | direct | none |
| opengrep | case-p19-0107 | pair-p19-0054 | control | 0 | false | tn | SE1007 | express | jsx | direct | none |
| opengrep | case-p19-0108 | pair-p19-0054 | vulnerable | 1 | true | tp | SE1007 | express | jsx | direct | none |
| opengrep | case-p19-0109 | pair-p19-0055 | vulnerable | 1 | true | tp | SE1005 | server-actions | tsx | inter-file-aliased | none |
| opengrep | case-p19-0110 | pair-p19-0055 | control | 1 | true | fp | SE1005 | server-actions | tsx | inter-file-aliased | none |
| opengrep | case-p19-0111 | pair-p19-0056 | control | 0 | false | tn | SE1003 | next-app-router | typescript | inter-file-aliased | none |
| opengrep | case-p19-0112 | pair-p19-0056 | vulnerable | 1 | true | tp | SE1003 | next-app-router | typescript | inter-file-aliased | none |

## Historical phase-separated table

| Phase | Study | Scanner | Lane | State | Attempts | Note |
|---|---|---|---|---|---:|---|
| 20 | one-shot multi-scanner comparison | secure-engine | native | completed | 112 | historical Phase 20 native evidence; not merged with normalized metrics |
| 20 | one-shot multi-scanner comparison | opengrep | capability-normalized | failed | 112 | immutable historical infrastructure failures; not replaced |
| 20 | one-shot multi-scanner comparison | semgrep-ce | capability-normalized | failed | 112 | immutable historical infrastructure failures; not replaced |
| 22 | post-open recovery study | opengrep | capability-normalized | completed | 112 | Phase 22 recovery evidence; separate denominator |
| 22 | post-open recovery study | semgrep-ce | capability-normalized | failed | 112 | Phase 22 recovery evidence; separate denominator |

## Limitations

The infrastructure correction changes only sandbox operability. Rules, corpus, expectations, and methodology are unchanged. Cross-phase results are not merged, native and normalized lanes are not ranked, and no overall winner is declared. See `limitations.md` for the complete validity boundary.

## Post-open verifier repair

After all 224 scanner attempts completed, the scanner-free verifier was repaired to accept the safe repository-relative bind sources recorded by the frozen runner. No scanner was started, no attempt or ledger entry was changed, and no retry occurred. See `verifier-repair.json`.
