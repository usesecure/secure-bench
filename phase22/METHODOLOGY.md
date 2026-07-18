# Phase 22 methodology

## Classification

This phase is a **post-open recovery study**. The 112-case corpus ceased to be
globally blind when Phase 20 opened it. Phase 22 cannot restore one-shot or
blind-holdout validity, and its outputs cannot replace the 224 historical
Phase 20 normalized-lane failures.

## Population and execution

The frozen plan contains 224 unique keys: 112 OpenGrep
capability-normalized keys followed by 112 Semgrep CE capability-normalized
keys. Case order is lexical and scanner order is fixed. There are zero retries.
Timeouts, crashes, malformed output, empty output, unsupported states, and
unavailable states remain non-completed observations and are never converted
to zero findings.

Phase 22 uses the unchanged Phase 19 capability-normalized rules, corpus,
expectations, and metadata. The only correction relative to the failed Phase
20 normalized runs is infrastructure: the exact corrected Phase 21 sandbox.
No Secure Engine or native-lane process is eligible.

Synthetic preflight scanner processes are qualification canaries, not recovery
study attempts. They run before the irreversible corpus-open marker and are
stored as separately sealed preflight evidence. No synthetic scanner is run
after the marker.

## Scoring

Detection quality is computed only from adapter-valid completed observations.
If a lane is incomplete, complete-lane aggregate metrics are unavailable; no
missing observation is imputed as a negative. For complete lanes, the report
contains TP, FP, TN, FN, precision, recall, specificity, F1, and balanced
accuracy with visible numerators and denominators.

Results are grouped by case, pair, SE1001–SE1007 family, framework, source
format, topology, adversarial variant, and vulnerable/control classification.
OpenGrep and Semgrep are compared only within the capability-normalized lane,
with paired disagreements and absolute metric differences.

Operational failures, detection quality, and duration summaries are separate.
The historical Phase 20 table identifies phase, study, scanner, lane, and
state; it does not merge cross-phase metrics or declare an overall winner.

## Validity boundary

Phase 22 can show whether the frozen scanners operate under the corrected
sandbox and how their unchanged normalized rules behave post-open. It cannot
support claims of restored blindness, restored one-shot execution, a neutral
three-scanner ranking, or a general winner across native and normalized lanes.
