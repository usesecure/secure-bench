# Phase 8 exit-code protocol defect adjudication

Phase 8 is an additive retrospective protocol correction over the 112 immutable reports and
recorded execution metadata from Phase 7. It is not another scanner execution, does not replace
the preregistered Phase 7 result, and makes no production-readiness, superiority, ranking, or
complete-coverage claim.

## Confirmed root cause

The public contracts already stated that a complete, internally error-free, adapter-valid report
is authoritative when a scanner uses a nonzero findings exit code. The generic Phase 1 runner
implemented that rule. The Phase 7 wrapper instead retained the preliminary process outcome and
entered report adaptation only when `process.status == success`. Consequently, all 33 normal
exit-code-1 executions were recorded as `runner.crash` before their retained reports could become
authoritative, and the frozen matcher treated those cases as not attempted.

The defect is in process/report status adjudication, not in Secure Engine, the frozen holdout,
evidence-contract v2, taxonomy, adapter mapping rules, expectation constraints, matching, or
scoring.

## Prospective correction

The tool-neutral policy in `policies/process-status-v1.json` separates clean successful reports,
successful findings reports, nonzero policy exits with valid findings reports, genuine crashes,
timeouts, missing reports, malformed or adapter-invalid reports, and internally errored reports.
A normal nonzero exit is not by itself a crash when the current report is complete, internally
error-free, adapter-valid, and contains findings. Signals and timeouts remain terminal failures,
and a nonzero exit with an empty report remains a crash.

## Retrospective method

The standalone Rust Phase 8 workspace has no process-launching API. It verifies the original
Phase 7 result, ledger, journal, run, artifact index, report aggregate, raw report-set digest,
frozen evaluator files, historical artifact trees, and frozen Phase 5 tree before adjudication.
It then correlates each recorded exit with exactly one retained report, projects corrected
statuses in memory, and invokes the already-frozen `evaluate_phase7` implementation. This keeps
evidence-contract-v2 matching, partial rules, duplicates, source/sink constraints, evidence-path
requirements, taxonomy, expectations, and scoring unchanged.

## Phase 7 and Phase 8 interpretation

| Dimension | Phase 7 | Phase 8 |
|---|---|---|
| Evidence acquisition | One-shot scanner execution | No execution; retained Phase 7 evidence only |
| Process policy | Nonzero exits gated out before report authority | Versioned report-authoritative policy |
| Official meaning | Preregistered but protocol-defective result | Additive retrospective correction |
| Raw reports and ledger | Immutable originals | Referenced byte-for-byte; separate ledger |
| Matcher and scoring | Frozen evidence-contract v2 | Same frozen evaluator, unchanged |

## Aggregate adjudication

| Metric | Original Phase 7 | Corrected Phase 8 |
|---|---:|---:|
| Exact detections | 0 | 0 |
| Partial matches | 0 | 0 |
| Misses | 36 | 56 |
| Vulnerable cases not attempted | 20 | 0 |
| Flagged safe controls | 0 | 13 |
| Clean safe controls | 43 | 43 |
| Safe controls not attempted | 13 | 0 |
| Distinct findings | 0 | 33 |
| Duplicate findings | 0 | 0 |
| Unrelated findings | 0 | 33 |
| Operational failures | 33 | 0 |
| Crashes | 33 | 0 |
| Precision | undefined, 0/0 | 0/33 |
| Recall | 0/56 | 0/56 |
| F1 | 0/56 | 0/89 |

The corrected agreement numerators are taxonomy 20/56, category 20/56, invariant 20/56,
CWE 20/56, source 0/56, sink 1/56, and evidence path 0/56. The result retains complete
taxonomy-family, framework, language, topology, and crossed-stratum tables. These values show
that correcting execution accounting does not convert unrelated or incomplete evidence into
detections.

## Limitations

Phase 8 can adjudicate only the retained public report contract and recorded process metadata. It
does not infer scanner intent from stderr, treat a nonzero empty report as successful, revise any
holdout answer, or establish production coverage. Phase 2, Phase 4, Phase 7, and Phase 8 use
different evidence lifecycles and must not be directly ranked.

## Artifact hashes

| Artifact | SHA-256 |
|---|---|
| Process-status policy | `8b5ff33690828dc97afa8be24ef14dc66bf44d6da913e2621d92208e513f26ac` |
| Additive adjudication result | `ddec5302afe6cf3dc60620654c905bfb2604bb8d0f39676d0a78a2889bed8f88` |
| Separate adjudication ledger | `d65032029680aedc478fab7463ab328d8f357e640468b02bd674f160ead4ce75` |
| Phase 8 artifact index | `a3dd2022108e907acbec3da77635cfb6d242c04f753ca7ddeb41f26651949517` |
