# Secure Engine 0.1.1 Prospective Taxonomy Measurement

This directory is the Phase 2 reproducibility bundle for two deterministic black-box runs of the user-supplied Secure Engine 0.1.1 artifact against the unchanged Phase 1 corpus under the frozen taxonomy 1.0.0 profile. It is an intentionally neutral foundation measurement, not a production benchmark, scanner comparison, public ranking, or claim that Secure Engine or any other tool is superior.

## Provenance

- Git base: `93c0821db065de436a339c15b070e158947ad76c`
- Suite: `phase-1-javascript-typescript`
- Suite SHA-256: `57d91da3dff7393b1ee8844072d3999161371403027a6d9c78df56907d61e97b`
- Corpus aggregate SHA-256: `9a32028a28d7c0396a630db8a2698a8977e173328578b1108f14603372e77761`
- Taxonomy artifact SHA-256: `059fe22d7707cf8d17f2c1621fdae9819787a1958ba2ef0421eca4e4ec858452`
- Taxonomy content hash: `22852bd7401020b315af11dfa2b60c0b46f78eb19f95079e6400d7b3bea3272c`
- Pre-execution profile SHA-256: `2b1279b612eaa0bd8570c33e374cabe66174ee03a4d112baab9c4378cb4ac37f`
- Binary SHA-256, locally verified before execution: `d154c427723f1a259f168d17f4974ced006ecc093d5b9150e8ef7186442aa8e2`
- Source RPM SHA-256, supplied by the user and recorded without a local source-RPM path: `a06c21fc0484d2b91ccacce8c49abfce2be9f985b58f79f83f8623a04523c795`
- Tool-reported version: `secure 0.1.1`
- Scanner command template: `scan {fixture} --format secure-json-v1 --output {report}`
- Tool report schema: `secure-json-v1`
- Empty configuration SHA-256: `e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855`
- Primary run SHA-256: `b1e0e8e8c2ee507f89d6d6057dff5876fd6ee9a382329e3d6af91c6dc8b0539e`
- Repeat run SHA-256: `e979c932a44c3f84614157a3281d74f90c28e0004908b58f5b5581b2e3c38873`
- Deterministic result SHA-256: `498869eb9069116ab07764240dd9b8a2213c98a890396756087b4cb435051eb3`
- Pre-execution contract SHA-256: `041c91990c38e451aa5d0effb28f39fd23f86163b511969706bad025b069365c`
- Network attestation SHA-256: `86ac268d201a674a43538579fc5adcf8451026fd7a966c169ef4bed2f53bee3c`

AI validation was disabled throughout. The benchmark supplied no configuration, AI provider, credentials, or AI subcommand. The complete runner, including the version probe and every scanner process, executed inside a fresh Linux network namespace created with `bwrap --unshare-net`. The retained attestation records only the loopback interface and a failed outbound probe with `Network is unreachable`.

Secure Engine was treated strictly as an external black box. Secure Bench did not build, install, update, inspect, import, or modify it. Expected answers, taxonomy assignments, matcher data, and the Phase 1 result were never present in scanner-visible fixture copies, arguments, configuration, or environment.

## Measurement

| Measure | Result |
|---|---:|
| Eligible vulnerable expectations | 7 |
| Exact canonical detections | 4 |
| Partial matches | 2 |
| Misses | 1 |
| Out of scope / not attempted | 0 / 0 |
| Precision | 4/10 (40.00%) |
| Recall | 4/7 (57.14%) |
| F1 | 8/17 (47.05%) |
| Category / invariant / CWE agreement | 6/7 (85.71%) each |
| Source / sink agreement | 4/7 (57.14%) / 6/7 (85.71%) |
| Evidence-path agreement | 5/7 (71.42%) |
| Flagged / clean safe controls | 1 / 6 |
| Normalized / duplicate / false-positive findings | 10 / 0 / 6 |
| Execution failures | 0 |

Exact detections were `phase1-001`, `phase1-003`, `phase1-007`, and `phase1-011`. `phase1-009` was partial because its selected finding did not satisfy the frozen source constraint. `phase1-013` was partial because its selected finding did not satisfy the source or evidence-path constraint. `phase1-005` was missed. Safe control `phase1-010` was flagged; the other six controls were clean.

CWE agreement is evaluated only as the public primary CWE associated with the already-selected frozen category/invariant pair. Scanner prose, rule identifiers, CWE text, severity, confidence, and tool identity cannot create a taxonomy mapping or matching credit.

## Stability and resource observations

Both runs completed all 14 cases. Their finding identifiers, semantic finding sets, case decisions, metrics, and semantic evaluation fingerprints were equal. All 10 normalized semantic finding fingerprints were stable. Raw report bytes differed for all 14 cases because the public reports contain volatile scan metadata; those differences are retained and reported rather than normalized away.

| Observation | Primary | Repeat |
|---|---:|---:|
| Measured case duration | 70 ms | 70 ms |
| Maximum observed direct-process memory | 237,568 bytes | 204,800 bytes |
| Retained report bytes | 1,173,617 | 1,173,619 |

Timing and memory are descriptive observations from one host, not comparative performance claims. Direct-process sampling can miss short peaks or descendant-only allocation.

## Historical comparison

The committed Phase 1 result remains byte-identical and is used only as an immutable comparison input. Phase 2 does not retrospectively relabel Phase 1. Under the prospective taxonomy contract, four previously vocabulary-unmapped observations satisfy the complete canonical contract, two satisfy only part of it, and one remains missed. Two Phase 1 control flags are absent; `phase1-010` remains flagged. There are no detection or false-positive regressions in the result's defined comparison model.

| Measure | Immutable Phase 1 | Prospective Phase 2 |
|---|---:|---:|
| Exact detections | 0/7 | 4/7 |
| Partial taxonomy matches | Not applicable | 2/7 |
| Vulnerable cases without exact credit | 7/7 | 3/7 |
| Flagged safe controls | 3/7 | 1/7 |
| Clean safe controls | 4/7 | 6/7 |
| Exact recall | 0/7 (0.00%) | 4/7 (57.14%) |
| Exact precision / F1 | Not defined by Phase 1 | 4/10 (40.00%) / 8/17 (47.05%) |
| Duplicates | 0 | 0 |
| Execution failures | 0 | 0 |

The columns use different published matching contracts. They are shown for traceability, not as a scanner-version ranking or a claim of general improvement.

## Artifacts and limits

`pre-execution-contract.json` records the frozen inputs and evaluator boundary before either run. `network-isolation.json` records the isolation probe. `primary/` and `repeat/` contain the independent run manifests and 28 unmodified accepted public reports. `result.json` contains the deterministic prospective decisions, normalized findings, separate metrics, stability comparison, historical comparison, and provenance.

After both raw runs were retained, a verification-only defect in the stability projection was corrected: the semantic aggregate now excludes raw report fingerprints while raw byte differences remain separately reported. Matching criteria, taxonomy assignments, adapters, raw reports, and every benchmark outcome and metric were unchanged. A regression test proves that volatile public-report metadata cannot make otherwise equal semantic evaluations unequal.

This corpus contains only seven synthetic vulnerable/control pairs across seven families. It cannot support confidence intervals, broad language or framework coverage, production-readiness conclusions, public rankings, or claims of scanner superiority. No other scanner was executed, so this bundle is not a cross-tool comparison.
