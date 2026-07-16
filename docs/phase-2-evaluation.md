# Phase 2 Prospective Evaluation

Phase 2 applies the frozen neutral taxonomy 1.0.0 prospectively to two retained black-box runs of the explicitly supplied Secure Engine 0.1.1 artifact. It leaves the corpus, Phase 1 raw artifacts, Phase 1 decisions, and Phase 1 result unchanged.

This phase remains an intentionally neutral foundation. It is not the cross-tool comparison described as a later product direction, a production benchmark, a public leaderboard, or evidence that Secure Engine or another analyzer is superior.

## Frozen boundary

Before execution, Secure Bench committed a strict profile assigning each of the seven vulnerable Phase 1 expectations to exactly one frozen category/invariant pair and primary public CWE association. The profile binds the exact suite and taxonomy versions and fingerprints. Validation fails closed on missing cases, duplicate assignments, unknown coordinates, pair conflicts, fingerprint drift, or schema drift.

The scanner receives only one copied fixture at a time and the public command `scan {fixture} --format secure-json-v1 --output {report}`. It does not receive the profile, suite labels, expectations, matcher rules, prior results, or corpus manifest. The adapter preserves reported taxonomy coordinates but cannot infer aliases or award credit.

## Decision contract

An exact canonical detection requires one selected finding to satisfy the frozen taxonomy mapping, category, invariant, source, sink, and evidence-path constraints. A partial match has a canonically mapped candidate but fails at least one required localization or evidence constraint. A miss has no canonically mapped candidate. Out-of-scope and not-attempted outcomes remain distinct and cannot receive detection credit.

Matching is deterministic and one-to-one. Semantically identical findings are duplicates, not extra detections. Safe controls are evaluated separately: any normalized finding flags the control, while failures cannot appear clean.

Precision uses exact detections over all normalized findings. Recall uses exact detections over all seven eligible expectations. Partial matches receive diagnostic agreement credit but no detection credit. Category, invariant, CWE, source, sink, and evidence-path agreement each retain their own numerator and denominator.

## Reproducibility and isolation

The exact external binary hash, user-supplied source RPM hash, public version, command template, empty configuration hash, report schema, suite, corpus, taxonomy, profile, network attestation, retained run, retained report, and historical-result hashes are recorded in `result.json`.

AI validation remained disabled. No provider, credentials, AI command, or network access was supplied. The complete version-probe and scan lifecycle ran under an outer Linux network namespace. Each raw report is retained and tied to its run manifest by size and SHA-256.

The primary and repeat run are evaluated independently. Raw public reports may differ in volatile metadata; stability therefore reports raw equality separately from normalized finding IDs, semantic finding sets, case decisions, metrics, and a semantic aggregate fingerprint. Re-evaluation of the same retained inputs must produce byte-identical result JSON.

## Recorded outcome

The retained result has 4 exact detections, 2 partial matches, 1 miss, 1 flagged control, 6 clean controls, 10 normalized findings, 0 duplicates, and 0 execution failures. Exact precision is 4/10, recall is 4/7, and F1 is 8/17. Both independent runs produced equal semantic findings, decisions, metrics, and semantic aggregate fingerprints.

The complete measurement, per-case interpretation, provenance hashes, resources, stability record, and limitations are in [the Phase 2 bundle](../baselines/phase-2-secure-engine-0-1-1/README.md).
