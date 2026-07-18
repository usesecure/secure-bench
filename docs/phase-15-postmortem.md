# Secure Bench Phase 15 offline postmortem

Phase 15 is a deterministic retrospective analysis of the retired and disclosed Phase 13 holdout and the immutable Phase 14 execution. It did not execute Secure Engine, another scanner, AI, a network operation, or any holdout case. It is not a rescore, ranking, scanner comparison, production-readiness statement, superiority claim, or complete-coverage claim.

## Confirmed root cause

Phase 14 correctly preregistered `evidence_contract_v2` as the authoritative projection, but its report adapter did not deserialize or use that field. Instead, it reconstructed canonical-looking evidence from the generic legacy `evidence_path` before deriving the finding ID and running Evidence Contract v2 matching. All 96 retained findings contain a complete authoritative v2 projection, while all 96 Phase 14 adapter records are `unmapped_semantics`. Scanner attribution in this postmortem is limited to defects already present inside the retained authoritative v2 projection; evidence lost only by the adapter is never blamed on the scanner.

This mechanism explains the Phase 14 agreement pattern: taxonomy, category, invariant, and CWE were 56/56; source identity was 0/56; source span was 28/56; sink identity was 8/56; sink span was 56/56; connected value identity and evidence path were both 0/56. Taxonomy metadata and locations survived the legacy route, but generic semantic labels did not preserve the canonical source/sink vocabulary and the adapter did not preserve the declared v2 path as the scoring input.

## Complete accounting

| Population | Count |
|---|---:|
| Retired cases | 112 |
| Retained findings | 96 |
| Adapter projection loss observed | 96 |
| Adapter projection loss outcome-causal | 10 |
| Flagged safe controls | 40 |
| Vulnerable authoritative-v2 exact comparisons | 10 |
| Vulnerable authoritative-v2 partial comparisons | 0 |
| Vulnerable authoritative-v2 no-match comparisons | 46 |

Every vulnerable case retained one finding: 10 authoritative v2 projections matched exactly, while 46 retained the wrong evidence (30 with source identity as the primary defect and 16 with source span as the primary defect). Adapter projection loss was therefore outcome-causal for 10 findings and observed but noncausal for the other 86. This is distinct from a scanner false negative caused by emitting no finding; that count is zero. All 40 flagged controls retained an overbroad finding without the frozen effective barrier, so they remain genuine scanner false positives. The frozen controls require 32 guards and 8 sanitizers; all 40 barriers terminate, apply to the same value, and dominate the sink.

Primary findings are adapter projection loss 10, scanner source identity 30, scanner source span 16, and scanner overbroad false positive 40. Contributing findings are scanner source identity 21, source span 32, guard recognition 32, sanitizer recognition 8, and dominance reasoning 40. These categories are not mutually exclusive across the primary and contributing layers.

The adapter and scanner defects co-occur in the retained evidence, so Phase 15 does not estimate independent effect sizes. For the 40 controls, the authoritative projection establishes that the required effective barrier was omitted, but black-box evidence cannot identify whether the engine ignored it, misclassified it, bypassed it, or failed to associate it with the evaluated value. Those internal alternatives remain explicitly unsupported.

The authoritative-v2 comparisons are diagnostic counterfactuals only. They do not alter the Phase 14 result, award retrospective credit, or silently repair any finding. The original exact, partial, miss, and control metrics and semantic fingerprint remain immutable.

## Historical and benchmark boundary

Before artifact generation, the frozen Phase 13 validator revalidated every fixture, expectation, mutation contract, taxonomy binding, span, connected path, paired barrier, aggregate corpus commitment, and contract Merkle root. Deterministic Phase 15 reconstruction then revalidates every Phase 13 checksum and the Phase 0–11 content-addressed payload while excluding only the prospective `diagnostics/phase-N` namespace declared by the stable historical boundary. No fixture/expectation defect, matcher defect, taxonomy drift, contract ambiguity, operational failure, or unresolved attribution was confirmed. The separate chained defect ledger records the adapter defect without changing the completed Phase 14 ledger.

## Regression handoff

The regression manifest contains only retired, disclosed Phase 13 development material and may be handed to the permitted Secure Engine Phase 6.9 regression workflow only as disclosed regression material, never as a hidden holdout or retrospective score repair. Future adapters must give a complete v2 projection precedence, fail closed on conflicts or malformed v2, and use a legacy projection only when v2 is absent and an explicit versioned legacy route is selected. Scanner-specific aliases, fixture identifiers, score exceptions, and retrospective repairs are prohibited.

## Limitations

This causal analysis is bounded by committed synthetic fixtures and retained reports. It does not establish real-world prevalence, exploitability, production fitness, superiority over another tool, or comprehensive vulnerability coverage. Phase 14 remains the preregistered historical result.
