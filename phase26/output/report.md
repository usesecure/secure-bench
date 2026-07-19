# Secure Bench Phase 26 certification report

## Decision

Accepted. Phase 26 independently certifies that the frozen Phase 25 evidence is
integral, operationally valid, and scoring-eligible under the Phase 26
specification. This is an additive successor certification; it does not claim
that the frozen Phase 25 Python verifier passed.

## Evidence

- Phase 25 commit: `a25175dc352c006deea579b5e85643d513be6984`
- Direct parent: `17946b9f326ff2c25ebcd5f0f1526af35b8702df`
- Signature/DCO: trusted ED25519; exactly one DCO trailer
- Frozen inventory: 684/684 entries verified
- Attempts: 112 unique, 112 completed, zero retries
- Raw evidence: 112 valid JSON reports; zero signals, timeouts, malformed, or unavailable states
- Effective `PWD=/tmp/fixture`: 112/112
- Derived ledger head: `ed0c0cbf20e5fc68bb40fedf2794953341b177ceae3c25ca28421c7a5b2b25c7`
- Tamper tests: 13/13 mutations rejected on temporary copies
- Scanner processes started by Phase 26: zero

## Independently recalculated results

TP 56, FP 16, TN 40, FN 0. Precision is 7/9 (0.777778), recall 1/1
(1.000000), specificity 5/7 (0.714286), F1 7/8 (0.875000), and balanced
accuracy 6/7 (0.857143). All family, framework, source-format, topology,
adversarial-variant, and classification strata match the frozen Phase 25
outputs.

## Normalized comparison

OpenGrep Phase 22 and Semgrep CE Phase 25 are an exact tie only in the
capability-normalized lane: 112/112 case agreements, 56/56 pair agreements,
zero disagreements, and zero absolute difference for all five metrics. No
general winner is declared between OpenGrep, Semgrep, and Secure Engine.

## Frozen verifier status

The original Phase 25 Python verifier remains failed and fail-closed. Its first
entry mismatch came from sorting observation object keys before hashing, while
the producer committed exact Rust-struct serialization bytes. Phase 26 did not
invoke, patch, or use that verifier as authority.
