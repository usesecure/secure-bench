# Phase 27 independent holdout v2 clean restart

Phase 27 constructs and freezes a scanner-neutral corpus. It does not execute a scanner, import scanner output, score a case, or create Phase 28 results.

## Design

The preregistration fixes a CSPRNG seed, seven public taxonomy invariants, four frameworks, four source formats, four data-flow topologies, two orientations, and ten adversarial variants before fixture creation. A keyed SHA-256 derivation produces new pair, case, and ticket identifiers. The generator uses a family-local balanced schedule: every family has eight pairs and exactly two assignments for every framework, source format, and topology.

Each pair contains one vulnerable fixture and one minimally changed control. The source, framework, format, topology, and adversarial context remain fixed within the pair. Controls restore the invariant through structured argument separation, parameter binding, canonical path confinement, exact outbound/redirect destination policy, data parsing instead of code evaluation, or a trusted server principal with tenant/owner/resource scope that dominates the mutation.

## Neutral review and syntax

The independent Python verifier checks all 56 pairs and 112 case contracts, exact and normalized uniqueness, counterfactual similarity, evidence spans, guard dominance, authorization identity provenance, balances, and every required family-by-factor matrix cell. A separate Rust utility parses JavaScript, JSX, TypeScript, and TSX with tree-sitter. Neither tool imports or runs a fixture.

## Commitments

Every leaf commits to the case ID, exact source fingerprint, and case-metadata hash with a domain separator. Binary Merkle nodes use `SHA256("node\\0" || left || right)` and duplicate the final node at odd levels. The genesis ledger entry commits to the Merkle root and commitments file and begins from 64 zeroes. `SHA256SUMS` covers every committed Phase 27 file except itself; its self-exclusion is necessary to avoid recursive hashing.

## Historical overlap

No redacted precomputed overlap index was supplied in the allowed neutral infrastructure. The historical overlap check is therefore frozen as `unavailable`. No historical holdout source, label, expectation, or result was opened to manufacture a comparison.

## Frozen execution contract

Phase 28 contains 336 planned attempts and zero retries: 112 Secure Engine native, 112 OpenGrep capability-normalized, and 112 Semgrep CE capability-normalized. Native and normalized lanes are disjoint. `failed`, `timeout`, `malformed`, `unsupported`, and `unavailable` are non-numeric states and cannot enter metrics or be coerced to zero.

## Limitations

- Tree-sitter establishes syntax, not framework type correctness or runtime behavior.
- Structural review establishes the preregistered invariants but does not predict scanner behavior.
- Historical novelty beyond within-corpus exact/normalized uniqueness is unavailable without an allowed redacted index.
- Phase 28 artifacts must pass their frozen identity and environment preflight before any later execution.
