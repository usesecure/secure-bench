# Phase 20 methodology

## Frozen inputs

Phase 20 consumes Phase 19 commit `b3e983891e4ae3e12cd727f6bdb460962f876a30`
without changing its corpus, expectations, rules, execution contracts, or lane policy. Preflight
checks the signed commit and parent, the complete Phase 19 checksum population, the 112-case corpus
and Evidence Contract commitments, all three execution contracts, the normalized rules, and every
pinned executable or wheel. The Phase 20 implementation tree is hashed after synthetic tests and
before the holdout is opened.

## Eligible lanes and attempts

The only eligible lanes are Secure Engine 0.1.6 native, OpenGrep 1.22.0
capability-normalized, and Semgrep CE 1.170.0 capability-normalized. Each lane receives exactly one
process for each of 112 cases, producing 336 possible attempts. Secure Engine normalized,
OpenGrep native, and Semgrep CE native remain `unsupported`; they have no process attempt, score,
or imputed zero.

Every eligible process receives a read-only copy of one case. Bubblewrap applies the frozen
read-only-host-root wrapper, a new network namespace, an empty `/tmp`, fixed resource limits, the
exact pinned tool mount, and one writable raw-output directory. The host environment is cleared and
only the recorded fixed variables are supplied. No network, telemetry, AI provider, credential, or
update operation is permitted inside the execution window.

## Process and adaptation policy

Process termination is adjudicated separately from raw-report adaptation. Timeout dominates;
missing, malformed, partial, wrong-version, proprietary-engine, unsafe-path, invalid-span, unknown
rule, and containment failures are explicit failed observations. Raw output, stdout, and stderr are
preserved byte-for-byte and hashed. The Phase 16 authoritative Evidence Contract v2 projection is
used for Secure Engine. The frozen Phase 17 and Phase 18 conservative JSON semantics are applied to
OpenGrep and Semgrep CE. No failed observation receives a finding count.

A failed attempt is never retried. If any attempt in a lane fails, that lane is `failed`, all of its
aggregate quality metrics are unavailable, and completed/failed counts plus individual evidence are
still reported.

## Neutral scoring

A case is predicted positive when its adapter-valid report contains at least one finding. Frozen
vulnerable/control labels determine TP, FP, TN, and FN. Precision, recall, specificity, F1, and
balanced accuracy are stored as exact numerator and denominator plus a six-decimal display value;
a zero denominator is `null`, not zero.

The same computation is emitted overall and by family, framework, source format, and topology.
Each vulnerable/control pair records both predictions and whether the pair is exact. OpenGrep and
Semgrep CE receive a paired same-lane comparison with agreement, discordant correctness counts, and
absolute metric differences only when both normalized lanes complete. All Secure Engine versus
normalized comparisons are explicitly `unavailable-cross-lane`. Phase 20 produces no combined
ranking and makes no capability-equivalence or production-readiness claim.

## Evidence and recomputation

The opening marker binds the preflight. A chronological hash-chained ledger then binds the marker,
all 336 observation documents, and canonical results. Each observation records the exact command
and environment vectors and their hashes, process timing and decision, raw paths, and raw hashes.
The artifact index binds the ledger, results, human report, and opening marker.

The separate `independent-verify` executable reads no scanner binary and starts no scanner. It
rehashes every raw artifact, re-adapts every completed report, reconstructs lane and comparison
results, checks canonical JSON byte equality, verifies the ledger chain and artifact index, and
writes a deterministic verification proof.
