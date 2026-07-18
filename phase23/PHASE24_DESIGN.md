# Recommended Phase 24 design

Phase 24 must be a new, explicitly post-open recovery study. It is not executed
by Phase 23.

- Start only after independently verifying the signed Phase 23 commit and its
  corrected environment contract.
- Freeze a new Phase 24 plan before opening any case.
- Execute exactly the 112 already-open cases only in the Semgrep CE 1.170.0
  capability-normalized lane. Do not execute OpenGrep, Secure Engine, or a
  native lane.
- Use the Phase 23 corrected profile verbatim, including the 8 MiB hard stack
  cap, the frozen Phase 19 ruleset, and the frozen Phase 20 Semgrep adapter.
- Give Phase 24 its own run ID, attempt IDs, irreversible open marker,
  hash-chained ledger, raw artifacts, provenance, exhaustive hashes, and
  independent verifier.
- Preserve all 112 Phase 22 Semgrep failures as immutable historical evidence.
  Phase 24 results are additive and must never replace, repair, retry, or
  reinterpret them.
- Keep process failures explicit and fail closed. Allow no retries.
- Do not declare the normalized comparison complete until all 112 Phase 24
  attempts and independent verification finish validly.

