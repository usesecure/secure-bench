# Phase 20: one-shot multi-scanner execution

Phase 20 consumes the immutable Phase 19 holdout and executes exactly three eligible lanes:
Secure Engine 0.1.6 native, OpenGrep 1.22.0 capability-normalized, and Semgrep CE 1.170.0
capability-normalized. Each scanner receives a read-only copy of one case per process, for 336
possible one-shot process attempts. Unsupported lanes remain explicit and have no denominator.

Tool acquisition is outside the sealed execution window. The preflight then rehashes every frozen
Phase 19 input, all 66 Semgrep wheels, installed distribution identities, binaries, rules,
contracts, Python, bubblewrap, and the complete Phase 20 implementation. The execution environment
is cleared, network is unshared, the host is read-only, `/tmp` is fresh, and only the raw-output
directory is writable.

The chronological ledger binds the opening marker, every observation, and canonical results.
Detection quality, timing, and failures are separate. A distinct verifier rehashes and re-adapts
all raw reports and recomputes the complete result document without executing any scanner.
