# Phase 25 methodology

Phase 25 is the final additive, post-open Semgrep CE 1.170.0 recovery study. It
does not restore blindness or one-shot validity and does not replace, repair,
retry, or reinterpret any Phase 22 or Phase 24 Semgrep observation. Its only
comparison is OpenGrep capability-normalized Phase 22 versus Semgrep
capability-normalized Phase 25. Native and Secure Engine lanes remain excluded;
there is no overall three-scanner winner.

Before freeze, the complete scanner command is rehearsed on two repository-owned
synthetic fixtures: one finding and one clean result. Rust and Python state
matrices cover completed, failed, timeout, malformed, and unavailable evidence,
including invalid combinations. Environment tests require the exact cleared
environment, including `PWD=/tmp/fixture`, and reject missing, changed, reordered,
or additional variables and shell, bubblewrap, wrapper, or Python injection.
Signature checks resolve `allowed_signers` from `git rev-parse --git-common-dir`
and are exercised in normal, linked, and detached worktree contexts.

The official Rust 1.96.1 distribution supplies Cargo 1.96.1, rustfmt
1.9.0-stable, and Clippy 0.1.96. Its channel manifest and distribution SHA-256
are frozen in the contract. All dependency use is offline and locked. Network is
forbidden after `prepare` succeeds.

`prepare` freezes an opaque 112-attempt plan, execution contract, pre-open
provenance, and ledger genesis without reading the manifest or case files.
`preflight` validates Phase 20 through Phase 24 history, tool hashes, signatures,
the synthetic qualification, and frozen artifacts. `execute-once` creates the
irreversible marker immediately before its first manifest read, then executes
exactly 112 Semgrep capability-normalized attempts with zero retries.

The effective sandbox is the corrected Phase 23 profile: no network, a new PID
namespace and procfs, read-only root, private temporary paths, `/dev/null`,
`RLIMIT_AS=4 GiB`, `RLIMIT_NPROC=64`, and both stack limits at 8 MiB. Every
attempt preserves command, exact effective environment, limits, mount table,
stdout, stderr, raw JSON when present, exit/signal/timeout data, duration, GNU
time evidence, hashes, and one contiguous ledger entry.

Evidence integrity, scoring eligibility, and operational outcome are separate.
All operational states can form integrity-valid evidence. Metrics exist only if
all 112 observations are completed and adapter-valid. A fully failed campaign is
therefore integrity-valid, operationally failed, non-scoreable, and has no
detection metrics. No failure is imputed.

When eligible, raw evidence is independently recalculated into TP/FP/TN/FN,
precision, recall, specificity, F1, balanced accuracy, case and pair decisions,
and family, framework, source-format, topology, adversarial-variant, and
classification strata. Rust and Python verifiers are scanner-free.
