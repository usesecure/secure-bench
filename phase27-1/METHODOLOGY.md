# Phase 27.1 scanner-binding certification

This additive overlay resolves only scanner identities left as `verify-at-phase28-preflight`. It does not replace or modify Phase 27, lanes, methodology, cases, scoring, commitments, ledger entries, or the frozen 336-attempt plan.

Certification is scanner-free. The independent verifier hashes the local Secure Engine RC RPM and extracted executable; the active and durable OpenGrep executable plus its preserved Phase 17 provenance; and Semgrep's Python runtime, 66-wheel locked closure, installed inventory, entrypoint, core runner, `semgrep-core`, ruleset, adapter, active cache, and durable archive. No scanner binary or case is executed.

OpenGrep Sigstore is recorded as `preserved-not-reverified-this-run`: the executable and Phase 17 provenance are byte-identical to the frozen identities, while `cosign` and the detached signature/certificate bytes were unavailable. This preserves the historical verification without claiming a new one.

Any identity, path, version, lane, environment, or precedence mismatch fails closed. Phase 28 may consume `binding-overlay.json` only after the frozen Phase 27 plan and only for scanner identity fields whose base status is `verify-at-phase28-preflight`.
