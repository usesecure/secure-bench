# Secure Bench Phase 21

Phase 21 repairs the scanner sandbox defect discovered after Phase 20 and
qualifies OpenGrep 1.22.0 and Semgrep CE 1.170.0 on synthetic inputs only.
Phase 20 is immutable: its 336 attempts, results, ledger, and methodology are
not changed, rerun, or reinterpreted.

The corrected `phase21-null-device-v1` profile creates a fresh `/dev` and
device-binds only `/dev/null`. It also masks `/home`, `/root`, `/run/user`, and
`/var/tmp`, mounts a fresh `/proc`, retains the read-only root, clears the
environment, applies process/address-space limits, and uses new network and PID
namespaces.

The qualification evidence is sealed under `output/`. It contains 16 canary
observations:

- two scanner-free sandbox probes;
- six scanner processes per scanner: legacy failure reproduction, corrected
  startup, clean result, expected finding, invalid rule, and timeout;
- one scanner-free malformed-output mock per adapter.

The 12 scanner processes are Phase 21 canaries, not Phase 20 attempts or Phase
22 attempts. There were no retries. The fixtures and rule were authored for
this phase and are not derived from the holdout.

Verify the sealed evidence without starting scanners:

```text
cargo run --offline --manifest-path phase21/Cargo.toml \
  --bin independent-verify -- .
```

Verify the frozen scanner cache, including all 66 Semgrep wheel hashes:

```text
cargo run --offline --manifest-path phase21/Cargo.toml \
  --bin secure-bench-phase21 -- verify-tools .
```

`qualify` is intentionally fail-closed when `phase21/output` already exists.
Do not remove sealed output to rerun the committed qualification.

See [the root-cause report](ROOT_CAUSE.md) and
[the Phase 22 draft](PHASE22_DESIGN.md).

