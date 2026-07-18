# Secure Bench Phase 20

Phase 20 performs the single sealed execution defined by Phase 19 and reports each scanner/lane
combination independently. It never combines native and capability-normalized scores.

The lifecycle is intentionally one-way:

1. Acquire the already-frozen artifacts outside the execution window.
2. Run synthetic unit tests that cannot address the Phase 19 holdout.
3. Run `preflight`, which fails closed unless every frozen input and tool hash matches.
4. Run `execute-once`. An existing opening marker or evidence directory makes a second attempt fail.
5. Run `independent-verify` to recompute every score from raw evidence.

No command performs updates, telemetry, credential discovery, AI calls, or network access during
the sealed execution.

The prospective sequence is:

```text
phase20/scripts/acquire-frozen-tools.sh
cargo test --offline --manifest-path phase20/Cargo.toml --all-features
cargo run --offline --manifest-path phase20/Cargo.toml -- synthetic-proof .
cargo run --offline --manifest-path phase20/Cargo.toml -- preflight .
cargo run --offline --manifest-path phase20/Cargo.toml -- execute-once .
cargo run --offline --manifest-path phase20/Cargo.toml --bin independent-verify -- .
```

The acquisition command is the only network-capable step and must finish before preflight. The
`execute-once` command creates `phase20/output/HOLDOUT_OPENED.json` before it reads a case or starts
a scanner. Never remove that marker or retry an observation. See [METHODOLOGY.md](METHODOLOGY.md)
for scoring and failure semantics.
