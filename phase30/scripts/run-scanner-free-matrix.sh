#!/usr/bin/env bash
set -euo pipefail

root=$(CDPATH= cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd -P)
export PATH="/tmp/secure-bench-tools/rust/1.96.1/bin:/home/danielcastrillon/.cargo/bin:/usr/bin:/bin"
export CARGO_NET_OFFLINE=true

cargo fmt --manifest-path "$root/phase30/Cargo.toml" --all --check
cargo clippy --manifest-path "$root/phase30/Cargo.toml" --locked --offline --all-targets -- -D warnings
cargo test --manifest-path "$root/phase30/Cargo.toml" --locked --offline
/home/danielcastrillon/.cargo/bin/cargo-audit audit --file "$root/phase30/Cargo.lock" --no-fetch --stale --deny warnings
/home/danielcastrillon/.cargo/bin/cargo-deny --manifest-path "$root/phase30/Cargo.toml" --config "$root/deny.toml" --frozen check all
cargo run --manifest-path "$root/phase30/Cargo.toml" --locked --offline -- --write-proof
python3 "$root/phase30/scripts/finalize.py"
(cd "$root" && sha256sum --check phase30/SHA256SUMS)
git -C "$root" diff --quiet 9b6566e600d18160865e45eda31d8634669c889a -- phase28 phase29
test "$(git -C "$root" rev-parse main)" = 9b6566e600d18160865e45eda31d8634669c889a
test "$(git -C "$root" rev-parse a5f8d978f21dae028eb722a5e73e12d858eeecb2^{commit})" = a5f8d978f21dae028eb722a5e73e12d858eeecb2
test "$(git -C "$root" rev-parse 73905cd14490f6bbe542dbd80c9f9b0c5889a3cf^{commit})" = 73905cd14490f6bbe542dbd80c9f9b0c5889a3cf
! pgrep -x secure >/dev/null
! pgrep -x opengrep >/dev/null
! pgrep -x semgrep >/dev/null
! pgrep -f '[s]ecure-bench-opengrep-json-runner' >/dev/null
! pgrep -f '[s]ecure-bench-semgrep-json-runner' >/dev/null
