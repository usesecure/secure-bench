#!/usr/bin/env bash
set -euo pipefail

root=$(CDPATH= cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd -P)
manifest="$root/phase27-1/Cargo.toml"
lock="$root/phase27-1/Cargo.lock"
export PATH="/tmp/secure-bench-tools/rust/1.96.1/bin:/home/danielcastrillon/.cargo/bin:/usr/bin:/bin"
export CARGO_NET_OFFLINE=true

cargo fmt --manifest-path "$manifest" --all --check
cargo clippy --manifest-path "$manifest" --locked --offline --all-targets -- -D warnings
cargo test --manifest-path "$manifest" --locked --offline
/home/danielcastrillon/.cargo/bin/cargo-audit audit --file "$lock" --no-fetch --stale --deny warnings
/home/danielcastrillon/.cargo/bin/cargo-deny --manifest-path "$manifest" --config "$root/deny.toml" --frozen check all
(
  cd "$root/phase27-1"
  sha256sum --check SHA256SUMS
)
python3 "$root/phase27-1/scripts/verify-bindings.py"
