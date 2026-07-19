#!/usr/bin/env bash
set -euo pipefail

root=$(CDPATH= cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd -P)
export PATH="/tmp/secure-bench-tools/rust/1.96.1/bin:/home/danielcastrillon/.cargo/bin:/usr/bin:/bin"
export CARGO_NET_OFFLINE=true

cargo fmt --manifest-path "$root/phase28/Cargo.toml" --all --check
cargo clippy --manifest-path "$root/phase28/Cargo.toml" --locked --offline --all-targets -- -D warnings
cargo test --manifest-path "$root/phase28/Cargo.toml" --locked --offline
python3 -m unittest discover -s "$root/phase29/tests" -p 'test_*.py'
/home/danielcastrillon/.cargo/bin/cargo-audit audit --file "$root/phase28/Cargo.lock" --no-fetch --stale --deny warnings
/home/danielcastrillon/.cargo/bin/cargo-deny --manifest-path "$root/phase28/Cargo.toml" --config "$root/deny.toml" --frozen check all
python3 "$root/phase29/harness.py" verify
git diff --quiet be54f5cea9221da67eebdb9c71dca70b7ad9674d -- phase28
git diff --quiet 540502c8bf1f139c7d54cb5f6e7c29ce97ffb934 -- phase27
git diff --quiet 0f6fe9f06f1f88233e6d537b9c4e1d826575d0ee -- phase27-1
git diff --quiet 467413eeb2a22017b5bc19f7f2052fdbc5d43d0d -- phase27-2
git diff --quiet 9d7ff67f7b360c9b70112d32445091671070ac57 -- phase27-3
