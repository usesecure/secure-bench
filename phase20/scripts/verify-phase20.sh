#!/usr/bin/env bash
set -euo pipefail

readonly root="$(git rev-parse --show-toplevel)"
cd "$root"
export CARGO_NET_OFFLINE=true

git diff --exit-code b3e983891e4ae3e12cd727f6bdb460962f876a30 -- phase19
git diff --check

if rg -n 'TcpStream|UdpSocket|reqwest|curl|wget' phase20/src; then
  echo "network-capable code found in sealed execution sources" >&2
  exit 1
fi

cargo fmt --manifest-path phase20/Cargo.toml --all --check
cargo clippy --offline --manifest-path phase20/Cargo.toml --all-targets --all-features -- -D warnings
cargo test --offline --manifest-path phase20/Cargo.toml --all-features
cargo audit --no-fetch --file phase20/Cargo.lock --deny warnings
cargo deny --manifest-path phase20/Cargo.toml check

if [[ -f phase20/output/results.json ]]; then
  cargo run --quiet --offline --manifest-path phase20/Cargo.toml --bin independent-verify -- .
fi

if ps -eo comm= | awk '$1 == "secure" || $1 == "secure-engine" || $1 == "opengrep" || $1 == "semgrep" || $1 == "joern" || $1 == "ollama" { found=1 } END { exit !found }'; then
  echo "prohibited scanner or AI process remains" >&2
  exit 1
fi

