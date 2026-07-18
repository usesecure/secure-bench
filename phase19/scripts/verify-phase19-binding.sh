#!/usr/bin/env bash
set -euo pipefail

readonly root="$(git rev-parse --show-toplevel)"
readonly base=aee2c7094983cfb8bdc16cf59b1962add82ca1db
cd "$root"
export CARGO_NET_OFFLINE=true

if rg -n 'std::process::Command|Command::new|TcpStream|UdpSocket|reqwest' phase19/src \
  || rg -n 'releases/latest' phase19/bindings phase19/execution; then
  echo "Phase 19 binding contains a scanner launch or moving release reference" >&2
  exit 1
fi

while IFS=$'\t' read -r status path rest; do
  case "$status:$path" in
    A:phase19/*|A:docs/phase-19-secure-engine-binding.md|A:docs/phase-19-multi-scanner-holdout.md|M:.github/workflows/ci.yml) ;;
    *)
      echo "historical-integrity violation: $status $path ${rest:-}" >&2
      exit 1
      ;;
  esac
done < <(git diff --name-status "$base" --)

printf '%s  %s\n' \
  f0a37799d4bc6b66eef8b4d9fcfc0eae3c9272b00bc3901ce996917f4cdcc1e1 phase19/bindings/secure-engine-v0.1.6.json \
  ac3c71ee258ac762dcdae91cd748ef14370acf3ae39a566195e5605f77b5ed09 phase19/schemas/secure-engine-binding-v1.schema.json \
  431bf00110d7a3f0f06d1fea0d0f2b10e6a4db11c0094575ac99d419af754087 phase19/provenance/secure-engine-v0.1.6.json \
  | sha256sum -c -

cargo fmt --manifest-path phase19/Cargo.toml --all --check
cargo clippy --offline --manifest-path phase19/Cargo.toml --all-targets --all-features -- -D warnings
cargo test --offline --manifest-path phase19/Cargo.toml --all-features
cargo audit --no-fetch --file phase19/Cargo.lock --deny warnings
cargo deny --manifest-path phase19/Cargo.toml check
cargo run --quiet --offline --manifest-path phase19/Cargo.toml -- verify .

first="$(mktemp)"
second="$(mktemp)"
trap 'rm -f "$first" "$second"' EXIT
cargo run --quiet --offline --manifest-path phase19/Cargo.toml -- validate-holdout . >"$first"
cargo run --quiet --offline --manifest-path phase19/Cargo.toml -- validate-holdout . >"$second"
cmp "$first" "$second"
cat "$first"
sha256sum -c phase19/holdout/SHA256SUMS >/dev/null

if [[ "$#" -eq 2 ]]; then
  cargo run --quiet --offline --manifest-path phase19/Cargo.toml -- verify-artifacts "$1" "$2"
elif [[ "$#" -ne 0 ]]; then
  echo "usage: $0 [official-rpm extracted-secure]" >&2
  exit 2
fi

if ps -eo comm= | awk '$1 == "secure" || $1 == "secure-engine" || $1 == "opengrep" || $1 == "semgrep" || $1 == "joern" || $1 == "ollama" { found=1 } END { exit !found }'; then
  echo "scanner or AI process audit found a prohibited executable" >&2
  exit 1
fi

git diff --check
