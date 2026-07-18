#!/usr/bin/env bash
set -euo pipefail

readonly base=c42f686514177936a20a1d323f6a2d1b1c7d26c9
readonly root="$(git rev-parse --show-toplevel)"
cd "$root"

while IFS=$'\t' read -r status path rest; do
  case "$status:$path" in
    A:phase17/*|A:docs/phase-17-scanner-protocol-opengrep.md|M:.github/workflows/ci.yml) ;;
    *)
      echo "historical-integrity violation: $status $path ${rest:-}" >&2
      exit 1
      ;;
  esac
done < <(git diff --name-status "$base" --)

if rg -n 'std::process::Command|Command::new|curl[^[:cntrl:]]*\|[^[:cntrl:]]*(sh|bash)' \
  phase17/scanner-protocol phase17/opengrep-adapter; then
  echo "scanner-process audit rejected a launch or pipe-to-shell path" >&2
  exit 1
fi

cargo fmt --manifest-path phase17/Cargo.toml --all --check
cargo clippy --offline --manifest-path phase17/Cargo.toml --workspace --all-targets --all-features -- -D warnings
cargo test --offline --manifest-path phase17/Cargo.toml --workspace --all-features
cargo audit --file phase17/Cargo.lock --deny warnings
cargo deny --manifest-path phase17/Cargo.toml check

first="$(mktemp)"
second="$(mktemp)"
trap 'rm -f "$first" "$second"' EXIT
cargo run --quiet --offline --manifest-path phase17/Cargo.toml \
  -p secure-bench-opengrep-adapter -- verify . >"$first"
cargo run --quiet --offline --manifest-path phase17/Cargo.toml \
  -p secure-bench-opengrep-adapter -- verify . >"$second"
cmp "$first" "$second"
git diff --check "$base" --
