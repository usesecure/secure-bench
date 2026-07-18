#!/usr/bin/env bash
set -euo pipefail

readonly base=241600628315db6d8a77e62bbaf6e61ba5c628f1
readonly phase17_tree=e2512d180118e6487a979ba03d1961c41d17825d
readonly root="$(git rev-parse --show-toplevel)"
cd "$root"

while IFS=$'\t' read -r status path rest; do
  case "$status:$path" in
    A:phase18/*|A:docs/phase-18-semgrep-ce-adapter.md|M:.github/workflows/ci.yml) ;;
    *)
      echo "historical-integrity violation: $status $path ${rest:-}" >&2
      exit 1
      ;;
  esac
done < <(git diff --name-status "$base" --)

test "$(git rev-parse "$base:phase17")" = "$phase17_tree"
test "$(git hash-object phase17/rules/opengrep-conformance-v1.yml)" = \
  "$(git rev-parse "$base:phase17/rules/opengrep-conformance-v1.yml")"
test "$(sha256sum phase17/rules/opengrep-conformance-v1.yml | cut -d' ' -f1)" = \
  a9b0c304d6f12c00f7efa6bb648fe97b9d4b64c49e97fffccc0287cf03f97a96

if rg -n 'std::process::Command|Command::new|curl[^[:cntrl:]]*\|[^[:cntrl:]]*(sh|bash)' \
  phase18/semgrep-adapter; then
  echo "scanner-process audit rejected a launch or pipe-to-shell path" >&2
  exit 1
fi

if rg -n -- '--pro($|[ =])|--config=auto|SEMGREP_APP_TOKEN[^[:cntrl:]]*=' \
  phase18/semgrep-adapter phase18/manifests phase18/provenance; then
  echo "proprietary, remote-registry, or credential configuration found" >&2
  exit 1
fi

cargo fmt --manifest-path phase18/Cargo.toml --all --check
cargo clippy --offline --manifest-path phase18/Cargo.toml --workspace --all-targets --all-features -- -D warnings
cargo test --offline --manifest-path phase18/Cargo.toml --workspace --all-features
cargo audit --file phase18/Cargo.lock --no-fetch --deny warnings
cargo deny --manifest-path phase18/Cargo.toml check

first="$(mktemp)"
second="$(mktemp)"
trap 'rm -f "$first" "$second"' EXIT
cargo run --quiet --offline --manifest-path phase18/Cargo.toml \
  -p secure-bench-semgrep-adapter -- verify . >"$first"
cargo run --quiet --offline --manifest-path phase18/Cargo.toml \
  -p secure-bench-semgrep-adapter -- verify . >"$second"
cmp "$first" "$second"
git diff --check "$base" --
