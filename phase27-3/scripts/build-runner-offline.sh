#!/usr/bin/env bash
set -euo pipefail

usage() {
  printf 'usage: %s <artifact-root> <opengrep|semgrep> <output>\n' "$0" >&2
  exit 2
}

[[ $# == 3 ]] || usage
artifact=$(CDPATH= cd -- "$1" && pwd -P)
kind=$2
output=$3
export PATH=/tmp/secure-bench-tools/rust/1.96.1/bin:/home/danielcastrillon/.cargo/bin:/usr/bin:/bin
export CARGO_NET_OFFLINE=true
export SOURCE_DATE_EPOCH=0
case "$kind" in
  opengrep)
    binary=secure-bench-opengrep-json-runner
    virtual=/secure-bench-phase27-3/opengrep
    ;;
  semgrep)
    binary=secure-bench-semgrep-json-runner
    virtual=/secure-bench-phase27-3/semgrep
    ;;
  *) usage ;;
esac
context="/home/danielcastrillon/Proyectos/.secure-bench-phase27-3-reproducible-$kind"
[[ ! -e "$context" ]] || { printf 'fixed build context is occupied: %s\n' "$context" >&2; exit 1; }
mkdir -p "$context"
cleanup() {
  chmod -R u+w "$context" 2>/dev/null || true
  rm -rf "$context"
}
trap cleanup EXIT

cp -a "$artifact/workspace"/. "$context"/
chmod -R u+w "$context"
if [[ $kind == opengrep ]]; then
  runner_root="$context/phase17/independent-runner"
else
  runner_root="$context/phase18/independent-runner"
fi
mkdir -p "$runner_root"
cp -a "$artifact/runner-source"/. "$runner_root"/
export RUSTFLAGS="--remap-path-prefix=$context=$virtual"
CARGO_TARGET_DIR="$context/target" cargo build \
  --manifest-path "$runner_root/Cargo.toml" \
  --release --locked --offline
install -m 0555 "$context/target/release/$binary" "$output"
