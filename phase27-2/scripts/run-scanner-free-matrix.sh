#!/usr/bin/env bash
set -euo pipefail

root=$(CDPATH= cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd -P)
phase="$root/phase27-2"
phase17=/home/danielcastrillon/Proyectos/secure-bench-phase17-workspace-241600628315db6d8a77e62bbaf6e61ba5c628f1/phase17
export PATH="/tmp/secure-bench-tools/rust/1.96.1/bin:/home/danielcastrillon/.cargo/bin:/usr/bin:/bin"
export CARGO_NET_OFFLINE=true
targets=$(mktemp -d /home/danielcastrillon/Proyectos/.secure-bench-phase27-2-targets.XXXXXX)
restore_durable="$targets/restore-durable"
restore_git="$targets/restore-git"
cleanup() {
  chmod -R u+w "$targets" 2>/dev/null || true
  rm -rf "$targets"
}
trap cleanup EXIT

if [[ ${PHASE27_2_RESUME_AFTER_FORMAT:-0} != 1 ]]; then
  python3 "$phase/scripts/verify-compatibility.py" --skip-protection
  cargo fmt --manifest-path "$phase17/Cargo.toml" --all --check
  cargo fmt --manifest-path "$phase/Cargo.toml" --all --check
  cargo fmt --manifest-path "$phase/conformance/Cargo.toml" --all --check
fi

if [[ ${PHASE27_2_RESUME_AT_CONFORMANCE:-0} == 1 ]]; then
  cargo fmt --manifest-path "$phase/conformance/Cargo.toml" --all --check
  CARGO_TARGET_DIR="$targets/conformance" cargo clippy --manifest-path "$phase/conformance/Cargo.toml" --locked --offline --all-targets -- -D warnings
else
  CARGO_TARGET_DIR="$targets/phase17" cargo clippy --manifest-path "$phase17/Cargo.toml" --locked --offline --workspace --all-targets -- -D warnings
  CARGO_TARGET_DIR="$targets/certification" cargo clippy --manifest-path "$phase/Cargo.toml" --locked --offline --all-targets -- -D warnings
  CARGO_TARGET_DIR="$targets/conformance" cargo clippy --manifest-path "$phase/conformance/Cargo.toml" --locked --offline --all-targets -- -D warnings
  CARGO_TARGET_DIR="$targets/phase17" cargo test --manifest-path "$phase17/Cargo.toml" --locked --offline -p secure-bench-scanner-protocol
  CARGO_TARGET_DIR="$targets/phase17" cargo test --manifest-path "$phase17/Cargo.toml" --locked --offline -p secure-bench-opengrep-adapter tests::symlink_sources_fail_closed -- --exact
fi
CARGO_TARGET_DIR="$targets/conformance" cargo test --manifest-path "$phase/conformance/Cargo.toml" --locked --offline
CARGO_TARGET_DIR="$targets/certification" cargo test --manifest-path "$phase/Cargo.toml" --locked --offline

/home/danielcastrillon/.cargo/bin/cargo-audit audit --file "$phase17/Cargo.lock" --no-fetch --stale --deny warnings
/home/danielcastrillon/.cargo/bin/cargo-audit audit --file "$phase/Cargo.lock" --no-fetch --stale --deny warnings
/home/danielcastrillon/.cargo/bin/cargo-audit audit --file "$phase/conformance/Cargo.lock" --no-fetch --stale --deny warnings
/home/danielcastrillon/.cargo/bin/cargo-deny --manifest-path "$phase17/Cargo.toml" --config "$root/deny.toml" --frozen check all
/home/danielcastrillon/.cargo/bin/cargo-deny --manifest-path "$phase/Cargo.toml" --config "$root/deny.toml" --frozen check all
/home/danielcastrillon/.cargo/bin/cargo-deny --manifest-path "$phase/conformance/Cargo.toml" --config "$root/deny.toml" --frozen check all

(
  cd "$phase"
  sha256sum --check SHA256SUMS
)
"$phase/scripts/restore-phase17-workspace.sh" durable "$restore_durable"
python3 "$phase/scripts/verify-compatibility.py" --workspace-only "$restore_durable"
"$phase/scripts/restore-phase17-workspace.sh" git "$restore_git"
python3 "$phase/scripts/verify-compatibility.py" --workspace-only "$restore_git"
python3 "$phase/scripts/verify-compatibility.py"

printf 'phase27_2_scanner_free_matrix=PASS\nscanner_processes=0\nphase28_attempts=0\nphase28_retries=0\n'
