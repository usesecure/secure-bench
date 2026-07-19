#!/usr/bin/env bash
set -euo pipefail

root=$(CDPATH= cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd -P)
phase="$root/phase27-3"
og=/home/danielcastrillon/Proyectos/.secure-bench-phase27-3-opengrep-staging
sg=/home/danielcastrillon/Proyectos/.secure-bench-phase27-3-semgrep-staging
export PATH=/tmp/secure-bench-tools/rust/1.96.1/bin:/home/danielcastrillon/.cargo/bin:/usr/bin:/bin
export CARGO_NET_OFFLINE=true
export PYTHONDONTWRITEBYTECODE=1
targets=$(mktemp -d /home/danielcastrillon/Proyectos/.secure-bench-phase27-3-matrix.XXXXXX)
restore_og="$targets/restore-opengrep"
restore_sg="$targets/restore-semgrep"
cleanup() {
  chmod -R u+w "$targets" 2>/dev/null || true
  rm -rf "$targets"
}
trap cleanup EXIT

for required in \
  "$og/phase17/Cargo.toml" \
  "$og/phase17/independent-runner/Cargo.toml" \
  "$sg/phase18/Cargo.toml" \
  "$sg/phase18/independent-runner/Cargo.toml"; do
  [[ -f "$required" ]] || { printf 'missing matrix input: %s\n' "$required" >&2; exit 1; }
done

if ps -eo comm= | awk 'BEGIN{IGNORECASE=1} /^(semgrep|opengrep|secure-engine)$/ {found=1} END{exit found ? 0 : 1}'; then
  printf 'prohibited scanner process is already running\n' >&2
  exit 1
fi

if [[ ${PHASE27_3_RESUME_AT_RESTORATION:-0} != 1 ]]; then
if [[ ${PHASE27_3_RESUME_AT_CERTIFICATION_CLIPPY:-0} != 1 ]]; then
if [[ ${PHASE27_3_RESUME_AT_OPENGREP_CLIPPY:-0} != 1 ]]; then
  python3 "$phase/scripts/verify-dual-closure.py" --skip-protection --skip-phase-sums
  python3 -c 'import ast,pathlib; [ast.parse(p.read_text(encoding="utf-8")) for p in pathlib.Path("phase27-3").rglob("*.py")]'
  python3 -m unittest discover -s "$phase/tests" -p 'test_*.py'

  cargo metadata --manifest-path "$og/phase17/Cargo.toml" --offline --locked --format-version 1 > /dev/null
  cargo metadata --manifest-path "$og/phase17/independent-runner/Cargo.toml" --offline --locked --format-version 1 > /dev/null
  cargo metadata --manifest-path "$sg/phase18/Cargo.toml" --offline --locked --format-version 1 > /dev/null
  cargo metadata --manifest-path "$sg/phase18/independent-runner/Cargo.toml" --offline --locked --format-version 1 > /dev/null

  cargo fmt --manifest-path "$og/phase17/Cargo.toml" --all --check
  cargo fmt --manifest-path "$sg/phase18/Cargo.toml" --all --check
  cargo fmt --manifest-path "$phase/Cargo.toml" --all --check
  CARGO_TARGET_DIR="$targets/clippy-phase17" cargo clippy --manifest-path "$og/phase17/Cargo.toml" --workspace --all-targets --locked --offline -- -D warnings
else
  python3 -m unittest discover -s "$phase/tests" -p 'test_*.py'
fi
cargo fmt --manifest-path "$og/phase17/independent-runner/Cargo.toml" --all --check
cargo fmt --manifest-path "$sg/phase18/independent-runner/Cargo.toml" --all --check
CARGO_TARGET_DIR="$targets/clippy-opengrep-runner" cargo clippy --manifest-path "$og/phase17/independent-runner/Cargo.toml" --all-targets --locked --offline -- -D warnings
CARGO_TARGET_DIR="$targets/clippy-phase18" cargo clippy --manifest-path "$sg/phase18/Cargo.toml" --workspace --all-targets --locked --offline -- -D warnings
CARGO_TARGET_DIR="$targets/clippy-semgrep-runner" cargo clippy --manifest-path "$sg/phase18/independent-runner/Cargo.toml" --all-targets --locked --offline -- -D warnings
else
  cargo fmt --manifest-path "$phase/Cargo.toml" --all --check
fi
CARGO_TARGET_DIR="$targets/clippy-certification" cargo clippy --manifest-path "$phase/Cargo.toml" --all-targets --locked --offline -- -D warnings

CARGO_TARGET_DIR="$targets/test-phase17" cargo test --manifest-path "$og/phase17/Cargo.toml" --workspace --locked --offline
CARGO_TARGET_DIR="$targets/test-opengrep-runner" cargo test --manifest-path "$og/phase17/independent-runner/Cargo.toml" --locked --offline
CARGO_TARGET_DIR="$targets/test-phase18" cargo test --manifest-path "$sg/phase18/Cargo.toml" --workspace --locked --offline
CARGO_TARGET_DIR="$targets/test-semgrep-runner" cargo test --manifest-path "$sg/phase18/independent-runner/Cargo.toml" --locked --offline
CARGO_TARGET_DIR="$targets/test-certification" cargo test --manifest-path "$phase/Cargo.toml" --locked --offline

for lock in \
  "$og/phase17/Cargo.lock" \
  "$og/phase17/independent-runner/Cargo.lock" \
  "$sg/phase18/Cargo.lock" \
  "$sg/phase18/independent-runner/Cargo.lock"; do
  /home/danielcastrillon/.cargo/bin/cargo-audit audit --file "$lock" --no-fetch --stale --deny warnings
done

/home/danielcastrillon/.cargo/bin/cargo-deny --manifest-path "$og/phase17/Cargo.toml" --config "$root/deny.toml" --frozen check all
/home/danielcastrillon/.cargo/bin/cargo-deny --manifest-path "$og/phase17/independent-runner/Cargo.toml" --config "$root/deny.toml" --frozen check all
/home/danielcastrillon/.cargo/bin/cargo-deny --manifest-path "$sg/phase18/Cargo.toml" --config "$root/deny.toml" --frozen check all
/home/danielcastrillon/.cargo/bin/cargo-deny --manifest-path "$sg/phase18/independent-runner/Cargo.toml" --config "$root/deny.toml" --frozen check all
fi

(cd /home/danielcastrillon/Proyectos/secure-bench-tool-cache/adapter-workspaces/opengrep-phase17 && sha256sum --check SHA256SUMS)
(cd /home/danielcastrillon/Proyectos/secure-bench-tool-cache/adapter-workspaces/semgrep-phase18 && sha256sum --check SHA256SUMS)

"$phase/scripts/restore-adapter-workspace.sh" opengrep "$restore_og"
"$phase/scripts/restore-adapter-workspace.sh" semgrep "$restore_sg"
"$restore_og/build-runner-offline.sh" "$restore_og" opengrep "$targets/rebuilt-opengrep"
"$restore_sg/build-runner-offline.sh" "$restore_sg" semgrep "$targets/rebuilt-semgrep"
printf '%s  %s\n' \
  5af3904e995ee59987553648d92d83ecd9ad09e0362869bec843ee830ddb049b \
  "$targets/rebuilt-opengrep" | sha256sum --check
printf '%s  %s\n' \
  be600adf907376a7d3bb70a2373b458ce4688ff42ba01ee9b0cd6fff639c91bc \
  "$targets/rebuilt-semgrep" | sha256sum --check

python3 "$phase/scripts/verify-dual-closure.py" --skip-protection --skip-phase-sums
if ps -eo comm= | awk 'BEGIN{IGNORECASE=1} /^(semgrep|opengrep|secure-engine)$/ {found=1} END{exit found ? 0 : 1}'; then
  printf 'prohibited scanner process appeared during matrix\n' >&2
  exit 1
fi

printf 'phase27_3_scanner_free_matrix=PASS\nsynthetic_runner_processes=20\nscanner_processes=0\nholdout_accesses=0\nphase28_attempts=0\nphase28_retries=0\nnetwork_requests=0\n'
