#!/usr/bin/env bash
set -euo pipefail

usage() {
  printf 'usage: %s <opengrep|semgrep> <destination>\n' "$0" >&2
  exit 2
}

[[ $# == 2 ]] || usage
kind=$1
destination=$2
case "$kind" in
  opengrep)
    source=/home/danielcastrillon/Proyectos/secure-bench-tool-cache/adapter-workspaces/opengrep-phase17
    ;;
  semgrep)
    source=/home/danielcastrillon/Proyectos/secure-bench-tool-cache/adapter-workspaces/semgrep-phase18
    ;;
  *) usage ;;
esac

[[ -d "$source" ]] || { printf 'missing durable cache: %s\n' "$source" >&2; exit 1; }
[[ ! -e "$destination" ]] || { printf 'destination already exists: %s\n' "$destination" >&2; exit 1; }
mkdir -p "$destination"
cp -a "$source"/. "$destination"/
(
  cd "$destination"
  sha256sum --check SHA256SUMS
)
printf 'restored_%s=%s\n' "$kind" "$destination"
