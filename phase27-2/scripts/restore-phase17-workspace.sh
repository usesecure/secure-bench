#!/usr/bin/env bash
set -euo pipefail

commit=241600628315db6d8a77e62bbaf6e61ba5c628f1
repo=/home/danielcastrillon/Proyectos/secure-bench
durable=/home/danielcastrillon/Proyectos/secure-bench-tool-cache/phase17-workspace/$commit/workspace

if [[ $# -ne 2 || ( $1 != durable && $1 != git ) ]]; then
  echo "usage: restore-phase17-workspace.sh {durable|git} TARGET" >&2
  exit 2
fi
mode=$1
target=$2
if [[ -e $target ]]; then
  echo "refusing existing restore target: $target" >&2
  exit 1
fi
mkdir -p "$target"
if [[ $mode == durable ]]; then
  cp -a "$durable/." "$target/"
else
  git -C "$repo" archive --format=tar "$commit" phase17 \
    | tar -xf - --strip-components=1 -C "$target"
fi
printf 'restored_mode=%s\ntarget=%s\ncommit=%s\n' "$mode" "$target" "$commit"
