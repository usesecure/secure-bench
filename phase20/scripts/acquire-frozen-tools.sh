#!/usr/bin/env bash
set -euo pipefail

readonly root="$(git rev-parse --show-toplevel)"
readonly cache=/tmp/secure-bench-tools
readonly semgrep_root="$cache/semgrep/1.170.0"
readonly lock="$root/phase18/provenance/semgrep-python314-linux-x86_64-lock.json"

if [[ -e "$root/phase20/output/HOLDOUT_OPENED.json" ]]; then
  echo "refusing tool acquisition after holdout opening" >&2
  exit 1
fi

install -d "$cache/secure-engine/0.1.6/usr/bin"
install -m 0444 \
  /var/tmp/secure-engine-v0.1.6-published-assets/secure-engine-0.1.6-1.fc44.x86_64.rpm \
  "$cache/secure-engine/0.1.6/secure-engine-0.1.6-1.fc44.x86_64.rpm"
install -m 0555 /var/tmp/secure-engine-v0.1.6-package-smoke/usr/bin/secure \
  "$cache/secure-engine/0.1.6/usr/bin/secure"

install -d "$cache/opengrep/1.22.0"
if [[ ! -f "$cache/opengrep/1.22.0/opengrep_manylinux_x86" ]]; then
  curl --fail --location --proto '=https' --tlsv1.2 \
    --output "$cache/opengrep/1.22.0/opengrep_manylinux_x86.partial" \
    https://github.com/opengrep/opengrep/releases/download/v1.22.0/opengrep_manylinux_x86
  mv "$cache/opengrep/1.22.0/opengrep_manylinux_x86.partial" \
    "$cache/opengrep/1.22.0/opengrep_manylinux_x86"
fi
chmod 0555 "$cache/opengrep/1.22.0/opengrep_manylinux_x86"

install -d "$semgrep_root/wheelhouse"
while IFS=$'\t' read -r filename digest url; do
  destination="$semgrep_root/wheelhouse/$filename"
  if [[ ! -f "$destination" ]]; then
    curl --fail --location --proto '=https' --tlsv1.2 \
      --output "$destination.partial" "$url"
    mv "$destination.partial" "$destination"
  fi
  printf '%s  %s\n' "$digest" "$destination" | sha256sum -c -
done < <(jq -r '.packages[] | [.filename,.sha256,.artifact_url] | @tsv' "$lock")

rm -rf "$semgrep_root/venv"
/usr/bin/python3.14 -m venv "$semgrep_root/venv"
jq -r '.packages[] | "\(.name)==\(.version) --hash=sha256:\(.sha256)"' "$lock" \
  > "$semgrep_root/requirements.lock"
PIP_DISABLE_PIP_VERSION_CHECK=1 PIP_NO_INDEX=1 \
  "$semgrep_root/venv/bin/python" -m pip install \
  --no-index --find-links "$semgrep_root/wheelhouse" --require-hashes \
  --only-binary=:all: -r "$semgrep_root/requirements.lock"

"$semgrep_root/venv/bin/python" - "$lock" "$semgrep_root/installed-distributions.json" <<'PY'
import importlib.metadata
import json
import pathlib
import sys

lock = json.loads(pathlib.Path(sys.argv[1]).read_text())
installed = {}
for package in lock["packages"]:
    name = package["name"].lower().replace("_", "-")
    version = importlib.metadata.version(package["name"])
    if version != package["version"]:
        raise SystemExit(f"installed version drift for {name}: {version}")
    installed[name] = version
pathlib.Path(sys.argv[2]).write_text(
    json.dumps(dict(sorted(installed.items())), separators=(",", ":")) + "\n"
)
PY

printf '%s  %s\n' \
  0f336a262d1c1cac51a73c625a7398c392feb9f3ecad2aa81f62cbc128a62a64 \
  "$cache/secure-engine/0.1.6/secure-engine-0.1.6-1.fc44.x86_64.rpm" \
  ad91499f3de9918963c9189bd236f5eb99b78cb99954e30f50bbc3098f18a5e0 \
  "$cache/secure-engine/0.1.6/usr/bin/secure" \
  45bcd58440e397ed52c50e953ccf5948909ea77087c9186fc7d277216f62e319 \
  "$cache/opengrep/1.22.0/opengrep_manylinux_x86" \
  7af874aca05879e1823cd820913b42fb8d8b994738a05ec39ce4256d85b03861 \
  /usr/bin/python3.14 | sha256sum -c -

echo "Frozen tools acquired and verified before the execution window; no scanner was executed."

