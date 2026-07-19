# Semgrep Phase 18 adapter workspace

This durable, scanner-free artifact contains the exact `phase17/` and `phase18/` trees from commit `aee2c7094983cfb8bdc16cf59b1962add82ca1db`, the minimal independent JSON runner source and lock, and the reproducibly compiled runner binary.

`workspace/phase17` and `workspace/phase18` are untouched historical trees. `runner-source` is injected as `phase18/independent-runner` only in a temporary build context. The runner calls the frozen public adapter API and never starts Semgrep.

Restore the byte-identical artifact with `./restore.sh semgrep <destination>`. Rebuild the runner offline with `./build-runner-offline.sh . semgrep <output>`. Verify all retained bytes with `sha256sum --check SHA256SUMS`.
