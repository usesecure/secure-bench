# OpenGrep Phase 17 adapter workspace

This durable, scanner-free artifact contains the exact `phase17/` tree from commit `241600628315db6d8a77e62bbaf6e61ba5c628f1`, the minimal independent JSON runner source and lock, and the reproducibly compiled runner binary.

`workspace/phase17` is the untouched historical tree. `runner-source` is injected as `phase17/independent-runner` only in a temporary build context. The runner calls the frozen public adapter API and never starts OpenGrep.

Restore the byte-identical artifact with `./restore.sh opengrep <destination>`. Rebuild the runner offline with `./build-runner-offline.sh . opengrep <output>`. Verify all retained bytes with `sha256sum --check SHA256SUMS`.
