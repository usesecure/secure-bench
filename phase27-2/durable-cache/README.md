# Durable Phase 17 workspace closure

The durable cache at `/home/danielcastrillon/Proyectos/secure-bench-tool-cache/phase17-workspace/241600628315db6d8a77e62bbaf6e61ba5c628f1` contains an immutable extraction of the complete `phase17/` subtree from commit `241600628315db6d8a77e62bbaf6e61ba5c628f1`.

Restore without network from the durable copy:

```text
restore.sh durable TARGET
```

Restore from the repository's local Git objects:

```text
restore.sh git TARGET
```

Both modes refuse an existing target. Validate a restored workspace with `verify-compatibility.py --workspace-only TARGET`; the required Git tree is `e2512d180118e6487a979ba03d1961c41d17825d`.
