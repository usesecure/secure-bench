# Phase 27.2 adapter/protocol compatibility certification

Phase 17 is certified as one atomic Cargo closure. Its workspace resolves both `secure-bench-opengrep-adapter` and `secure-bench-scanner-protocol` as Cargo version 0.3.0, while their public adapter/protocol versions remain 1.0.0. No manifest, source, package version, scanner binding, or Phase 27/27.1 artifact is changed.

The closure is materialized only from local Git objects at commit `241600628315db6d8a77e62bbaf6e61ba5c628f1`. Integrity is bound to the full commit tree, the `phase17/` subtree, both package trees, the original lock, every package manifest and source, and a deterministic Git-archive SHA-256. The durable copy is independently reconstructed and checked against the same subtree identity.

Phase 27.2 supersedes Phase 27.1 only for the atomic Cargo pair. Phase 27.1 remains authoritative for scanner executables, normalized adapters, rulesets, sandbox, environment, and all other artifact bindings. Mixed 0.1.0/0.3.0 contexts fail closed.

Certification is offline and scanner-free. It uses Cargo metadata, compilation, protocol unit tests, an adapter test that creates only synthetic temporary input, and independent synthetic conformance. It never starts OpenGrep or any other scanner and does not open Phase 28.
