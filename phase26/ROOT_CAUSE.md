# Root cause of the frozen Phase 25 Python verifier failure

Phase 25 closed fail-closed because its frozen Python verifier reported
`ledger chain drift at 1`. That verifier used one `sort_keys=True`
canonicalization function for two different producer domains.

For the observation payload, Rust serialized an `Observation` struct in struct
field order, appended a newline, wrote those bytes to `observation.json`, and
hashed the same bytes for `payload_sha256`. Entry 1 therefore commits
`764953dbe39aac094d669c9cef7c14c6e041af12ba9e7d73f03d0483affafca4`.
The frozen Python verifier parsed that object, sorted its keys, reserialized it,
and obtained
`1dfd6ffe887e469495e4f02e23dfa89cc3e93f072d653590e2c59888e62e86b4`.

For the ledger projection, Rust used `serde_json::Value`; deterministic map-key
ordering is correct for that distinct domain. The defect was therefore not a
corrupt observation or ledger. It was applying the projection's key-ordering
rule to a struct payload.

Phase 26 leaves the failed verifier and all Phase 25 evidence unchanged. Its
successor verifier hashes inventoried observation bytes directly and uses a
separate `serde_json::Value` projection serializer for entry hashes.
