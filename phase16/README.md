# Secure Bench Phase 16

Phase 16 is the prospective Secure Bench 0.2.2 authoritative Evidence Contract v2 adapter.
It is additive and does not modify Secure Engine, execute a scanner, rerun a holdout, or rescore
Phase 14. The workspace reads committed retired reports only for offline adapter conformance.

Run `cargo run --locked --manifest-path phase16/Cargo.toml -- verify .` from the repository root.
The command verifies the immutable Phase 15 handoff, executes every Phase 15 conformance vector,
projects all 112 retained Phase 14 reports offline, and confirms the diagnostic 10 exact / 46
no-match vulnerable counterfactual without changing the official historical result.
