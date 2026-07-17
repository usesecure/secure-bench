# Retired Phase 3 diagnostic corpus

This directory is the public Secure Bench Phase 6 diagnostic package derived from the executed Phase 3 holdout and immutable Phase 4 result.

The corpus is retired and no longer unseen. It is appropriate for development, debugging, adapter conformance, and regression testing. It is not an unbiased benchmark, a production scanner comparison, a ranking input, or evidence that any tool is superior or completely covers these vulnerability families.

`retired-holdout-diagnostic-v1.json` is the complete case and pair postmortem. `regression-manifest-v1.json` is the engine-consumable regression contract. `fixtures/` contains byte-identical public copies of all retired scanner-visible fixtures. The original Phase 3 and Phase 4 artifacts remain unchanged.

No scanner was executed to create this package. Official Phase 4 credit is unchanged, and no Phase 5 holdout case, answer, identifier, or metadata was read or disclosed.
