# Phase 1.5 Neutral Taxonomy Verification

## Historical boundary

Phase 1.5 is based directly on signed Phase 1 commit `535d4f642e1a075e1f89e83a78fbb90243fb4b60`. The Phase 0 anchor is signed commit `5e911044f8692d2611b3bc685086a39eac3cf843`. Both signatures were verified before Phase 1.5 work began.

The preserved Phase 1 commit has Git tree `b412181143f98db776ee5f065fcfbea504c78d2b`. The `main` and `codex/phase-1-secure-engine-corpus` references remained at that exact commit while work proceeded on `codex/phase-1-5-neutral-taxonomy`.

No scanner was executed, installed, built, updated, inspected, imported, or modified for Phase 1.5. In particular, the committed Secure Engine Phase 6 reports, run manifest, result, and measurement record were not changed. A regression test reevaluates that retained bundle and requires byte-for-byte equality with its committed `result.json`.

## Taxonomy verification

The Rust implementation verifies:

- strict JSON parsing and committed JSON Schema validation;
- exactly seven sorted, unique namespaced category/invariant pairs;
- deterministic canonical serialization and a self-excluding content hash;
- official MITRE CWE identifier/URL consistency and a complete source URL set;
- explicit missing, incomplete, version-mismatched, unknown, and conflicting resolution states;
- identical taxonomy metadata across native JSON and SARIF adapters;
- rejection of scanner-specific alias fields;
- matching based on frozen coordinates plus source, sink, and evidence constraints; and
- independence from category prose, invariant prose, native rule identity, severity, confidence, and tool identity.

The committed taxonomy content hash is `22852bd7401020b315af11dfa2b60c0b46f78eb19f95079e6400d7b3bea3272c`. Raw repository artifact SHA-256 fingerprints are:

- taxonomy data: `059fe22d7707cf8d17f2c1621fdae9819787a1958ba2ef0421eca4e4ec858452`;
- taxonomy JSON Schema: `cdecd643d338aa8ae42ec7398c6c4703cb97d60ad355340c98744fc94bcb7d6f`; and
- taxonomy methodology: `eac27e5800be35c5ae77f7804e52ae90462cbda403a5484baa8fab62f02ab562`.

## Required gates

The final verification record requires formatting, strict Clippy, all workspace tests, RustSec audit, dependency policy, taxonomy CLI validation, corpus validation, exact baseline result preservation, baseline tree preservation, clean working state, and a single signed DCO commit directly above Phase 1. No network-dependent scanner behavior is part of these gates.

On 2026-07-16, formatting and strict Clippy completed without warnings; all 53 workspace tests passed; the locally cached RustSec database reported no actionable advisory; and dependency advisories, bans, licenses, and sources passed policy. Taxonomy validation reported seven categories, canonical serialization, and equal declared/computed content hashes. Corpus validation still reported 14 cases split into seven vulnerable cases and seven paired controls with fingerprint `9a32028a28d7c0396a630db8a2698a8977e173328578b1108f14603372e77761`.

Phase 1.5 remains a neutral prospective contract. Passing these gates does not establish production benchmark validity, scanner quality, a comparative ranking, or superiority by Secure Engine or any other tool.
