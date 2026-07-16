//! Phase 3 frozen-holdout integrity and immutability tests.

#![allow(clippy::expect_used)]

use secure_bench_core::adapter::fingerprint;
use secure_bench_core::holdout::{
    canonical_holdout_json, load_holdout_manifest, validate_holdout_ledger,
};
use std::fs;
use std::path::{Path, PathBuf};

fn root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../..")
}

fn inputs() -> (Vec<u8>, Vec<u8>, Vec<u8>) {
    let root = root();
    (
        fs::read(root.join("holdout/phase-3/manifest.json")).expect("manifest"),
        fs::read(root.join("taxonomy/secure-bench-taxonomy-v1.json")).expect("taxonomy"),
        fs::read(root.join("holdout/phase-3/execution-ledger.jsonl")).expect("ledger"),
    )
}

#[test]
fn frozen_holdout_validates_with_exact_coverage_and_commitments() {
    let (manifest_bytes, taxonomy, ledger) = inputs();
    let (manifest, validation) =
        load_holdout_manifest(&manifest_bytes, &root(), &taxonomy).expect("valid holdout");
    assert_eq!(validation.pairs, 28);
    assert_eq!(validation.cases, 56);
    assert_eq!(validation.vulnerable_cases, 28);
    assert_eq!(validation.safe_controls, 28);
    assert_eq!(validation.taxonomy_pairs.len(), 7);
    assert!(validation.taxonomy_pairs.values().all(|count| *count == 4));
    assert_eq!(
        validation.aggregate_corpus_sha256,
        "28f4599c9711465a7cbbfe0ebc356e017a3bb6145bc77d57577b3b5d31790844"
    );
    assert_eq!(
        validation.contract_merkle_root,
        "fcfbe4f8d5dc0fc871ce55c1eac3e3d2618bcc76261bfa16bd4b1f98833c96e5"
    );
    assert_eq!(
        canonical_holdout_json(&manifest).expect("canonical"),
        manifest_bytes
    );
    let entries = validate_holdout_ledger(&ledger, &manifest).expect("valid ledger");
    assert_eq!(entries.len(), 1);
}

#[test]
fn contract_tampering_and_reordering_fail_closed() {
    let (manifest_bytes, taxonomy, _) = inputs();
    let (mut manifest, _) =
        load_holdout_manifest(&manifest_bytes, &root(), &taxonomy).expect("valid holdout");
    manifest.pairs[0].rationale.push_str(" changed");
    let tampered = canonical_holdout_json(&manifest).expect("canonical tamper");
    assert!(load_holdout_manifest(&tampered, &root(), &taxonomy).is_err());

    let (mut manifest, _) =
        load_holdout_manifest(&manifest_bytes, &root(), &taxonomy).expect("valid holdout");
    manifest.pairs.swap(0, 1);
    let reordered = canonical_holdout_json(&manifest).expect("canonical reorder");
    assert!(load_holdout_manifest(&reordered, &root(), &taxonomy).is_err());
}

#[test]
fn ledger_is_canonical_chained_and_not_replaceable() {
    let (manifest_bytes, taxonomy, mut ledger) = inputs();
    let (manifest, _) =
        load_holdout_manifest(&manifest_bytes, &root(), &taxonomy).expect("valid holdout");
    ledger.extend_from_slice(&ledger.clone());
    assert!(validate_holdout_ledger(&ledger, &manifest).is_err());
    let mut noncanonical = inputs().2;
    noncanonical.insert(0, b' ');
    assert!(validate_holdout_ledger(&noncanonical, &manifest).is_err());
}

#[test]
fn immutable_pre_phase3_artifacts_remain_exact() {
    let root = root();
    for (path, expected) in [
        (
            "fixtures/corpus-v1.toml",
            "57d91da3dff7393b1ee8844072d3999161371403027a6d9c78df56907d61e97b",
        ),
        (
            "taxonomy/secure-bench-taxonomy-v1.json",
            "059fe22d7707cf8d17f2c1621fdae9819787a1958ba2ef0421eca4e4ec858452",
        ),
        (
            "taxonomy/phase-1-corpus-taxonomy-profile-v1.json",
            "2b1279b612eaa0bd8570c33e374cabe66174ee03a4d112baab9c4378cb4ac37f",
        ),
        (
            "baselines/phase-1-secure-engine-phase6/result.json",
            "b16c374c21e5738967c82eb836992dc41a8ea0bd10627f34b4dda304b58f7099",
        ),
        (
            "baselines/phase-2-secure-engine-0-1-1/result.json",
            "498869eb9069116ab07764240dd9b8a2213c98a890396756087b4cb435051eb3",
        ),
        (
            "baselines/phase-2-secure-engine-0-1-1/pre-execution-contract.json",
            "041c91990c38e451aa5d0effb28f39fd23f86163b511969706bad025b069365c",
        ),
    ] {
        assert_eq!(
            fingerprint(&fs::read(root.join(path)).expect(path)),
            expected,
            "{path}"
        );
    }
}
