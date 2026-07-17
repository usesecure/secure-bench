//! Scanner-free Phase 7 lifecycle and completed-artifact regression checks.

#![allow(clippy::expect_used)]

use secure_bench_core::adapter::fingerprint;
use secure_bench_core::phase7::{
    PHASE7_ARTIFACTS_SCHEMA_V1, PHASE7_GENESIS_LEDGER_SHA256, PHASE7_RESULT_SCHEMA_V1,
    PHASE7_RUN_ID, PHASE7_RUN_SCHEMA_V1, Phase7Artifacts, Phase7Result, Phase7Run,
    load_phase7_ledger,
};
use secure_bench_core::schema::{
    validate_phase7_artifacts, validate_phase7_result, validate_phase7_run,
};
use std::fs;
use std::path::{Path, PathBuf};

fn root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../..")
}

#[test]
fn genesis_lifecycle_projection_is_read_only_and_exact() {
    let bytes = fs::read(root().join("fixtures/projections/phase5-genesis-ledger.jsonl"))
        .expect("genesis ledger projection");
    assert_eq!(fingerprint(&bytes), PHASE7_GENESIS_LEDGER_SHA256);
    let ledger = load_phase7_ledger(&bytes).expect("valid genesis lifecycle projection");
    assert!(ledger.entries.is_empty());
}

#[test]
fn completed_artifacts_remain_schema_valid_and_hash_bound() {
    let root = root();
    let artifacts_path = root.join("artifacts/phase-7-secure-engine-0-1-3/artifacts.json");
    if !artifacts_path.exists() {
        // The one-shot slot has deliberately not been consumed in the pre-execution tree.
        return;
    }

    let artifacts_bytes = fs::read(&artifacts_path).expect("artifact index");
    let artifacts: Phase7Artifacts =
        serde_json::from_slice(&artifacts_bytes).expect("artifact index JSON");
    validate_phase7_artifacts(&artifacts).expect("artifact index schema");
    assert_eq!(artifacts.schema_version, PHASE7_ARTIFACTS_SCHEMA_V1);
    assert_eq!(artifacts.run_id, PHASE7_RUN_ID);
    assert_eq!(artifacts.ledger_entries, 115);

    let run_bytes = fs::read(root.join(&artifacts.run_path)).expect("run manifest");
    let run: Phase7Run = serde_json::from_slice(&run_bytes).expect("run JSON");
    validate_phase7_run(&run).expect("run schema");
    assert_eq!(run.schema_version, PHASE7_RUN_SCHEMA_V1);
    assert_eq!(run.run_id, PHASE7_RUN_ID);
    assert_eq!(run.cases.len(), 112);
    assert_eq!(fingerprint(&run_bytes), artifacts.run_sha256);

    let result_bytes = fs::read(root.join(&artifacts.result_path)).expect("result");
    let result: Phase7Result = serde_json::from_slice(&result_bytes).expect("result JSON");
    validate_phase7_result(&result).expect("result schema");
    assert_eq!(result.schema_version, PHASE7_RESULT_SCHEMA_V1);
    assert_eq!(result.run_id, PHASE7_RUN_ID);
    assert_eq!(result.cases.len(), 112);
    assert_eq!(result.metrics.counts.vulnerable_expectations, 56);
    assert_eq!(result.metrics.counts.safe_controls, 56);
    assert_eq!(fingerprint(&result_bytes), artifacts.result_sha256);

    let contract_bytes =
        fs::read(root.join(&artifacts.pre_execution_contract_path)).expect("pre-execution");
    assert_eq!(
        fingerprint(&contract_bytes),
        artifacts.pre_execution_contract_sha256
    );
    let ledger_bytes = fs::read(root.join(&artifacts.ledger_path)).expect("completed ledger");
    let ledger = load_phase7_ledger(&ledger_bytes).expect("completed ledger lifecycle");
    assert_eq!(ledger.entries.len(), 114);
    assert_eq!(fingerprint(&ledger_bytes), artifacts.ledger_sha256);
}
