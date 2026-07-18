//! Scanner-free integration tests for the frozen Phase 23 contract.

use serde_json::Value;
use std::fs;
use std::path::Path;

#[test]
fn corrected_contract_and_synthetic_inputs_are_self_contained()
-> Result<(), Box<dyn std::error::Error>> {
    let phase = Path::new(env!("CARGO_MANIFEST_DIR"));
    let contract: Value = serde_json::from_slice(&fs::read(
        phase.join("config/corrected-environment-contract-v1.json"),
    )?)?;
    assert_eq!(
        contract
            .pointer("/resource_limits/stack_hard_bytes")
            .and_then(Value::as_u64),
        Some(8_388_608)
    );
    assert_eq!(
        contract
            .pointer("/isolation/network_namespace")
            .and_then(Value::as_str),
        Some("unshared")
    );
    for fixture in [
        "fixtures/reproducer-1/app-01.js",
        "fixtures/reproducer-2/app-01.js",
        "fixtures/reproducer-2/app-02.js",
        "fixtures/qualification/clean/app.js",
        "fixtures/qualification/finding/app.js",
        "fixtures/qualification/malformed/app.js",
        "fixtures/qualification/multi/app-01.js",
        "fixtures/qualification/multi/app-02.js",
        "fixtures/qualification/multi/app-03.js",
    ] {
        let path = phase.join(fixture);
        assert!(path.is_file(), "missing synthetic fixture {fixture}");
        assert!(
            !path.to_string_lossy().contains("holdout"),
            "fixture path escaped synthetic scope"
        );
    }
    Ok(())
}
