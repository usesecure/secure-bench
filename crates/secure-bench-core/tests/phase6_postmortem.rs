//! Phase 6 reproducibility and historical-integrity tests.

use secure_bench_core::adapter::fingerprint;
use secure_bench_core::phase6::{DiagnosticCategory, validate_phase6};
use std::fs;
use std::path::Path;

const MANIFEST_SHA256: &str = "a7a2e47fa85c5fcda305e2c193b91216fd9df1c28fd52dd0179b588f83790da2";
const LEDGER_SHA256: &str = "4153d6ef7a3728f0dd5c29a0782c919debc60b963d2e8c22865ce65b6c1d480c";
const RESULT_SHA256: &str = "86fa3a373dbc6b7eb346ecaa84b86c1a1aef04bf7f05c807f3f3f6cfaa0b0911";

fn repository_root() -> &'static Path {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(Path::parent)
        .unwrap_or_else(|| Path::new("."))
}

#[test]
fn committed_diagnostic_package_reproduces_from_historical_sources()
-> Result<(), Box<dyn std::error::Error>> {
    let validation = validate_phase6(repository_root())?;
    assert_eq!(validation.cases, 56);
    assert_eq!(validation.pairs, 28);
    assert_eq!(
        validation
            .category_counts
            .get(&DiagnosticCategory::NoFindingEmitted),
        Some(&16)
    );
    assert_eq!(
        validation
            .category_counts
            .get(&DiagnosticCategory::SafeControlFalsePositive),
        Some(&10)
    );
    Ok(())
}

#[test]
fn phase3_and_phase4_sources_remain_byte_identical() -> Result<(), Box<dyn std::error::Error>> {
    for (relative, expected) in [
        ("holdout/phase-3/manifest.json", MANIFEST_SHA256),
        ("holdout/phase-3/execution-ledger.jsonl", LEDGER_SHA256),
        (
            "artifacts/phase-4-secure-engine-0-1-2/result.json",
            RESULT_SHA256,
        ),
    ] {
        assert_eq!(
            fingerprint(&fs::read(repository_root().join(relative))?),
            expected
        );
    }
    Ok(())
}
