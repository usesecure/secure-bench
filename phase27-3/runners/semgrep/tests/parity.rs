//! Scanner-free parity and tamper tests for the `Semgrep` runner.

use secure_bench_scanner_protocol::ScannerManifest;
use secure_bench_semgrep_adapter::{RAW_FORMAT, adapt_report};
use serde_json::{Value, json};
use std::error::Error;
use std::fs;
use std::io::Write as _;
use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};

fn phase_root() -> Result<PathBuf, Box<dyn Error>> {
    Ok(Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .ok_or("runner has no historical workspace parent")?
        .to_path_buf())
}

fn manifest(root: &Path) -> Result<(ScannerManifest, Value), Box<dyn Error>> {
    let bytes = fs::read(root.join("manifests/semgrep-v1.170.0-conformance.json"))?;
    Ok((
        serde_json::from_slice(&bytes)?,
        serde_json::from_slice(&bytes)?,
    ))
}

fn invoke(request: &Value) -> Result<Output, Box<dyn Error>> {
    let mut child = Command::new(env!("CARGO_BIN_EXE_secure-bench-semgrep-json-runner"))
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()?;
    child
        .stdin
        .take()
        .ok_or("runner stdin unavailable")?
        .write_all(&serde_json::to_vec(request)?)?;
    Ok(child.wait_with_output()?)
}

fn request(root: &Path, manifest: &Value, raw: &str) -> Value {
    json!({
        "schema_version": "secure-bench-adapter-runner-request-v1",
        "raw_format": RAW_FORMAT,
        "case_scope": "phase27-3-synthetic-parity",
        "fixture_root": root.join("fixtures/conformance/workspace"),
        "manifest": manifest,
        "raw_json": raw,
    })
}

fn parity(case: &str) -> Result<Vec<u8>, Box<dyn Error>> {
    let root = phase_root()?;
    let (typed_manifest, manifest_json) = manifest(&root)?;
    let raw = fs::read(root.join(format!("fixtures/conformance/reports/{case}.json")))?;
    let direct = adapt_report(
        "phase27-3-synthetic-parity",
        &raw,
        &root.join("fixtures/conformance/workspace"),
        &typed_manifest,
    )
    .map(|report| serde_json::to_value(report.public_projection()))
    .map_err(|error| error.to_string());
    let raw = String::from_utf8(raw)?;
    let output = invoke(&request(&root, &manifest_json, &raw))?;
    match direct {
        Ok(expected) => {
            assert!(output.status.success());
            let actual: Value = serde_json::from_slice(&output.stdout)?;
            assert_eq!(actual, expected?);
        }
        Err(expected) => {
            assert_eq!(output.status.code(), Some(3));
            let error: Value = serde_json::from_slice(&output.stderr)?;
            assert_eq!(error["kind"], "adapter");
            assert_eq!(error["message"], expected);
        }
    }
    Ok(output.stdout)
}

#[test]
fn direct_and_runner_results_are_identical() -> Result<(), Box<dyn Error>> {
    for case in ["clean", "finding", "duplicate", "malformed", "partial"] {
        let _ = parity(case)?;
    }
    let first = parity("duplicate")?;
    let second = parity("duplicate")?;
    assert_eq!(first, second);
    Ok(())
}

#[test]
fn input_contract_and_paths_fail_closed() -> Result<(), Box<dyn Error>> {
    let root = phase_root()?;
    let (_, manifest_json) = manifest(&root)?;
    let raw = fs::read_to_string(root.join("fixtures/conformance/reports/finding.json"))?;
    let mut wrong_format = request(&root, &manifest_json, &raw);
    wrong_format["raw_format"] = Value::String("opengrep-json-v1".to_owned());
    assert_eq!(invoke(&wrong_format)?.status.code(), Some(2));

    let mut scoring = request(&root, &manifest_json, &raw);
    scoring["score"] = json!({"tp": 1});
    assert_eq!(invoke(&scoring)?.status.code(), Some(2));

    let traversal =
        fs::read_to_string(root.join("fixtures/conformance/reports/path-traversal.json"))?;
    let output = invoke(&request(&root, &manifest_json, &traversal))?;
    assert_eq!(output.status.code(), Some(3));
    Ok(())
}
