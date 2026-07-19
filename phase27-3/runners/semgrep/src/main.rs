//! Minimal process boundary for the frozen Phase 18 `Semgrep` adapter.

#![forbid(unsafe_code)]

use secure_bench_scanner_protocol::ScannerManifest;
use secure_bench_semgrep_adapter::{RAW_FORMAT, adapt_report};
use serde::{Deserialize, Serialize};
use std::io::{self, Read as _, Write as _};
use std::path::PathBuf;

const REQUEST_SCHEMA: &str = "secure-bench-adapter-runner-request-v1";
const ERROR_SCHEMA: &str = "secure-bench-adapter-runner-error-v1";

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct Request {
    schema_version: String,
    raw_format: String,
    case_scope: String,
    fixture_root: PathBuf,
    manifest: ScannerManifest,
    raw_json: String,
}

#[derive(Serialize)]
struct ErrorDocument<'a> {
    schema_version: &'static str,
    kind: &'a str,
    message: &'a str,
}

struct Failure {
    kind: &'static str,
    message: String,
    exit_code: i32,
}

impl Failure {
    fn input(message: impl Into<String>) -> Self {
        Self {
            kind: "input",
            message: message.into(),
            exit_code: 2,
        }
    }

    fn adapter(message: impl Into<String>) -> Self {
        Self {
            kind: "adapter",
            message: message.into(),
            exit_code: 3,
        }
    }

    fn output(message: impl Into<String>) -> Self {
        Self {
            kind: "output",
            message: message.into(),
            exit_code: 4,
        }
    }
}

fn execute(input: &str) -> Result<String, Failure> {
    let request: Request = serde_json::from_str(input)
        .map_err(|error| Failure::input(format!("invalid runner request: {error}")))?;
    if request.schema_version != REQUEST_SCHEMA {
        return Err(Failure::input("unsupported runner request schema"));
    }
    if request.raw_format != RAW_FORMAT {
        return Err(Failure::input(
            "raw format does not select the Semgrep adapter",
        ));
    }
    let report = adapt_report(
        &request.case_scope,
        request.raw_json.as_bytes(),
        &request.fixture_root,
        &request.manifest,
    )
    .map_err(|error| Failure::adapter(error.to_string()))?;
    serde_json::to_string(&report.public_projection())
        .map_err(|error| Failure::output(format!("projection serialization failed: {error}")))
}

fn emit_error(error: &Failure) {
    let document = ErrorDocument {
        schema_version: ERROR_SCHEMA,
        kind: error.kind,
        message: &error.message,
    };
    if let Ok(serialized) = serde_json::to_string(&document) {
        let _ = writeln!(io::stderr().lock(), "{serialized}");
    }
}

fn run() -> Result<(), Failure> {
    if std::env::args_os().len() != 1 {
        return Err(Failure::input(
            "the runner accepts input only through stdin",
        ));
    }
    let mut input = String::new();
    io::stdin()
        .lock()
        .read_to_string(&mut input)
        .map_err(|error| Failure::input(format!("stdin read failed: {error}")))?;
    let output = execute(&input)?;
    writeln!(io::stdout().lock(), "{output}")
        .map_err(|error| Failure::output(format!("stdout write failed: {error}")))?;
    Ok(())
}

fn main() {
    if let Err(error) = run() {
        emit_error(&error);
        std::process::exit(error.exit_code);
    }
}
